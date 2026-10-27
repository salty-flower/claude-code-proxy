//! Durable loss-detection markers, not transcript or credential storage.
//! An empty marker means cached opaque context may not be replaced silently by
//! the portable summary in a client request. Markers deliberately do not expire.
use std::fs::{self, File, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::request_identity::ConversationIdentity;

const MAX_MARKERS: usize = 4096;
pub(crate) const RECOVERY_ERROR: &str = "Managed Codex compacted context is unavailable or incompatible. Start a new Claude conversation with restored full context; a portable summary alone will not be substituted automatically.";

pub(crate) struct ReplayMarker {
    config_dir: PathBuf,
    directory: PathBuf,
    file: PathBuf,
}

impl ReplayMarker {
    pub(crate) fn for_owner(
        config_dir: &Path,
        owner: Option<&ConversationIdentity>,
        session: Option<&str>,
    ) -> Option<Self> {
        let identity = match owner {
            Some(ConversationIdentity::Main(session)) => json!(["main", session]),
            Some(ConversationIdentity::Agent(session, agent)) => json!(["agent", session, agent]),
            None => json!(["unowned", session?]),
        };
        let directory = config_dir.join("codex").join("rotate-context-v1");
        let digest = Sha256::digest(identity.to_string().as_bytes());
        let file = directory.join(format!("{digest:x}.required"));
        Some(Self {
            config_dir: config_dir.to_owned(),
            directory,
            file,
        })
    }

    pub(crate) fn required(&self) -> Result<bool> {
        self.check_directories()?;
        match fs::symlink_metadata(&self.file) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.len() != 0 {
                    bail!("Invalid managed Codex context marker; refusing portable-only replay");
                }
                #[cfg(unix)]
                if metadata.permissions().mode() & 0o077 != 0 {
                    bail!("Managed Codex context marker must be private");
                }
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => bail!("Could not inspect managed Codex context marker"),
        }
    }

    pub(crate) fn require(&self) -> Result<()> {
        self.check_directories()?;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(&self.directory).map_err(|_| {
            anyhow::anyhow!("Could not create private managed Codex context directory")
        })?;
        let metadata = fs::symlink_metadata(&self.directory)
            .map_err(|_| anyhow::anyhow!("Could not inspect managed Codex context directory"))?;
        if !metadata.is_dir() {
            bail!("Managed Codex context directory must not be a symlink");
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("Managed Codex context directory must be private");
        }
        let lock_path = self.directory.join(".lock");
        if fs::symlink_metadata(&lock_path).is_ok_and(|metadata| !metadata.is_file()) {
            bail!("Invalid managed Codex context lock");
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options.mode(0o600);
        let lock = options
            .open(&lock_path)
            .map_err(|_| anyhow::anyhow!("Could not open managed Codex context lock"))?;
        lock.try_lock().map_err(|_| {
            anyhow::anyhow!("Managed Codex context store is busy; retry before compacting")
        })?;
        if self.required()? {
            return Ok(());
        }
        let count = fs::read_dir(&self.directory)
            .map_err(|_| anyhow::anyhow!("Could not inspect managed Codex context store"))?
            .take(MAX_MARKERS + 2)
            .try_fold(0usize, |count, entry| {
                let entry = entry.map_err(|_| {
                    anyhow::anyhow!("Could not inspect managed Codex context store")
                })?;
                Ok::<_, anyhow::Error>(count + usize::from(entry.file_name() != ".lock"))
            })?;
        if count >= MAX_MARKERS {
            bail!("Managed Codex context safety-marker capacity reached; no context was discarded");
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let marker = options
            .open(&self.file)
            .map_err(|_| anyhow::anyhow!("Could not create managed Codex context safety marker"))?;
        marker.sync_all().map_err(|_| {
            anyhow::anyhow!("Could not persist managed Codex context safety marker")
        })?;
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| anyhow::anyhow!("Could not persist managed Codex context directory"))?;
        for directory in [
            self.directory.parent(),
            Some(self.config_dir.as_path()),
            self.config_dir.parent(),
        ]
        .into_iter()
        .flatten()
        {
            File::open(directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| {
                    anyhow::anyhow!("Could not persist managed Codex context directory ancestry")
                })?;
        }
        Ok(())
    }

    fn check_directories(&self) -> Result<()> {
        for directory in [
            &self.config_dir,
            &self.config_dir.join("codex"),
            &self.directory,
        ] {
            match fs::symlink_metadata(directory) {
                Ok(metadata) => {
                    if !metadata.is_dir() {
                        bail!("Managed Codex context storage must not use directory symlinks");
                    }
                    #[cfg(unix)]
                    if directory == &self.directory && metadata.permissions().mode() & 0o077 != 0 {
                        bail!("Managed Codex context directory must be private");
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => bail!("Could not inspect managed Codex context storage"),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotate_context_marker_survives_restart_and_separates_siblings() {
        let directory = tempfile::tempdir().unwrap();
        let owner = ConversationIdentity::Agent(
            "conversation-secret-id".to_owned(),
            "worker-one".to_owned(),
        );
        let marker = ReplayMarker::for_owner(directory.path(), Some(&owner), None).unwrap();
        assert!(!marker.required().unwrap());
        marker.require().unwrap();
        drop(marker);
        let restarted = ReplayMarker::for_owner(directory.path(), Some(&owner), None).unwrap();
        assert!(restarted.required().unwrap());
        assert!(
            !restarted
                .file
                .to_string_lossy()
                .contains("conversation-secret-id")
        );
        assert_eq!(fs::read(&restarted.file).unwrap(), b"");
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&restarted.directory)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&restarted.file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let sibling = ConversationIdentity::Agent(
            "conversation-secret-id".to_owned(),
            "worker-two".to_owned(),
        );
        assert!(
            !ReplayMarker::for_owner(directory.path(), Some(&sibling), None)
                .unwrap()
                .required()
                .unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn rotate_context_marker_rejects_symlink_storage() {
        let config = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(other.path(), config.path().join("codex")).unwrap();
        let marker = ReplayMarker::for_owner(
            config.path(),
            Some(&ConversationIdentity::Main("session".to_owned())),
            None,
        )
        .unwrap();
        assert!(marker.required().is_err());
        assert!(marker.require().is_err());
        assert_eq!(fs::read_dir(other.path()).unwrap().count(), 0);
    }
}
