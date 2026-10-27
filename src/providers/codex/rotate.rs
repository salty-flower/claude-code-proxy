//! Personal machine-state credential authority, protocol version 1.
//! A snapshot is request-local; neither tokens nor helper output implement Debug.
use std::collections::HashMap;
use std::ops::Deref;
use std::process::Stdio;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use anyhow::{Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::auth::token_store::StoredAuth;
use crate::request_identity::ConversationIdentity;

const MAX_RPC_BYTES: usize = 128 * 1024;
const RPC_TIMEOUT: Duration = Duration::from_secs(50);

#[derive(Clone, Deserialize)]
pub(crate) struct Snapshot {
    pub account_key: String,
    pub account_id: String,
    pub selection_epoch: u64,
    pub credential_revision: u64,
    pub access_token: String,
    pub expires_at: u64,
}

impl Snapshot {
    fn validate(&self) -> Result<()> {
        if self.account_key.is_empty()
            || self.account_key.len() > 4096
            || self.account_id.is_empty()
            || self.account_id.len() > 4096
            || self.access_token.is_empty()
            || self.access_token.len() > 64 * 1024
            || self.expires_at.checked_mul(1000).is_none()
        {
            bail!("Codex rotate helper returned an invalid credential snapshot");
        }
        Ok(())
    }

    pub(crate) fn scope(&self) -> String {
        // Hash the unambiguous tuple rather than allowing user-controlled session
        // strings to collide with a generated account namespace.
        let tuple = json!(["codex-rotate-v1", self.account_key, self.selection_epoch]);
        format!("{:x}", Sha256::digest(tuple.to_string().as_bytes()))
    }

    pub(crate) fn socket_revision(&self) -> String {
        format!("{}:{}", self.scope(), self.credential_revision)
    }
}

#[derive(Clone)]
pub(crate) struct Helper {
    argv: Arc<Vec<String>>,
    timeout: Duration,
}

impl Helper {
    pub(crate) fn new(argv: Vec<String>) -> Self {
        Self {
            argv: Arc::new(argv),
            timeout: RPC_TIMEOUT,
        }
    }

    async fn rpc(&self, request: Value) -> Result<Value> {
        let input = serde_json::to_vec(&request)
            .map_err(|_| anyhow::anyhow!("Could not encode Codex rotate request"))?;
        if input.len() > MAX_RPC_BYTES {
            bail!("Codex rotate request exceeded the size limit");
        }
        let mut child = tokio::process::Command::new(&self.argv[0])
            .args(&self.argv[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| anyhow::anyhow!("Could not start Codex rotate helper"))?;
        let result = tokio::time::timeout(self.timeout, async {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("Codex rotate stdin unavailable"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("Codex rotate stdout unavailable"))?;
            // Concurrent bounded IO prevents a misbehaving helper from deadlocking
            // the caller by filling stdout before consuming stdin.
            let (write, read) = tokio::join!(
                async move {
                    stdin.write_all(&input).await?;
                    stdin.shutdown().await?;
                    drop(stdin); // ChildStdin::shutdown alone does not close the pipe.
                    Ok::<_, std::io::Error>(())
                },
                async {
                    let mut output = Vec::new();
                    stdout
                        .take((MAX_RPC_BYTES + 1) as u64)
                        .read_to_end(&mut output)
                        .await?;
                    Ok::<_, std::io::Error>(output)
                }
            );
            write.map_err(|_| anyhow::anyhow!("Codex rotate helper input failed"))?;
            let output = read.map_err(|_| anyhow::anyhow!("Codex rotate helper output failed"))?;
            if output.len() > MAX_RPC_BYTES {
                bail!("Codex rotate helper output exceeded the size limit");
            }
            let status = child
                .wait()
                .await
                .map_err(|_| anyhow::anyhow!("Could not wait for Codex rotate helper"))?;
            let response: Value = serde_json::from_slice(&output)
                .map_err(|_| anyhow::anyhow!("Codex rotate helper returned invalid JSON"))?;
            if response.get("version").and_then(Value::as_u64) != Some(1) {
                bail!("Unsupported Codex rotate helper protocol version");
            }
            if !status.success() || response.get("ok").and_then(Value::as_bool) != Some(true) {
                // Only a known error code crosses the secret-bearing RPC boundary.
                let code = response
                    .pointer("/error/code")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let safe_code = match code {
                    "invalid_request" | "not_configured" | "signed_out" | "no_accounts"
                    | "unknown_account" | "all_exhausted" | "reauth_required"
                    | "refresh_uncertain" | "network_unavailable" | "busy" | "io_error" => code,
                    _ => "helper_failed",
                };
                bail!("Codex rotate: {safe_code}");
            }
            Ok(response)
        })
        .await;
        match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(error)) => {
                let _ = child.kill().await;
                Err(error)
            }
            Err(_) => {
                let _ = child.kill().await;
                bail!("Codex rotate helper timed out");
            }
        }
    }

    async fn snapshot(&self, request: Value) -> Result<Snapshot> {
        let response = self.rpc(request).await?;
        let snapshot: Snapshot =
            serde_json::from_value(response.get("snapshot").cloned().unwrap_or(Value::Null))
                .map_err(|_| {
                    anyhow::anyhow!("Codex rotate helper returned an invalid credential snapshot")
                })?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub(crate) async fn acquire(&self, model: Option<&str>) -> Result<RequestAuth> {
        let snapshot = self
            .snapshot(json!({"version": 1, "op": "acquire", "model": model}))
            .await?;
        Ok(RequestAuth::external(self.clone(), snapshot))
    }

    async fn refresh(&self, rejected: &Snapshot) -> Result<Snapshot> {
        let fresh = self.snapshot(json!({
            "version": 1, "op": "refresh", "account_key": rejected.account_key,
            "selection_epoch": rejected.selection_epoch, "rejected_revision": rejected.credential_revision,
        })).await?;
        if fresh.account_key != rejected.account_key
            || fresh.account_id != rejected.account_id
            || fresh.selection_epoch != rejected.selection_epoch
            || fresh.credential_revision < rejected.credential_revision
        {
            bail!("Codex rotate helper changed the identity of an in-flight request");
        }
        Ok(fresh)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) struct Fixture {
        _dir: tempfile::TempDir,
        pub helper: Helper,
        requests: std::path::PathBuf,
        response: std::path::PathBuf,
    }

    pub(crate) fn snapshot(account: &str, epoch: u64, revision: u64) -> Value {
        json!({
            "version": 1, "ok": true, "snapshot": {
                "account_key": format!("key-{account}"), "account_id": format!("account-{account}"),
                "selection_epoch": epoch, "credential_revision": revision,
                "access_token": format!("access-{account}-{revision}"), "expires_at": 4_000_000_000_u64,
            }
        })
    }

    impl Fixture {
        pub(crate) fn new(response: Value) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let requests = dir.path().join("requests.jsonl");
            let response_path = dir.path().join("response.json");
            let shell = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .map(|directory| directory.join("sh"))
                .find(|path| path.is_file())
                .expect("POSIX shell required for process fixture");
            let helper = Helper::new(vec![
                shell.to_str().unwrap().to_owned(),
                "-c".to_owned(),
                "IFS= read -r request; printf '%s\\n' \"$request\" >> \"$1\"; exec cat \"$2\""
                    .to_owned(),
                "fixture".to_owned(),
                requests.to_str().unwrap().to_owned(),
                response_path.to_str().unwrap().to_owned(),
            ]);
            let fixture = Self {
                _dir: dir,
                helper,
                requests,
                response: response_path,
            };
            fixture.respond(response);
            fixture
        }

        pub(crate) fn respond(&self, response: Value) {
            std::fs::write(&self.response, serde_json::to_vec(&response).unwrap()).unwrap();
        }

        pub(crate) fn requests(&self) -> Vec<Value> {
            std::fs::read_to_string(&self.requests)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
    }

    #[tokio::test]
    async fn rotate_helper_refresh_is_pinned_to_rejected_identity_and_revision() {
        let fixture = Fixture::new(snapshot("a", 4, 9));
        let original = fixture.helper.acquire(Some("gpt-5.6-sol")).await.unwrap();
        assert!(original.refresh.is_empty());
        fixture.respond(snapshot("b", 5, 1));
        let global_selection = fixture.helper.acquire(Some("gpt-5.6-sol")).await.unwrap();
        fixture.respond(snapshot("a", 4, 10));
        let refreshed = original.refresh_external().await.unwrap().unwrap();
        assert_eq!(refreshed.account_id.as_deref(), Some("account-a"));
        assert_eq!(refreshed.access, "access-a-10");
        assert_eq!(global_selection.account_id.as_deref(), Some("account-b"));
        assert_eq!(
            fixture.requests()[2],
            json!({
                "version": 1, "op": "refresh", "account_key": "key-a", "selection_epoch": 4, "rejected_revision": 9,
            })
        );
    }

    #[tokio::test]
    async fn rotate_helper_refuses_identity_substitution_and_redacts_errors() {
        let fixture = Fixture::new(snapshot("a", 1, 1));
        let original = fixture.helper.acquire(None).await.unwrap();
        fixture.respond(snapshot("b", 2, 1));
        let error = original
            .refresh_external()
            .await
            .unwrap()
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("changed the identity"));
        assert!(!error.contains("access-b"));
        fixture.respond(json!({"version": 1, "ok": false, "error": {
            "code": "reauth_required", "message": "SECRET TOKEN SHOULD NOT ESCAPE"
        }}));
        assert_eq!(
            fixture
                .helper
                .acquire(None)
                .await
                .err()
                .unwrap()
                .to_string(),
            "Codex rotate: reauth_required"
        );
        fixture.respond(json!({"version": 1, "ok": false, "error": {
            "code": "SECRET", "message": "SECRET"
        }}));
        assert_eq!(
            fixture
                .helper
                .acquire(None)
                .await
                .err()
                .unwrap()
                .to_string(),
            "Codex rotate: helper_failed"
        );
    }

    #[tokio::test]
    async fn rotate_helper_bounds_and_validates_responses() {
        let fixture = Fixture::new(snapshot("a", 1, 1));
        std::fs::write(&fixture.response, "x".repeat(MAX_RPC_BYTES + 1)).unwrap();
        assert!(
            fixture
                .helper
                .acquire(None)
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("size limit")
        );
        fixture.respond(json!({"version": 2, "ok": true}));
        assert!(
            fixture
                .helper
                .acquire(None)
                .await
                .err()
                .unwrap()
                .to_string()
                .contains("protocol version")
        );
        let mut invalid = snapshot("a", 1, 1);
        invalid["snapshot"]["expires_at"] = json!(u64::MAX);
        fixture.respond(invalid);
        assert!(fixture.helper.acquire(None).await.is_err());
    }

    #[tokio::test]
    async fn rotate_helper_timeout_is_bounded() {
        let fixture = Fixture::new(snapshot("a", 1, 1));
        let mut helper = fixture.helper.clone();
        let mut argv = (*helper.argv).clone();
        argv[2] = "exec sleep 10".to_owned();
        helper.argv = Arc::new(argv);
        helper.timeout = Duration::from_millis(50);
        assert_eq!(
            helper.acquire(None).await.err().unwrap().to_string(),
            "Codex rotate helper timed out"
        );
    }

    #[tokio::test]
    async fn rotate_scope_isolates_accounts_agents_and_late_completion() {
        let _guard = super::super::continuation::lock_continuation_registry_for_async_tests().await;
        let fixture = Fixture::new(snapshot("a", 3, 1));
        let a = fixture.helper.acquire(None).await.unwrap();
        fixture.respond(snapshot("b", 4, 1));
        let b = fixture.helper.acquire(None).await.unwrap();
        let owner =
            ConversationIdentity::Agent(uuid::Uuid::new_v4().to_string(), "worker".to_owned());
        let (a_owner, _) = scope_context(a.snapshot().unwrap(), Some(&owner), None);
        let request = serde_json::from_value(json!({
            "model": "gpt-5.6-sol", "input": [], "store": false, "stream": true, "parallel_tool_calls": false,
            "text": {"verbosity": "low"}
        })).unwrap();
        let old = super::super::continuation::continuation_candidate_for_owner(
            a_owner.as_ref(),
            &request,
            true,
        );
        let (b_owner, _) = scope_context(b.snapshot().unwrap(), Some(&owner), None);
        let current = super::super::continuation::continuation_candidate_for_owner(
            b_owner.as_ref(),
            &request,
            true,
        );
        assert_ne!(a_owner, b_owner);
        assert!(!super::super::continuation::is_current_turn_for_owner(&old));
        super::super::continuation::record_continuation_for_owner(
            &old,
            &request,
            Some("old-response"),
            Some(11),
            &[],
        );
        assert!(super::super::continuation::is_current_turn_for_owner(
            &current
        ));
        assert!(current.candidate().previous_response_id.is_none());
        // A late A acquire cannot retire B's reservation or move its namespace back.
        scope_context(a.snapshot().unwrap(), Some(&owner), None);
        assert!(super::super::continuation::is_current_turn_for_owner(
            &current
        ));
        let sibling = ConversationIdentity::Agent(
            match &owner {
                ConversationIdentity::Agent(session, _) => session.clone(),
                _ => unreachable!(),
            },
            "sibling".to_owned(),
        );
        assert_ne!(
            b_owner,
            scope_context(b.snapshot().unwrap(), Some(&sibling), None).0
        );
    }
}

#[derive(Clone)]
pub(crate) struct RequestAuth {
    auth: StoredAuth,
    external: Option<(Helper, Snapshot)>,
}

impl RequestAuth {
    pub(crate) fn internal(auth: StoredAuth) -> Self {
        Self {
            auth,
            external: None,
        }
    }

    fn external(helper: Helper, snapshot: Snapshot) -> Self {
        let auth = StoredAuth {
            access: snapshot.access_token.clone(),
            refresh: String::new(),
            expires: snapshot.expires_at * 1000,
            account_id: Some(snapshot.account_id.clone()),
        };
        Self {
            auth,
            external: Some((helper, snapshot)),
        }
    }

    pub(crate) async fn refresh_external(&self) -> Option<Result<Self>> {
        let (helper, snapshot) = self.external.as_ref()?;
        Some(
            helper
                .refresh(snapshot)
                .await
                .map(|fresh| Self::external(helper.clone(), fresh)),
        )
    }

    pub(crate) fn snapshot(&self) -> Option<&Snapshot> {
        self.external.as_ref().map(|(_, snapshot)| snapshot)
    }
}

impl Deref for RequestAuth {
    type Target = StoredAuth;
    fn deref(&self) -> &Self::Target {
        &self.auth
    }
}

struct PublishedScope {
    epoch: u64,
    scoped_session: String,
    scoped_owner: Option<ConversationIdentity>,
}

static CONTEXT_SCOPES: LazyLock<Mutex<HashMap<String, PublishedScope>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub(crate) fn clear_session_compaction(session_id: &str) {
    let registry = CONTEXT_SCOPES.lock().unwrap();
    for (identity, scope) in registry.iter() {
        let identity: Value = serde_json::from_str(identity).unwrap_or(Value::Null);
        if identity.get(1).and_then(Value::as_str) == Some(session_id) {
            super::compaction::clear_compaction(&scope.scoped_session);
        }
    }
}

/// A late old-account completion can only update its old namespace. Epochs are
/// monotonic, so a delayed acquire cannot move the published scope backwards.
pub(crate) fn scope_context(
    snapshot: &Snapshot,
    owner: Option<&ConversationIdentity>,
    session: Option<&str>,
) -> (Option<ConversationIdentity>, Option<String>) {
    let identity = match owner {
        Some(ConversationIdentity::Main(session)) => json!(["main", session]),
        Some(ConversationIdentity::Agent(session, agent)) => json!(["agent", session, agent]),
        None => match session {
            Some(session) => json!(["unowned", session]),
            None => return (None, None),
        },
    };
    let original = identity.to_string();
    let scoped_session = format!(
        "cr-{:x}",
        Sha256::digest(json!([snapshot.scope(), identity]).to_string().as_bytes())
    );
    let mut registry = CONTEXT_SCOPES.lock().unwrap();
    if let Some(previous) = registry.get(&original)
        && previous.epoch < snapshot.selection_epoch
    {
        // Retain anchored encrypted compaction under the new lease. The original
        // MessagesRequest is still translated first, preserving portable context.
        super::compaction::copy_anchored_compaction(&previous.scoped_session, &scoped_session);
        // Retire only this conversation's old idle socket and reservation. An
        // in-flight stream keeps its own Arc and finishes, but cannot reinsert
        // its socket or publish an old continuation after the selection moved.
        super::continuation::clear_continuation_for_owner(previous.scoped_owner.as_ref());
        if let Some(owner) = previous.scoped_owner.as_ref() {
            super::websocket::invalidate_codex_websocket_pool_owner(owner);
        }
    }
    let scoped_owner = owner.map(|owner| match owner {
        ConversationIdentity::Main(_) => ConversationIdentity::Main(scoped_session.clone()),
        ConversationIdentity::Agent(_, agent) => {
            ConversationIdentity::Agent(scoped_session.clone(), agent.clone())
        }
    });
    if registry
        .get(&original)
        .is_none_or(|previous| previous.epoch <= snapshot.selection_epoch)
    {
        if registry.len() >= 1000 && !registry.contains_key(&original) {
            registry.clear(); // Loss of the acceleration index never drops caller history.
        }
        registry.insert(
            original,
            PublishedScope {
                epoch: snapshot.selection_epoch,
                scoped_session: scoped_session.clone(),
                scoped_owner: scoped_owner.clone(),
            },
        );
    }
    (scoped_owner, Some(scoped_session))
}
