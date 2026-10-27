//! Model fallback on quota exhaustion: when the upstream for a requested model
//! rejects it with 429 or 402 before any output, the request is retried once
//! on a configured substitute, usually the same model on another
//! subscription. The registry owns the map; production reads it from
//! `CCP_MODEL_FALLBACKS_FILE`.

use std::collections::HashMap;

use axum::http::StatusCode;

#[derive(Debug, Default)]
pub struct FallbackMap {
    targets: HashMap<String, String>,
}

impl FallbackMap {
    pub fn from_json(raw: &str) -> anyhow::Result<Self> {
        Ok(Self {
            targets: serde_json::from_str(raw)?,
        })
    }

    pub fn target_for(&self, model: &str) -> Option<&str> {
        self.targets.get(model).map(String::as_str)
    }

    /// Reads the JSON object named by `CCP_MODEL_FALLBACKS_FILE`, for example
    /// `{"opencode-go/glm-5.3": "commandcode/zai-org/GLM-5.3"}`.
    pub fn load_configured() -> Self {
        let Some(path) = std::env::var("CCP_MODEL_FALLBACKS_FILE")
            .ok()
            .filter(|value| !value.is_empty())
        else {
            return Self::default();
        };
        let loaded = std::fs::read_to_string(&path)
            .map_err(anyhow::Error::from)
            .and_then(|raw| Self::from_json(&raw));
        match loaded {
            Ok(map) => map,
            Err(error) => {
                eprintln!("claude-code-proxy: ignoring model fallbacks file {path}: {error}");
                Self::default()
            }
        }
    }
}

/// Rejections a substitute can cure: a spent quota or a rate limit on this
/// subscription. Authentication, permission, and request errors would fail
/// the same way elsewhere or hide a misconfiguration.
pub fn is_fallback_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS | StatusCode::PAYMENT_REQUIRED
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_resolves_configured_models_only() {
        let map =
            FallbackMap::from_json(r#"{"opencode-go/glm-5.3": "commandcode/zai-org/GLM-5.3"}"#)
                .unwrap();
        assert_eq!(
            map.target_for("opencode-go/glm-5.3"),
            Some("commandcode/zai-org/GLM-5.3")
        );
        assert_eq!(map.target_for("opencode-go/kimi-k3"), None);
    }

    #[test]
    fn only_quota_and_rate_limit_rejections_fall_back() {
        assert!(is_fallback_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_fallback_status(StatusCode::PAYMENT_REQUIRED));
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::BAD_REQUEST,
            StatusCode::BAD_GATEWAY,
        ] {
            assert!(!is_fallback_status(status));
        }
    }
}
