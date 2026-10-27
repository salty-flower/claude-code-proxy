use base64::Engine;
use serde_json::Value;

const PREFIX: &str = "ccp:codex:v1:";
const PROVENANCE_PREFIX: &str = "ccp:codex:v2:";
const MAX_ID_BYTES: usize = 4 * 1024;
const MAX_ENCRYPTED_CONTENT_BYTES: usize = 8 * 1024 * 1024;

/// Whether `signature` was produced by this proxy's Codex reasoning replay
/// encoder.
///
/// These signatures embed the opaque `encrypted_content` replay blob, so
/// traffic captures redact the whole value. Keeping the check beside the
/// encoder keeps the format definition in one place.
pub(crate) fn is_proxy_reasoning_signature(signature: &str) -> bool {
    signature.starts_with(PREFIX)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReasoningReplay {
    pub id: String,
    pub encrypted_content: String,
}

#[derive(Debug, Clone, Default)]
pub struct PendingReasoning {
    id: Option<String>,
    encrypted_content: Option<String>,
}

impl PendingReasoning {
    pub fn capture(&mut self, item: &Value) {
        if let Some(id) = non_empty_string(item.get("id")) {
            self.id = Some(id.to_string());
        }
        if let Some(encrypted_content) = non_empty_string(item.get("encrypted_content")) {
            self.encrypted_content = Some(encrypted_content.to_string());
        }
    }

    pub fn replay(&self) -> Option<ReasoningReplay> {
        Some(ReasoningReplay {
            id: self.id.clone()?,
            encrypted_content: self.encrypted_content.clone()?,
        })
    }
}

pub fn encode_reasoning_signature(replay: &ReasoningReplay) -> Option<String> {
    if replay.id.is_empty()
        || replay.id.len() > MAX_ID_BYTES
        || replay.encrypted_content.is_empty()
        || replay.encrypted_content.len() > MAX_ENCRYPTED_CONTENT_BYTES
    {
        return None;
    }
    let encoded_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(replay.id.as_bytes());
    Some(format!("{PREFIX}{encoded_id}:{}", replay.encrypted_content))
}

pub fn decode_reasoning_signature(signature: &str) -> Option<ReasoningReplay> {
    // v1 remains replayable with unknown provenance. v2 records origin but
    // does not discard ciphertext on account changes: cross-account replay is
    // provisionally supported and must fail explicitly if upstream rejects it.
    let payload = if let Some(payload) = signature.strip_prefix(PROVENANCE_PREFIX) {
        let (provenance, payload) = payload.split_once(':')?;
        if !valid_provenance(provenance) {
            return None;
        }
        payload
    } else {
        signature.strip_prefix(PREFIX)?
    };
    if payload.is_empty() || payload.len() > max_payload_len() {
        return None;
    }
    let (encoded_id, encrypted_content) = payload.split_once(':')?;
    if encoded_id.is_empty()
        || encoded_id.len() > encoded_id_len_limit()
        || encrypted_content.is_empty()
        || encrypted_content.len() > MAX_ENCRYPTED_CONTENT_BYTES
    {
        return None;
    }
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_id)
        .ok()?;
    if id.is_empty() || id.len() > MAX_ID_BYTES {
        return None;
    }
    Some(ReasoningReplay {
        id: String::from_utf8(id).ok()?,
        encrypted_content: encrypted_content.to_string(),
    })
}

fn valid_provenance(provenance: &str) -> bool {
    provenance.len() == 64 && provenance.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn signature_with_provenance(signature: String, provenance: Option<&str>) -> String {
    match (provenance, signature.strip_prefix(PREFIX)) {
        (Some(provenance), Some(payload)) if valid_provenance(provenance) => {
            format!("{PROVENANCE_PREFIX}{provenance}:{payload}")
        }
        _ => signature,
    }
}

pub(crate) fn annotate_response_signatures(response: &mut Value, provenance: &str) {
    if let Some(content) = response.get_mut("content").and_then(Value::as_array_mut) {
        for block in content {
            if block.get("type").and_then(Value::as_str) != Some("thinking") {
                continue;
            }
            if let Some(signature) = block.get_mut("signature")
                && let Some(value) = signature.as_str()
            {
                *signature = Value::String(signature_with_provenance(
                    value.to_owned(),
                    Some(provenance),
                ));
            }
        }
    }
}

fn encoded_id_len_limit() -> usize {
    MAX_ID_BYTES.div_ceil(3) * 4
}

fn max_payload_len() -> usize {
    encoded_id_len_limit() + 1 + MAX_ENCRYPTED_CONTENT_BYTES
}

fn non_empty_string(value: Option<&Value>) -> Option<&str> {
    value?.as_str().filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn signature_round_trip_preserves_reasoning_identity() {
        let replay = ReasoningReplay {
            id: "rs_1".to_string(),
            encrypted_content: "gAAAAopaque".to_string(),
        };
        let signature = encode_reasoning_signature(&replay).unwrap();
        assert!(signature.starts_with(PREFIX));
        assert!(signature.ends_with(":gAAAAopaque"));
        assert_eq!(decode_reasoning_signature(&signature), Some(replay));
    }

    #[test]
    fn rotate_signature_provenance_migrates_v1_without_losing_ciphertext() {
        let replay = ReasoningReplay {
            id: "rs_1".to_owned(),
            encrypted_content: "opaque-cross-account".to_owned(),
        };
        let legacy = encode_reasoning_signature(&replay).unwrap();
        let provenance = "a".repeat(64);
        let annotated = signature_with_provenance(legacy.clone(), Some(&provenance));
        assert!(annotated.starts_with(PROVENANCE_PREFIX));
        assert_eq!(decode_reasoning_signature(&legacy), Some(replay.clone()));
        assert_eq!(decode_reasoning_signature(&annotated), Some(replay));
        assert!(decode_reasoning_signature("ccp:codex:v2:invalid:rs:ciphertext").is_none());
    }

    #[test]
    fn foreign_and_malformed_signatures_are_ignored() {
        assert_eq!(decode_reasoning_signature("anthropic-signature"), None);
        assert_eq!(decode_reasoning_signature("ccp:codex:v1:not-base64"), None);
    }

    #[test]
    fn pending_reasoning_keeps_early_metadata_when_done_omits_it() {
        let mut pending = PendingReasoning::default();
        pending.capture(&json!({
            "id": "rs_1",
            "encrypted_content": "early"
        }));
        pending.capture(&json!({"id": "rs_1"}));
        assert_eq!(
            pending.replay(),
            Some(ReasoningReplay {
                id: "rs_1".to_string(),
                encrypted_content: "early".to_string(),
            })
        );
    }

    #[test]
    fn oversized_signature_is_ignored_without_decoding() {
        let signature = format!(
            "{PREFIX}cnNfMQ:{}",
            "A".repeat(MAX_ENCRYPTED_CONTENT_BYTES + 1)
        );
        assert_eq!(decode_reasoning_signature(&signature), None);
    }
}
