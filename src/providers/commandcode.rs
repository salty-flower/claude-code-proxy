//! Command Code's Provider API: the same three wire protocols as OpenCode Go
//! behind `https://api.commandcode.ai/provider/v1`, so it runs as a second
//! instance of the OpenCode gateway provider. Its catalog is large and changes
//! often, so the routed models come from a JSON file rather than a compiled-in
//! table; a deployment narrows the list there.

use std::sync::Arc;

use serde::Deserialize;

use crate::provider::CliHandlers;
use crate::providers::opencode::OpenCodeProvider;
use crate::providers::opencode::gateway::Gateway;
use crate::providers::opencode::model::{EndpointKind, ModelCatalog, ResolvedModel};

pub const MODEL_PREFIX: &str = "commandcode/";

pub static COMMAND_CODE: Gateway = Gateway {
    provider: "commandcode",
    label: "Command Code",
    key_hint: "set CCP_COMMANDCODE_API_KEY, CMD_API_KEY, CCP_COMMANDCODE_API_KEY_FILE, or commandcode.apiKey in config.json",
    session_header: None,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireEndpoint {
    ChatCompletions,
    Messages,
    Responses,
}

#[derive(Debug, Deserialize)]
struct CatalogEntry {
    id: String,
    endpoint: WireEndpoint,
}

/// Command Code model IDs reuse other vendors' names (`gpt-6-luna`,
/// `claude-opus-5-5`), so they are routed and advertised only with the
/// `commandcode/` prefix and never steal a bare ID from another provider.
#[derive(Debug, Default)]
pub struct CommandCodeCatalog {
    models: Vec<ResolvedModel>,
}

impl CommandCodeCatalog {
    pub fn from_json(raw: &str) -> anyhow::Result<Self> {
        let entries: Vec<CatalogEntry> = serde_json::from_str(raw)?;
        let models = entries
            .into_iter()
            .map(|entry| ResolvedModel {
                id: entry.id,
                endpoint: match entry.endpoint {
                    WireEndpoint::ChatCompletions => EndpointKind::ChatCompletions,
                    WireEndpoint::Messages => EndpointKind::Messages,
                    WireEndpoint::Responses => EndpointKind::Responses,
                },
            })
            .collect();
        Ok(Self { models })
    }

    /// A missing or unreadable file leaves the lane empty rather than
    /// stopping the proxy: the other providers must keep working.
    fn load_configured() -> Self {
        let Some(path) = crate::config::commandcode_models_file() else {
            return Self::default();
        };
        let loaded = std::fs::read_to_string(&path)
            .map_err(anyhow::Error::from)
            .and_then(|raw| Self::from_json(&raw));
        match loaded {
            Ok(catalog) => catalog,
            Err(error) => {
                eprintln!("claude-code-proxy: ignoring Command Code models file {path}: {error}");
                Self::default()
            }
        }
    }
}

impl ModelCatalog for CommandCodeCatalog {
    fn resolve(&self, raw: &str) -> Option<ResolvedModel> {
        let id = raw.strip_prefix(MODEL_PREFIX)?;
        self.models.iter().find(|model| model.id == id).cloned()
    }

    fn advertised_models(&self) -> Vec<String> {
        let mut models: Vec<String> = self
            .models
            .iter()
            .map(|model| format!("{MODEL_PREFIX}{}", model.id))
            .collect();
        models.sort_unstable();
        models
    }
}

pub fn provider() -> OpenCodeProvider {
    OpenCodeProvider::for_gateway(
        &COMMAND_CODE,
        Arc::new(CommandCodeCatalog::load_configured()),
        &COMMAND_CODE_CLI,
        crate::config::commandcode_base_url(),
        crate::config::commandcode_api_key(),
    )
}

struct CommandCodeCli;

impl CliHandlers for CommandCodeCli {
    fn login(&self) -> anyhow::Result<()> {
        anyhow::bail!("Command Code uses an API key; {}", COMMAND_CODE.key_hint)
    }

    fn device(&self) -> anyhow::Result<()> {
        self.login()
    }

    fn status(&self) -> anyhow::Result<()> {
        let Some(source) = crate::config::commandcode_api_key_source() else {
            anyhow::bail!("Not authenticated");
        };
        println!("API key configured: true");
        println!("Source: {source}");
        println!("Base URL: {}", crate::config::commandcode_base_url());
        Ok(())
    }

    fn logout(&self) -> anyhow::Result<()> {
        anyhow::bail!(
            "Command Code credentials are managed through environment variables or config.json"
        )
    }
}

static COMMAND_CODE_CLI: CommandCodeCli = CommandCodeCli;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anthropic::schema::MessagesRequest;
    use crate::provider::{Provider, RequestContext};
    use crate::providers::opencode::client::OpenCodeClient;
    use axum::{
        Json, Router,
        extract::{OriginalUri, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
    };
    use serde_json::json;
    use std::sync::Mutex;

    const CATALOG: &str = r#"[
        {"id": "deepseek/deepseek-v4.1-flash", "endpoint": "chat_completions"},
        {"id": "zai-org/GLM-5.3", "endpoint": "chat_completions"},
        {"id": "claude-sonnet-5-5", "endpoint": "messages"}
    ]"#;

    fn context() -> RequestContext {
        RequestContext {
            req_id: "req_test".to_string(),
            provider: "commandcode".to_string(),
            session_id: Some("claude-session".to_string()),
            session_seq: None,
            monitor: None,
            traffic: None,
        }
    }

    #[test]
    fn catalog_routes_only_prefixed_listed_models() {
        let catalog = CommandCodeCatalog::from_json(CATALOG).unwrap();
        let resolved = catalog
            .resolve("commandcode/deepseek/deepseek-v4.1-flash")
            .unwrap();
        assert_eq!(resolved.id, "deepseek/deepseek-v4.1-flash");
        assert_eq!(resolved.endpoint, EndpointKind::ChatCompletions);
        assert_eq!(
            catalog
                .resolve("commandcode/claude-sonnet-5-5")
                .unwrap()
                .endpoint,
            EndpointKind::Messages
        );
        // Bare IDs belong to other providers; unlisted models stay unrouted.
        assert!(catalog.resolve("claude-sonnet-5-5").is_none());
        assert!(
            catalog
                .resolve("commandcode/deepseek/deepseek-v4-pro")
                .is_none()
        );
        assert_eq!(
            catalog.advertised_models(),
            [
                "commandcode/claude-sonnet-5-5",
                "commandcode/deepseek/deepseek-v4.1-flash",
                "commandcode/zai-org/GLM-5.3",
            ]
        );
    }

    #[test]
    fn malformed_catalog_is_rejected() {
        assert!(CommandCodeCatalog::from_json(r#"[{"id": "x", "endpoint": "grpc"}]"#).is_err());
    }

    #[derive(Debug)]
    struct Seen {
        path: String,
        authorization: String,
        opencode_session: Option<String>,
        model: serde_json::Value,
    }

    async fn upstream(
        State(seen): State<Arc<Mutex<Vec<Seen>>>>,
        OriginalUri(uri): OriginalUri,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> Response {
        seen.lock().unwrap().push(Seen {
            path: uri.path().to_string(),
            authorization: headers
                .get(http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string(),
            opencode_session: headers
                .get("x-opencode-session")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            model: body["model"].clone(),
        });
        (
            [(http::header::CONTENT_TYPE, "text/event-stream")],
            concat!(
                "data: {\"choices\":[{\"delta\":{\"content\":\"hello from command code\"}}]}\n\n",
                "data: {\"choices\":[{\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":3}}\n\n",
                "data: [DONE]\n\n"
            ),
        )
            .into_response()
    }

    #[tokio::test]
    async fn requests_reach_the_provider_api_with_the_vendor_model_id() {
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/provider/v1/chat/completions", post(upstream))
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let provider = OpenCodeProvider::with_gateway_client(
            &COMMAND_CODE,
            Arc::new(CommandCodeCatalog::from_json(CATALOG).unwrap()),
            &COMMAND_CODE_CLI,
            OpenCodeClient::for_gateway(
                &COMMAND_CODE,
                format!("http://{address}/provider/v1"),
                Some("cc-key".to_string()),
            )
            .unwrap(),
        );
        assert_eq!(provider.name(), "commandcode");

        let body: MessagesRequest = serde_json::from_value(json!({
            "model": "commandcode/deepseek/deepseek-v4.1-flash",
            "stream": false,
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .unwrap();
        let response = provider.handle_messages(body, context()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["content"][0]["text"], "hello from command code");
        server.abort();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, "/provider/v1/chat/completions");
        assert_eq!(seen[0].authorization, "Bearer cc-key");
        assert_eq!(seen[0].model, "deepseek/deepseek-v4.1-flash");
        assert_eq!(seen[0].opencode_session, None);
    }

    #[tokio::test]
    async fn missing_key_names_command_code_settings() {
        let provider = OpenCodeProvider::with_gateway_client(
            &COMMAND_CODE,
            Arc::new(CommandCodeCatalog::from_json(CATALOG).unwrap()),
            &COMMAND_CODE_CLI,
            OpenCodeClient::for_gateway(&COMMAND_CODE, "https://example.com/v1".into(), None)
                .unwrap(),
        );
        let body: MessagesRequest = serde_json::from_value(json!({
            "model": "commandcode/zai-org/GLM-5.3",
            "messages": [{"role": "user", "content": "hello"}]
        }))
        .unwrap();
        let response = provider.handle_messages(body, context()).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let message = value["error"]["message"].as_str().unwrap();
        assert!(message.contains("Command Code"));
        assert!(message.contains("CMD_API_KEY"));
    }
}
