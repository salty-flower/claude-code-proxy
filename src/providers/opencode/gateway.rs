/// What distinguishes one OpenAI/Anthropic-compatible gateway from another
/// once the wire protocols are shared: its registry name, the label used in
/// error messages, how its key is configured, and an optional session header.
#[derive(Debug)]
pub struct Gateway {
    pub provider: &'static str,
    pub label: &'static str,
    pub key_hint: &'static str,
    pub session_header: Option<&'static str>,
}

pub static OPENCODE_GO: Gateway = Gateway {
    provider: "opencode",
    label: "OpenCode Go",
    key_hint: "set CCP_OPENCODE_API_KEY, OPENCODE_API_KEY, CCP_OPENCODE_API_KEY_FILE, or opencode.apiKey in config.json",
    session_header: Some("x-opencode-session"),
};
