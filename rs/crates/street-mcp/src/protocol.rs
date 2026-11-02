use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct JsonRpcReq {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcRes {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
}

impl JsonRpcRes {
    pub fn ok(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }
}

pub fn initialize(req: &JsonRpcReq) -> JsonRpcRes {
    JsonRpcRes::ok(
        req.id.clone(),
        serde_json::json!({
            "protocolVersion": crate::PROTOCOL_VERSION,
            "capabilities": {
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": crate::SERVER_NAME,
                "version": crate::SERVER_VERSION
            },
            "instructions": "Token-first RE server. Prefer func.card and evidence.packet over decompile. Never dump a whole binary. max_chars defaults are small on purpose."
        }),
    )
}

pub fn text_result(id: Option<serde_json::Value>, text: String) -> JsonRpcRes {
    JsonRpcRes::ok(
        id,
        serde_json::json!({
            "content": [{ "type": "text", "text": text }]
        }),
    )
}

pub fn json_result(id: Option<serde_json::Value>, v: serde_json::Value) -> JsonRpcRes {
    let text = serde_json::to_string(&v).unwrap_or_else(|_| "{}".into());
    text_result(id, text)
}
