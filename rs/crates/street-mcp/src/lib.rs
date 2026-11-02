//! MCP stdio server. Token-first: cards and evidence packets, never full listings by default.

pub mod budget;
pub mod packet;
pub mod protocol;
pub mod session;
pub mod tools;

use protocol::{JsonRpcReq, JsonRpcRes};
use session::SessionStore;
use std::io::{BufRead, BufReader, Write};
use std::sync::Mutex;

pub const PROTOCOL_VERSION: &str = "2024-11-05";
pub const SERVER_NAME: &str = "street-decrepytor";
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn serve_stdio() -> anyhow::Result<()> {
    let store = Mutex::new(SessionStore::new());
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    // Support both LSP-style Content-Length and newline JSON.
    let mut reader = BufReader::new(stdin.lock());
    loop {
        let msg = match read_message(&mut reader) {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(_) => break,
        };
        let req: JsonRpcReq = match serde_json::from_str(&msg) {
            Ok(r) => r,
            Err(e) => {
                write_message(&mut stdout, &error_res(None, -32700, &e.to_string()))?;
                continue;
            }
        };
        if req.method == "notifications/initialized" || req.method.starts_with("notifications/") {
            continue;
        }
        let res = dispatch(&store, &req);
        write_message(&mut stdout, &res)?;
    }
    Ok(())
}

fn dispatch(store: &Mutex<SessionStore>, req: &JsonRpcReq) -> JsonRpcRes {
    match req.method.as_str() {
        "initialize" => protocol::initialize(req),
        "ping" => JsonRpcRes::ok(req.id.clone(), serde_json::json!({})),
        "tools/list" => tools::list_tools(req),
        "tools/call" => tools::call_tool(store, req),
        "resources/list" => JsonRpcRes::ok(req.id.clone(), serde_json::json!({"resources": []})),
        _ => error_res(req.id.clone(), -32601, &format!("unknown method {}", req.method)),
    }
}

fn error_res(id: Option<serde_json::Value>, code: i64, msg: &str) -> JsonRpcRes {
    JsonRpcRes {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(serde_json::json!({"code": code, "message": msg})),
    }
}

fn read_message<R: BufRead>(r: &mut R) -> std::io::Result<Option<String>> {
    let mut header = String::new();
    let mut content_len: Option<usize> = None;
    loop {
        header.clear();
        let n = r.read_line(&mut header)?;
        if n == 0 {
            return Ok(None);
        }
        let line = header.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Content-Length:") {
            content_len = rest.trim().parse().ok();
        }
        // newline-delimited JSON (no headers)
        if line.starts_with('{') {
            return Ok(Some(line.to_string()));
        }
    }
    if let Some(len) = content_len {
        let mut buf = vec![0u8; len];
        r.read_exact(&mut buf)?;
        Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
    } else {
        Ok(None)
    }
}

fn write_message<W: Write>(w: &mut W, res: &JsonRpcRes) -> std::io::Result<()> {
    let body = serde_json::to_string(res).unwrap();
    write!(w, "Content-Length: {}\r\n\r\n{}", body.len(), body)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_lists_caps() {
        let req = JsonRpcReq {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::json!(1)),
            method: "initialize".into(),
            params: serde_json::json!({}),
        };
        let res = protocol::initialize(&req);
        let r = res.result.unwrap();
        assert_eq!(r["protocolVersion"], PROTOCOL_VERSION);
        assert!(r["capabilities"]["tools"].is_object());
    }

    #[test]
    fn tools_list_not_empty() {
        let req = JsonRpcReq {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::json!(1)),
            method: "tools/list".into(),
            params: serde_json::json!({}),
        };
        let res = tools::list_tools(&req);
        let tools = res.result.unwrap()["tools"].as_array().unwrap().clone();
        assert!(tools.iter().any(|t| t["name"] == "func.card"));
        assert!(tools.iter().any(|t| t["name"] == "evidence.packet"));
        assert!(tools.iter().any(|t| t["name"] == "decompile"));
    }
}
