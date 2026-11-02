//! JSON-aware truncation. Keep valid JSON. Set truncated=true.

pub fn bounded_json(mut v: serde_json::Value, max_chars: usize) -> serde_json::Value {
    let mut width = 32usize;
    let mut depth = 8usize;
    loop {
        prune(&mut v, depth, width);
        let s = serde_json::to_string(&v).unwrap_or_default();
        if s.len() <= max_chars || width <= 4 {
            if s.len() > max_chars {
                if let serde_json::Value::Object(ref mut m) = v {
                    m.insert("truncated".into(), serde_json::Value::Bool(true));
                }
            }
            return v;
        }
        width = (width / 2).max(4);
        depth = depth.saturating_sub(1).max(2);
    }
}

fn prune(v: &mut serde_json::Value, depth: usize, width: usize) {
    if depth == 0 {
        *v = serde_json::json!("[truncated]");
        return;
    }
    match v {
        serde_json::Value::Array(a) => {
            if a.len() > width {
                a.truncate(width);
            }
            for x in a.iter_mut() {
                prune(x, depth - 1, width);
            }
        }
        serde_json::Value::Object(m) => {
            let keys: Vec<String> = m.keys().cloned().collect();
            if keys.len() > width {
                for k in keys.iter().skip(width) {
                    m.remove(k);
                }
                m.insert("_omitted_keys".into(), serde_json::json!(keys.len() - width));
            }
            for x in m.values_mut() {
                prune(x, depth - 1, width);
            }
        }
        serde_json::Value::String(s) if s.len() > 400 => {
            s.truncate(400);
            s.push_str("…");
        }
        _ => {}
    }
}

pub fn cap_str(s: &str, max: usize) -> (String, bool) {
    if s.len() <= max {
        (s.to_string(), false)
    } else {
        let mut t = s[..max].to_string();
        t.push_str("\n[truncated; request specific evidence]");
        (t, true)
    }
}
