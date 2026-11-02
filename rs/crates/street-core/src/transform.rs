use serde::{Deserialize, Serialize};

/// Honesty contract (CRITICAL.md): only `cipher` and `runtime_dump` set decrypted=true.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformKind {
    Copy,
    Patch,
    Inflate,
    Cipher,
    Inventoried,
    RuntimeDump,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transform {
    pub kind: TransformKind,
    pub layer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

pub fn image_transform(kind: TransformKind, layer: &str, path: Option<&str>) -> Transform {
    Transform {
        kind,
        layer: layer.to_string(),
        path: path.map(|s| s.to_string()),
        extra: serde_json::Map::new(),
    }
}

pub fn decrypted_flag(transforms: &[Transform]) -> bool {
    transforms
        .iter()
        .any(|t| matches!(t.kind, TransformKind::Cipher | TransformKind::RuntimeDump))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_is_not_decrypt() {
        let t = vec![image_transform(TransformKind::Copy, "res", Some("a"))];
        assert!(!decrypted_flag(&t));
    }

    #[test]
    fn cipher_is_decrypt() {
        let t = vec![image_transform(TransformKind::Cipher, "xor", Some("a"))];
        assert!(decrypted_flag(&t));
    }

    #[test]
    fn runtime_dump_counts() {
        let t = vec![image_transform(TransformKind::RuntimeDump, "themida_text", Some("x"))];
        assert!(decrypted_flag(&t));
    }
}
