use serde::{Deserialize, Serialize};

/// Guide §11: prefer "I don't know" over a fake fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Heuristic,
    Signature,
    Pdb,
    Dwarf,
    Dynamic,
    Kernel,
    Manual,
    Decoder,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Heuristic => "heuristic",
            Origin::Signature => "signature",
            Origin::Pdb => "pdb",
            Origin::Dwarf => "dwarf",
            Origin::Dynamic => "dynamic",
            Origin::Kernel => "kernel",
            Origin::Manual => "manual",
            Origin::Decoder => "decoder",
        }
    }
}
