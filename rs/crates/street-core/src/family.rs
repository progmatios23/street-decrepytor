use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LangFamily {
    NativePe,
    NativeElf,
    Dotnet,
    Java,
    Python,
    Go,
    Rust,
    CppCli,
    Mixed,
    Container,
    Archive,
    Script,
    Unknown,
}

impl LangFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            LangFamily::NativePe => "native_pe",
            LangFamily::NativeElf => "native_elf",
            LangFamily::Dotnet => "dotnet",
            LangFamily::Java => "java",
            LangFamily::Python => "python",
            LangFamily::Go => "go",
            LangFamily::Rust => "rust",
            LangFamily::CppCli => "cpp_cli",
            LangFamily::Mixed => "mixed",
            LangFamily::Container => "container",
            LangFamily::Archive => "archive",
            LangFamily::Script => "script",
            LangFamily::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for LangFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
