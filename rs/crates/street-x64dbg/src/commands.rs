//! Street command set — registered via `_plugin_registercommand`, same table as x64dbg cmds.

#[derive(Debug, Clone, Copy)]
pub struct Command {
    pub name: &'static str,
    pub help: &'static str,
    pub debugonly: bool,
}

/// Mirrors x64dbg analysis group (`anal`, `analr`, `cfanal`) plus Street verbs.
pub const COMMAND_SET: &[Command] = &[
    Command { name: "street.anal", help: "Analyze current module: functions + cfg (native)", debugonly: true },
    Command { name: "street.analr", help: "Recursive analyze from CIP", debugonly: true },
    Command { name: "street.decompile", help: "Decompile CIP/addr to C (native motor)", debugonly: true },
    Command { name: "street.lift", help: "Native C only, ignore other backends", debugonly: true },
    Command { name: "street.c", help: "Write C listing of CIP function to file", debugonly: true },
    Command { name: "street.card", help: "Function card (no body) — token-cheap", debugonly: true },
    Command { name: "street.packet", help: "Evidence packet to log/clipboard", debugonly: true },
    Command { name: "street.funcs", help: "List recovered functions", debugonly: true },
    Command { name: "street.xrefs", help: "Xrefs at addr", debugonly: true },
    Command { name: "street.cfg", help: "CFG edges for function", debugonly: true },
    Command { name: "street.strings", help: "Interesting strings in module", debugonly: false },
    Command { name: "street.classify", help: "Classify current module image", debugonly: false },
    Command { name: "street.backend", help: "street.backend native|ghidra|ida|binja", debugonly: false },
    Command { name: "street.backends", help: "List backend capability flags", debugonly: false },
    Command { name: "street.compare", help: "Compare backends at CIP, capped", debugonly: true },
    Command { name: "street.mcp", help: "Print MCP launch line (street-mcp stdio)", debugonly: false },
];

pub fn command_help() -> String {
    let mut s = String::from("Street command set\n");
    for c in COMMAND_SET {
        s.push_str(&format!("  {:<18} {}\n", c.name, c.help));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_decompile() {
        assert!(COMMAND_SET.iter().any(|c| c.name == "street.decompile"));
        assert!(COMMAND_SET.iter().any(|c| c.name == "street.packet"));
    }
}
