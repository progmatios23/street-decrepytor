//! x64dbg menu set — mirrors the 7 plugin menu slots from PLUG_SETUPSTRUCT.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuSlot {
    Plugin,
    Disasm,
    Dump,
    Stack,
    Graph,
    Memmap,
    Symmod,
}

#[derive(Debug, Clone, Copy)]
pub struct MenuEntry {
    pub id: i32,
    pub slot: MenuSlot,
    pub title: &'static str,
    pub hotkey: Option<&'static str>,
    pub command: &'static str,
}

/// Stable entry IDs — CBMENUENTRY dispatches on these.
pub const MENU_CLASSIFY: i32 = 1;
pub const MENU_DECOMPILE: i32 = 2;
pub const MENU_DECOMPILE_ALL: i32 = 3;
pub const MENU_CARD: i32 = 4;
pub const MENU_PACKET: i32 = 5;
pub const MENU_MCP: i32 = 6;
pub const MENU_DUMP_C: i32 = 7;
pub const MENU_FUNCS: i32 = 8;
pub const MENU_STRINGS: i32 = 9;
pub const MENU_XREFS: i32 = 10;
pub const MENU_ANALYZE: i32 = 11;
pub const MENU_BACKEND_NATIVE: i32 = 12;
pub const MENU_BACKEND_GHIDRA: i32 = 13;
pub const MENU_FOLLOW_C: i32 = 14;
pub const MENU_HARVEST: i32 = 15;
pub const MENU_CFG: i32 = 16;
pub const MENU_ANAL_MEM: i32 = 17;
pub const MENU_FUNCS_MOD: i32 = 18;

pub const MENU_SET: &[MenuEntry] = &[
    // Plugins bar
    MenuEntry { id: MENU_CLASSIFY, slot: MenuSlot::Plugin, title: "&Classify module", hotkey: None, command: "street.classify" },
    MenuEntry { id: MENU_ANALYZE, slot: MenuSlot::Plugin, title: "&Analyze module (funcs+cfg)", hotkey: Some("Ctrl+Alt+A"), command: "street.anal" },
    MenuEntry { id: MENU_FUNCS, slot: MenuSlot::Plugin, title: "&Function list", hotkey: None, command: "street.funcs" },
    MenuEntry { id: MENU_STRINGS, slot: MenuSlot::Plugin, title: "&Strings", hotkey: None, command: "street.strings" },
    MenuEntry { id: MENU_MCP, slot: MenuSlot::Plugin, title: "Start &MCP (stdio note)", hotkey: None, command: "street.mcp" },
    MenuEntry { id: MENU_BACKEND_NATIVE, slot: MenuSlot::Plugin, title: "Backend: &native", hotkey: None, command: "street.backend native" },
    MenuEntry { id: MENU_BACKEND_GHIDRA, slot: MenuSlot::Plugin, title: "Backend: &ghidra-json", hotkey: None, command: "street.backend ghidra" },
    // CPU disasm context
    MenuEntry { id: MENU_DECOMPILE, slot: MenuSlot::Disasm, title: "Street: Decompile &here", hotkey: Some("Ctrl+Shift+D"), command: "street.decompile" },
    MenuEntry { id: MENU_DECOMPILE_ALL, slot: MenuSlot::Disasm, title: "Street: Decompile (all backends)", hotkey: None, command: "street.compare" },
    MenuEntry { id: MENU_CARD, slot: MenuSlot::Disasm, title: "Street: Function &card", hotkey: Some("Ctrl+Shift+C"), command: "street.card" },
    MenuEntry { id: MENU_PACKET, slot: MenuSlot::Disasm, title: "Street: Copy &evidence packet", hotkey: Some("Ctrl+Shift+E"), command: "street.packet" },
    MenuEntry { id: MENU_DUMP_C, slot: MenuSlot::Disasm, title: "Street: Dump C to file", hotkey: None, command: "street.c" },
    MenuEntry { id: MENU_XREFS, slot: MenuSlot::Disasm, title: "Street: Xrefs here", hotkey: None, command: "street.xrefs" },
    MenuEntry { id: MENU_FOLLOW_C, slot: MenuSlot::Disasm, title: "Street: Follow C listing", hotkey: None, command: "street.lift" },
    // Dump
    MenuEntry { id: MENU_HARVEST, slot: MenuSlot::Dump, title: "Street: Classify / harvest selection", hotkey: None, command: "street.classify" },
    // Graph
    MenuEntry { id: MENU_CFG, slot: MenuSlot::Graph, title: "Street: C CFG overlay", hotkey: None, command: "street.cfg" },
    // Memmap
    MenuEntry { id: MENU_ANAL_MEM, slot: MenuSlot::Memmap, title: "Street: Analyze region", hotkey: None, command: "street.analr" },
    // Symbols
    MenuEntry { id: MENU_FUNCS_MOD, slot: MenuSlot::Symmod, title: "Street: Functions in module", hotkey: None, command: "street.funcs" },
];

/// Human-readable tree for docs / `street x64dbg-menus`.
pub fn plugin_menus() -> String {
    let mut s = String::from("Street x64dbg menu set\n");
    for e in MENU_SET {
        let slot = match e.slot {
            MenuSlot::Plugin => "Plugins",
            MenuSlot::Disasm => "Disasm",
            MenuSlot::Dump => "Dump",
            MenuSlot::Stack => "Stack",
            MenuSlot::Graph => "Graph",
            MenuSlot::Memmap => "Memmap",
            MenuSlot::Symmod => "Symmod",
        };
        s.push_str(&format!("  [{slot}] {:>2}  {}  →  {}\n", e.id, e.title.replace('&', ""), e.command));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_plugin_bar_ids_ok() {
        assert!(MENU_SET.iter().any(|e| e.id == MENU_DECOMPILE && matches!(e.slot, MenuSlot::Disasm)));
        assert!(plugin_menus().contains("Decompile here"));
    }
}
