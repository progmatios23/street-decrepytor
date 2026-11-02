//! x64dbg plugin + command/menu set. Copy `street_x64dbg.dll` as `plugins/street.dp64`.

pub mod commands;
pub mod menus;

#[cfg(windows)]
pub mod abi;
#[cfg(windows)]
pub mod plugin;

pub use commands::COMMAND_SET;
pub use menus::{plugin_menus, MenuEntry, MENU_SET};

pub const PLUGIN_NAME: &str = "Street";
pub const PLUGIN_VERSION: i32 = 2;
