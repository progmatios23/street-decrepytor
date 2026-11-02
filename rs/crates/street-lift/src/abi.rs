use crate::Abi;

pub fn arg_name(abi: Abi, index: usize) -> String {
    match abi {
        Abi::Win64 => match index {
            0 => "arg0".into(),
            1 => "arg1".into(),
            2 => "arg2".into(),
            3 => "arg3".into(),
            n => format!("arg{n}"),
        },
        Abi::Sysv | Abi::Aapcs64 => format!("arg{index}"),
        Abi::Cdecl => format!("arg{index}"),
    }
}

pub fn win64_reg_arg(reg: &str) -> Option<usize> {
    match reg {
        "rcx" | "ecx" | "cx" => Some(0),
        "rdx" | "edx" | "dx" => Some(1),
        "r8" | "r8d" => Some(2),
        "r9" | "r9d" => Some(3),
        _ => None,
    }
}

pub fn sysv_reg_arg(reg: &str) -> Option<usize> {
    match reg {
        "rdi" | "edi" => Some(0),
        "rsi" | "esi" => Some(1),
        "rdx" | "edx" => Some(2),
        "rcx" | "ecx" => Some(3),
        "r8" | "r8d" => Some(4),
        "r9" | "r9d" => Some(5),
        _ => None,
    }
}
