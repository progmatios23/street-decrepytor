//! StreetKernel.sys client. Fallback: none — caller uses RPM if `open()` fails.
//! IOCTL numbers match `kernel/StreetKernel.c`.

use serde::{Deserialize, Serialize};

pub const DEVICE: &str = r"\\.\StreetKernel";

const FILE_DEVICE_UNKNOWN: u32 = 0x00000022;
const METHOD_BUFFERED: u32 = 0;
const FILE_READ_DATA: u32 = 1;
const FILE_WRITE_DATA: u32 = 2;

const fn ctl(fn_code: u32, access: u32) -> u32 {
    (FILE_DEVICE_UNKNOWN << 16) | (access << 14) | (fn_code << 2) | METHOD_BUFFERED
}

pub const IOCTL_GET_EVENT: u32 = ctl(0x801, FILE_READ_DATA);
pub const IOCTL_SET_TARGET: u32 = ctl(0x802, FILE_WRITE_DATA);
pub const IOCTL_FORCE_DUMP: u32 = ctl(0x803, FILE_WRITE_DATA);
pub const IOCTL_GET_PAYLOAD: u32 = ctl(0x804, FILE_READ_DATA);
pub const IOCTL_READ_VIRTUAL: u32 = ctl(0x806, FILE_READ_DATA);

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct ReadVirtIn {
    pub pid: u32,
    pub address: u64,
    pub size: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct StreetEvent {
    pub ty: u32,
    pub pid: u32,
    pub data_size: u32,
    pub address: u64,
    pub image_name: [u8; 260],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelStatus {
    pub present: bool,
    pub device: String,
    pub note: String,
}

pub struct KernelClient {
    #[cfg(windows)]
    handle: Option<windows::Win32::Foundation::HANDLE>,
}

impl KernelClient {
    pub fn open() -> Self {
        #[cfg(windows)]
        {
            use windows::core::PCWSTR;
            use windows::Win32::Foundation::GENERIC_READ;
            use windows::Win32::Storage::FileSystem::{
                CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
            };
            let wide: Vec<u16> = DEVICE.encode_utf16().chain(std::iter::once(0)).collect();
            let h = unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    GENERIC_READ.0 | windows::Win32::Foundation::GENERIC_WRITE.0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            };
            match h {
                Ok(handle) if !handle.is_invalid() => Self { handle: Some(handle) },
                _ => Self { handle: None },
            }
        }
        #[cfg(not(windows))]
        Self {}
    }

    pub fn present(&self) -> bool {
        #[cfg(windows)]
        {
            self.handle.is_some()
        }
        #[cfg(not(windows))]
        false
    }

    pub fn status(&self) -> KernelStatus {
        KernelStatus {
            present: self.present(),
            device: DEVICE.into(),
            note: if self.present() {
                "StreetKernel.sys open — physical VA walk available".into()
            } else {
                "driver not loaded — usermode RPM only".into()
            },
        }
    }

    pub fn read_virtual(&self, pid: u32, addr: u64, size: u32) -> Option<Vec<u8>> {
        #[cfg(windows)]
        {
            use windows::Win32::System::IO::DeviceIoControl;
            let h = self.handle?;
            let inp = ReadVirtIn {
                pid,
                address: addr,
                size,
            };
            let mut out = vec![0u8; size as usize];
            let mut ret = 0u32;
            let ok = unsafe {
                DeviceIoControl(
                    h,
                    IOCTL_READ_VIRTUAL,
                    Some((&inp as *const ReadVirtIn).cast()),
                    std::mem::size_of::<ReadVirtIn>() as u32,
                    Some(out.as_mut_ptr().cast()),
                    size,
                    Some(&mut ret),
                    None,
                )
            };
            if ok.is_ok() && ret > 0 {
                out.truncate(ret as usize);
                Some(out)
            } else {
                None
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (pid, addr, size);
            None
        }
    }

    pub fn set_target(&self, image: &str) -> bool {
        #[cfg(windows)]
        {
            use windows::Win32::System::IO::DeviceIoControl;
            let Some(h) = self.handle else { return false };
            let mut wide: Vec<u16> = image.encode_utf16().collect();
            wide.push(0);
            let mut ret = 0u32;
            unsafe {
                DeviceIoControl(
                    h,
                    IOCTL_SET_TARGET,
                    Some(wide.as_ptr().cast()),
                    (wide.len() * 2) as u32,
                    None,
                    0,
                    Some(&mut ret),
                    None,
                )
                .is_ok()
            }
        }
        #[cfg(not(windows))]
        {
            let _ = image;
            false
        }
    }
}

impl Drop for KernelClient {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if let Some(h) = self.handle.take() {
                let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
            }
        }
    }
}
