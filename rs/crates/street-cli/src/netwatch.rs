//! Observe a process's network peers from outside it.
//!
//! This exists because some targets refuse to be debugged at all. When a target
//! detects the debug object and refuses to run under a tracer, attaching is not
//! an option, and the only observation left is external. For an authentication
//! flow that is also the *right* observation: what matters is the HTTP exchange,
//! and the exchange can be read without putting a single byte inside the target.
//!
//! It also answers the question a syscall trace cannot: which host the target
//! talks to, and therefore which host to intercept.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};

// Address families, as plain constants: the WinSock module path has moved
// between `windows` crate versions and these values are fixed by the ABI.
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

/// One observed remote endpoint.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Peer {
    pub address: String,
    pub port: u16,
}

/// Every remote endpoint the given process currently has a connection to.
///
/// Loopback and the wildcard address are filtered out: a target talking to
/// itself is not a network dependency, and reporting it would bury the peer that
/// matters.
pub fn tcp_peers_of(pid: u32) -> Vec<Peer> {
    let mut out = BTreeMap::new();
    collect_v4(pid, &mut out);
    collect_v6(pid, &mut out);
    out.into_keys().collect()
}

fn collect_v4(pid: u32, out: &mut BTreeMap<Peer, ()>) {
    let Some(buf) = table(AF_INET) else {
        return;
    };
    // MIB_TCPTABLE_OWNER_PID is a u32 count followed by an array of rows. Read
    // the rows through the real struct rather than by byte offset: every field
    // in MIB_TCPROW_OWNER_PID is a DWORD, ports included, and hand-computed
    // offsets get that wrong.
    let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    for i in 0..count {
        let off = 4 + i * row_size;
        if off + row_size > buf.len() {
            break;
        }
        let r: MIB_TCPROW_OWNER_PID =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off).cast()) };
        if r.dwOwningPid != pid {
            continue;
        }
        // Stored in network byte order; a native read reverses it.
        let ip = Ipv4Addr::from(r.dwRemoteAddr.swap_bytes());
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        out.insert(
            Peer {
                address: ip.to_string(),
                // The port occupies the low 16 bits in network order.
                port: (r.dwRemotePort as u16).to_be(),
            },
            (),
        );
    }
}

fn collect_v6(pid: u32, out: &mut BTreeMap<Peer, ()>) {
    let Some(buf) = table(AF_INET6) else {
        return;
    };
    let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let row_size = std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
    for i in 0..count {
        let off = 4 + i * row_size;
        if off + row_size > buf.len() {
            break;
        }
        // MIB_TCP6ROW_OWNER_PID starts with ucLocalAddr and puts dwState last —
        // a different order from the v4 row, which is why this reads the struct.
        let r: MIB_TCP6ROW_OWNER_PID =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off).cast()) };
        if r.dwOwningPid != pid {
            continue;
        }
        let ip = Ipv6Addr::from(r.ucRemoteAddr);
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }
        let port = (r.dwRemotePort as u16).to_be();
        // A v4-mapped address is really a v4 peer; report it once, as v4.
        if let Some(v4) = ip.to_ipv4_mapped() {
            if v4.is_loopback() || v4.is_unspecified() {
                continue;
            }
            out.insert(
                Peer {
                    address: v4.to_string(),
                    port,
                },
                (),
            );
            continue;
        }
        out.insert(
            Peer {
                address: ip.to_string(),
                port,
            },
            (),
        );
    }
}

/// Fetch a `GetExtendedTcpTable` result, growing the buffer as the API demands.
fn table(family: u32) -> Option<Vec<u8>> {
    let mut size: u32 = 0;
    unsafe {
        let r = GetExtendedTcpTable(None, &mut size, false, family, TCP_TABLE_OWNER_PID_ALL, 0);
        if r != ERROR_INSUFFICIENT_BUFFER.0 && r != NO_ERROR.0 {
            return None;
        }
    }
    if size == 0 {
        return None;
    }
    // Slack: the table can grow between the sizing call and the fetch.
    let mut buf = vec![0u8; size as usize + 4096];
    let mut size2 = buf.len() as u32;
    let r = unsafe {
        GetExtendedTcpTable(
            Some(buf.as_mut_ptr().cast()),
            &mut size2,
            false,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if r != NO_ERROR.0 {
        return None;
    }
    buf.truncate(size2 as usize);
    Some(buf)
}

/// Watch a process's peers for `seconds`, returning everything seen.
///
/// Sampling rather than a single read matters: a short-lived connection — an
/// auth call that completes in milliseconds — is invisible to a one-shot look.
pub fn watch(pid: u32, seconds: u64) -> Vec<Peer> {
    let mut seen: BTreeMap<Peer, ()> = BTreeMap::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        if !process_alive(pid) {
            break;
        }
        for p in tcp_peers_of(pid) {
            seen.insert(p, ());
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    seen.into_keys().collect()
}

fn process_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}
