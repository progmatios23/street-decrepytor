# Street-Decryptor v2 — Automated VM Sandbox, Kernel Driver & RAM Auto-Dump Architecture Plan

## Executive Overview

**Street-Decryptor v2** shifts from a static Python analysis script to a high-performance **C++20 / Rust Native Core** integrated with a **Windows Kernel-Mode Driver (Ring 0)** and an **Automated Virtual Machine (VM) Sandbox Environment**. 

This platform automatically executes untrusted target binaries (`.exe`), intercepts their outbound network requests (downloads, C2 drops, payload fetches), detects dynamic memory allocations (`VirtualAlloc`, `NtMapViewOfSection`), traps execution on decrypted RAM buffers, and **dumps all downloaded or injected payloads directly from RAM in real time**.

---

## 1. System Architecture Overview

```
+-----------------------------------------------------------------------------------+
|                            HOST ORCHESTRATOR (C++20 / RUST)                        |
|                                                                                   |
|  +------------------------+    +-----------------------+    +------------------+  |
|  | VM Snapshot Controller |    | Payload Store & Logs  |    | PE Rebuilder /   |  |
|  |  (QEMU/Hyper-V API)    |    |  (Dumps, Network PCAP)|    | IAT Fixer        |  |
|  +-----------+------------+    +-----------+-----------+    +--------+---------+  |
+--------------|-----------------------------|-------------------------|------------+
               | VSOCK / Pipe                | Shared Storage          |
+--------------v-----------------------------v-------------------------v------------+
|                        GUEST VIRTUAL MACHINE (WINDOWS 11)                         |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  |                         USERLAND AGENT (C++ / RUST)                         |  |
|  |  - Auto-Exec Target    - PAGE_GUARD Execution Trapper   - IAT Reconstruction|  |
|  +-------------------------------------+---------------------------------------+  |
|                                        | IOCTL Communication                      |
|  +-------------------------------------v---------------------------------------+  |
|  |                      RING 0 KERNEL DRIVER (WDK / C)                         |  |
|  |                                                                             |  |
|  |  [Process/Thread Callbacks]     [WFP Network Engine]     [Memory Filter]      |  |
|  |  - PsSetCreateProcess...        - Intercept HTTP/TCP     - NtWriteVirtualMem  |  |
|  |  - ObRegisterCallbacks          - RAM Download Dumper    - NtMapViewOfSection |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        | Monitored Execution                      |
|  +-------------------------------------v---------------------------------------+  |
|  |                       TARGET EXECUTABLE (untrusted.exe)                     |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Modules & Responsibilities

### Module 1: Automated VM Sandbox Infrastructure
* **Hypervisor Layer:** QEMU/KVM with Libvirt API (or Hyper-V / VirtualBox COM API).
* **Snapshot Management:** Fast revert to clean RAM state prior to target execution.
* **Guest-Host Communication:** Secure, isolated `VSOCK` or Hyper-V VMBus channel for sending targets and receiving live dumps without network leakage.
* **Anti-VM Evasion:** Hardened guest environment (RDTSC offset masking, hypervisor CPUID leaf spoofing, MAC address randomization, fake registry/device drivers).

### Module 2: Ring 0 Kernel Driver (`StreetKernel.sys`)
* **WFP (Windows Filtering Platform) Callout Driver:** Intercepts TCP/UDP network streams. When the target downloads a file/payload, WFP extracts the raw byte stream directly from kernel memory buffers (`NET_BUFFER_LIST`) before it touches disk or disk AV.
* **Process & Thread Notify Routines:** `PsSetCreateProcessNotifyRoutineEx` tracks any child process spawned by the target. `ObRegisterCallbacks` strips `PROCESS_TERMINATE` and `PROCESS_VM_READ` rights from third-party security software trying to interfere.
* **Kernel Memory Allocation Filter:** Hooks native system calls (`NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtWriteVirtualMemory`) to detect when executable memory buffers (`PAGE_EXECUTE_READWRITE` / `0x40`) are allocated or injected into child processes.

### Module 3: Native Userland Monitor & Auto-Dumper (`StreetAgent`)
* **Written in C++20 or Rust:** Maximum performance, zero runtime dependencies.
* **PAGE_GUARD / EPT Execution Trapper:** Traps target memory pages using `PAGE_GUARD` or EPT hypervisor page faults. When decrypted or downloaded payload code attempts to execute, the exception handler fires **instantly**, dumping the raw RAM buffer before anti-debugging code can wipe it.
* **Real-time RAM Downloader Dump:** Synchronizes with `StreetKernel.sys` via IOCTL to automatically write raw downloaded payloads from RAM directly into disk artifacts.
* **IAT & PE Reconstruction Engine:** Parses section headers of RAM dumps, aligns Virtual Addresses (VA) to Raw Data pointers, fixes Import Address Table (IAT) thunks, and outputs fully runnable `.exe` / `.dll` binaries.

---

## 3. Implementation Plans & Phased Roadmap

```
Phase 1: VM Sandbox & Host Orchestrator ──> Phase 2: Ring 0 Driver Development
                                                     │
Phase 4: C++/Rust Userland Auto-Dumper  <── Phase 3: WFP RAM Network Dumper
```

### Phase 1: VM Sandbox Automation & Host Orchestrator
- Deploy Libvirt / QEMU C++ wrapper for snapshot creation, instant VM revert, and VSOCK transport.
- Build host-side submission pipeline that feeds target binaries into the guest VM and waits for output streams.

### Phase 2: Kernel Driver (`StreetKernel.sys`) Core
- Implement `PsSetCreateProcessNotifyRoutineEx` for target & child process lifecycle tracking.
- Implement `ObRegisterCallbacks` to protect `StreetAgent` from target anti-analysis routines.
- Implement IOCTL dispatch interface for bidirectional Userland <-> Kernel communication.

### Phase 3: Kernel WFP Network Download Dumper
- Implement Windows Filtering Platform (`FWPM_LAYER_STREAM_V4`) callouts.
- Inspect incoming network streams (`FWPS_STREAM_CALLOUT_IO_PACKET`).
- Filter payloads with executable signatures (`MZ` / `0x5A4D`, `ELF`, PE sections, encrypted payload entropy) and dump byte streams directly from kernel memory buffers.

### Phase 4: C++ / Rust Auto-Dumper & PE Rebuilder
- Port `street_decrepytor` core to C++20 / Rust.
- Implement PAGE_GUARD exception filter (`AddVectoredExceptionHandler`) for capturing Original Entry Point (OEP) hits.
- Implement automated PE section realignment, IAT pointer resolution, and dump generation.

---

## 4. Code Prototypes & Implementation Details

### A. Kernel Driver: Process Notify & WFP Network Stream Interceptor (`StreetKernel.c`)

```c
// Target: Windows 11 x64 Kernel Driver
// Architecture: WFP Stream Callout + Process Tracking for Real-Time RAM Extraction

#include <ntddk.h>
#include <wdf.h>
#include <fwpmk.h>
#include <fwpsk.h>

#pragma comment(lib, "Fwpkclnt.lib")

// Driver & WFP Global Handles
PDEVICE_OBJECT g_DeviceObject = NULL;
HANDLE g_EngineHandle = NULL;
UINT32 g_CalloutId = 0;

VOID ProcessNotifyCallback(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    UNREFERENCED_PARAMETER(Process);
    if (CreateInfo) {
        DbgPrint("[StreetKernel] Process Spawned: PID %6d | Path: %wZ\n", 
            (ULONG)(ULONG_PTR)ProcessId, CreateInfo->ImageFileName);
    }
}

// WFP Stream Callout: Intercepts inbound network bytes directly in Kernel RAM
VOID NTAPI WfpStreamClassifyCallout(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUE0* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER1* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut) 
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    FWPS_STREAM_CALLOUT_IO_PACKET0* streamPacket = (FWPS_STREAM_CALLOUT_IO_PACKET0*)layerData;
    if (streamPacket && streamPacket->streamData) {
        NET_BUFFER_LIST* nbl = streamPacket->streamData->netBufferListChain;
        if (nbl) {
            NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
            ULONG dataLength = NET_BUFFER_DATA_LENGTH(nb);
            
            if (dataLength >= 2) {
                PUCHAR buffer = (PUCHAR)NdisGetDataBuffer(nb, 2, NULL, 1, 0);
                if (buffer && buffer[0] == 'M' && buffer[1] == 'Z') {
                    DbgPrint("[StreetKernel] ALERT: Executable payload (MZ Header) detected downloading in RAM! Length: %d bytes\n", dataLength);
                    // Trigger IOCTL / Direct Kernel Memory copy to dump payload before disk write
                }
            }
        }
    }
    classifyOut->actionType = FWP_ACTION_PERMIT;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status = STATUS_SUCCESS;

    DriverObject->DriverUnload = (PDRIVER_UNLOAD) [](PDRIVER_OBJECT DriverObj) {
        UNREFERENCED_PARAMETER(DriverObj);
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        DbgPrint("[StreetKernel] Driver Unloaded.\n");
    };

    // Register Process Notify Routine
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status)) return status;

    DbgPrint("[StreetKernel] WFP & Process Monitor Driver initialized successfully.\n");
    return STATUS_SUCCESS;
}
```

---

### B. Rust Userland Auto-Dumper & RAM Execution Trapper (`main.rs`)

```rust
// Target: Windows 11 x64 (Rust 2021 Edition)
// Cargo.toml dependencies: windows = { version = "0.52", features = ["Win32_Foundation", "Win32_System_Memory", "Win32_System_Threading", "Win32_Storage_FileSystem"] }

use std::fs::File;
use std::io::Write;
use std::ptr::null_mut;
use windows::Win32::Foundation::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Storage::FileSystem::*;

pub struct MemoryAutoDumper {
    process_handle: HANDLE,
    pid: u32,
}

impl MemoryAutoDumper {
    pub fn new(pid: u32) -> Result<Self, String> {
        unsafe {
            let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
                .map_err(|e| format!("Failed to open process PID {}: {}", pid, e))?;
            Ok(Self {
                process_handle: handle,
                pid,
            })
        }
    }

    // Traps RAM allocation with PAGE_GUARD to trigger execution dump
    pub fn set_execution_trap(&self, base_address: *const std::ffi::c_void, size: usize) -> bool {
        unsafe {
            let mut old_protect = PAGE_PROTECTION_FLAGS(0);
            let result = VirtualProtectEx(
                self.process_handle,
                base_address,
                size,
                PAGE_EXECUTE_READWRITE | PAGE_GUARD,
                &mut old_protect,
            );
            result.is_ok()
        }
    }

    // Dumps downloaded or decrypted memory payload straight from RAM to disk
    pub fn auto_dump_ram_payload(&self, base_address: *const std::ffi::c_void, size: usize, output_path: &str) -> bool {
        unsafe {
            let mut buffer = vec![0u8; size];
            let mut bytes_read = 0usize;

            if ReadProcessMemory(
                self.process_handle,
                base_address,
                buffer.as_mut_ptr() as *mut _,
                size,
                Some(&mut bytes_read),
            ).is_ok() && bytes_read > 0 {
                if let Ok(mut file) = File::create(output_path) {
                    let _ = file.write_all(&buffer[..bytes_read]);
                    println!("[+] AUTO-DUMP SUCCESS: Saved {} bytes from RAM to {}", bytes_read, output_path);
                    return true;
                }
            }
            false
        }
    }
}

fn main() {
    let target_pid = 1234; // Example PID
    println!("[*] Initializing Street-Decryptor Rust Auto-Dumper for PID: {}", target_pid);

    if let Ok(dumper) = MemoryAutoDumper::new(target_pid) {
        let base_addr = 0x00400000 as *const std::ffi::c_void;
        if dumper.set_execution_trap(base_addr, 0x10000) {
            println!("[+] Execution trap active on base memory address.");
        }
        
        // Simulating immediate RAM dump of downloaded target payload
        dumper.auto_dump_ram_payload(base_addr, 0x10000, "dumped_payload_ram.bin");
    }
}
```

---

## 5. Verification Matrix & Expected Outcomes

| Component | Test Case | Success Criteria |
|-----------|-----------|------------------|
| **VM Sandbox** | Auto-submit `.exe`, revert snapshot after execution | Guest reverts cleanly in < 3 seconds; output logs transfer to host via VSOCK. |
| **WFP Driver** | Executable downloads payload via HTTP/HTTPS | `StreetKernel.sys` catches `MZ` magic bytes in kernel stream and triggers RAM dump. |
| **Memory Monitor** | Target executes `VirtualAlloc` + decrypts shellcode | `PAGE_GUARD` trap catches execution attempt and writes decrypted `.text` to disk. |
| **PE Rebuilder** | Dumped PE has Virtual Address layout | Rebuilder realigns sections (`PointerToRawData`), rebuilds IAT, and produces runnable executable. |
