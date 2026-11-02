/*
 * StreetKernel.sys — Ring 0 Kernel Monitor Driver
 * Target: Windows 11 x64, WDK 10.0.26100+, KMDF 1.33
 * Compile: Visual Studio + WDK, x64 Release, kernel mode
 *
 * Capabilities:
 *   1. PsSetCreateProcessNotifyRoutineEx  — track target process spawns
 *   2. ObRegisterCallbacks                — strip PROCESS_TERMINATE from security tools
 *   3. WFP stream callout                 — intercept TCP/HTTP downloads in kernel RAM
 *   4. IOCTL device                       — bidirectional kernel ↔ userland event channel
 *
 * Build note: link Fwpkclnt.lib, Ndis.lib, ntoskrnl.lib
 */

#include <ntddk.h>
#include <wdf.h>
#include <fwpmk.h>
#include <fwpsk.h>
#include <ndis.h>

#pragma warning(disable: 4100 4201)
#pragma comment(lib, "Fwpkclnt.lib")
#pragma comment(lib, "Ndis.lib")

// ---------------------------------------------------------------------------
// Constants & device paths
// ---------------------------------------------------------------------------

#define STREET_DEVICE_NAME   L"\\Device\\StreetKernel"
#define STREET_DOS_LINK      L"\\DosDevices\\StreetKernel"
#define STREET_POOL_TAG      'STKN'
#define MAX_EVENT_QUEUE      256
#define MAX_PAYLOAD_BYTES    (8 * 1024 * 1024)  // 8 MB max captured per event

// IOCTL codes
#define IOCTL_STREET_GET_EVENT  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA)
#define IOCTL_STREET_SET_TARGET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define IOCTL_STREET_FORCE_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_WRITE_DATA)

// ---------------------------------------------------------------------------
// Event types sent to userland
// ---------------------------------------------------------------------------

typedef enum _STREET_EVENT_TYPE {
    EvtProcessSpawn    = 1,
    EvtProcessExit     = 2,
    EvtNetworkPayloadMz = 3,
    EvtHighEntropyStream = 4,
    EvtRwxAlloc        = 5,
} STREET_EVENT_TYPE;

#pragma pack(push, 1)
typedef struct _STREET_EVENT {
    STREET_EVENT_TYPE Type;
    ULONG             Pid;
    ULONG             DataSize;
    ULONGLONG         Address;      // for RWX alloc events
    CHAR              ImageName[260];
    // variable payload follows in ring buffer
} STREET_EVENT, *PSTREET_EVENT;
#pragma pack(pop)

// ---------------------------------------------------------------------------
// Ring buffer for kernel→userland events
// ---------------------------------------------------------------------------

typedef struct _EVENT_RING {
    KSPIN_LOCK  Lock;
    ULONG       Head;
    ULONG       Tail;
    ULONG       Count;
    KEVENT      DataReady;
    PSTREET_EVENT Items[MAX_EVENT_QUEUE];
    PVOID         Payloads[MAX_EVENT_QUEUE];  // heap-allocated payload blobs
    ULONG         PayloadSizes[MAX_EVENT_QUEUE];
} EVENT_RING, *PEVENT_RING;

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static PDEVICE_OBJECT   g_DeviceObject = NULL;
static UNICODE_STRING   g_DeviceName;
static UNICODE_STRING   g_DosLink;
static EVENT_RING       g_EventRing;

// WFP
static HANDLE           g_WfpEngineHandle = NULL;
static UINT32           g_WfpCalloutId    = 0;
static UINT64           g_WfpFilterId     = 0;

// ObCallbacks
static PVOID            g_ObCallbackHandle = NULL;

// Target filter: if set, only capture events from this image name
static WCHAR            g_TargetImage[260] = { 0 };

// ---------------------------------------------------------------------------
// Utility — Shannon entropy estimate (fast integer path)
// ---------------------------------------------------------------------------

static BOOLEAN
EntropyHigh(PUCHAR buf, ULONG size)
{
    // Returns TRUE if likely compressed / encrypted (entropy > ~7.0 equivalent)
    // Approximation: count byte-value uniqueness in first 4KB sample
    if (size == 0) return FALSE;
    ULONG sampleSize = min(size, 4096);
    ULONG freq[256] = { 0 };
    for (ULONG i = 0; i < sampleSize; i++) freq[buf[i]]++;
    ULONG unique = 0;
    for (int i = 0; i < 256; i++) if (freq[i]) unique++;
    return unique > 220;  // high diversity ≈ high entropy
}

// ---------------------------------------------------------------------------
// Event ring helpers
// ---------------------------------------------------------------------------

static VOID
RingInit(VOID)
{
    KeInitializeSpinLock(&g_EventRing.Lock);
    KeInitializeEvent(&g_EventRing.DataReady, NotificationEvent, FALSE);
    g_EventRing.Head = g_EventRing.Tail = g_EventRing.Count = 0;
}

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

// ---------------------------------------------------------------------------
// Process Notify Callback — PsSetCreateProcessNotifyRoutineEx
// ---------------------------------------------------------------------------

static VOID
StreetProcessNotify(
    _Inout_ PEPROCESS Process,
    _In_    HANDLE    ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    STREET_EVENT evt = { 0 };
    evt.Pid = HandleToULong(ProcessId);

    if (CreateInfo != NULL) {
        // Process creation
        evt.Type = EvtProcessSpawn;
        if (CreateInfo->ImageFileName) {
            ULONG copyLen = min(
                (ULONG)CreateInfo->ImageFileName->Length / sizeof(WCHAR),
                (ULONG)(sizeof(evt.ImageName) / sizeof(WCHAR) - 1));
            // Convert Unicode to narrow for simplicity
            for (ULONG i = 0; i < copyLen; i++)
                evt.ImageName[i] = (CHAR)CreateInfo->ImageFileName->Buffer[i];
        }
        RingPush(&evt, NULL, 0);
    } else {
        evt.Type = EvtProcessExit;
        RingPush(&evt, NULL, 0);
    }
}

// ---------------------------------------------------------------------------
// ObCallback — strip PROCESS_TERMINATE from security tools on our target
// ---------------------------------------------------------------------------

static OB_PREOP_CALLBACK_STATUS
StreetObPreCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInfo)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Only filter handle-open operations to processes
    if (OperationInfo->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;

    PEPROCESS targetProc = (PEPROCESS)OperationInfo->Object;
    PEPROCESS requestor  = PsGetCurrentProcess();
    if (targetProc == requestor)
        return OB_PREOP_SUCCESS;

    // Strip termination rights from any process not in our list
    // This protects StreetAgent from being killed by the target or AV
    if (OperationInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
        OperationInfo->Parameters->CreateHandleInformation.DesiredAccess &=
            ~(PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME);
    } else if (OperationInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        OperationInfo->Parameters->DuplicateHandleInformation.DesiredAccess &=
            ~(PROCESS_TERMINATE | PROCESS_VM_WRITE);
    }

    return OB_PREOP_SUCCESS;
}

// ---------------------------------------------------------------------------
// WFP Stream Classify Callout — intercepts inbound TCP byte streams
// ---------------------------------------------------------------------------

static VOID NTAPI
StreetWfpClassify(
    _In_ const FWPS_INCOMING_VALUES0        *inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUE0 *inMetaValues,
    _Inout_opt_ void                        *layerData,
    _In_opt_ const void                     *classifyContext,
    _In_ const FWPS_FILTER1                 *filter,
    _In_ UINT64                              flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0              *classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    // Always permit — we observe, not block
    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (!layerData) return;

    FWPS_STREAM_CALLOUT_IO_PACKET0 *streamPkt =
        (FWPS_STREAM_CALLOUT_IO_PACKET0 *)layerData;
    if (!streamPkt->streamData || !streamPkt->streamData->netBufferListChain)
        return;

    // Flatten the NET_BUFFER_LIST into a contiguous buffer for inspection
    NET_BUFFER_LIST *nbl    = streamPkt->streamData->netBufferListChain;
    NET_BUFFER      *nb     = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb) return;

    ULONG dataLen = NET_BUFFER_DATA_LENGTH(nb);
    if (dataLen < 2 || dataLen > MAX_PAYLOAD_BYTES) return;

    // Allocate staging buffer
    PUCHAR staging = ExAllocatePool2(POOL_FLAG_NON_PAGED, dataLen, STREET_POOL_TAG);
    if (!staging) return;

    PUCHAR flat = NdisGetDataBuffer(nb, dataLen, staging, 1, 0);
    if (!flat) {
        ExFreePool(staging);
        return;
    }

    BOOLEAN isMz         = (flat[0] == 'M' && flat[1] == 'Z');
    BOOLEAN isHighEntropy = (!isMz && EntropyHigh(flat, dataLen));

    if (isMz || isHighEntropy) {
        // Copy payload for ring buffer
        PVOID payloadCopy = ExAllocatePool2(POOL_FLAG_NON_PAGED, dataLen, STREET_POOL_TAG);
        if (payloadCopy) {
            RtlCopyMemory(payloadCopy, flat, dataLen);

            STREET_EVENT evt = { 0 };
            evt.Type     = isMz ? EvtNetworkPayloadMz : EvtHighEntropyStream;
            evt.Pid      = HandleToULong(PsGetCurrentProcessId());
            evt.DataSize = dataLen;

            if (!RingPush(&evt, payloadCopy, dataLen))
                ExFreePool(payloadCopy);
        }
    }

    if (flat != staging) {} // flat may point inside nbl — don't free
    ExFreePool(staging);
}

static NTSTATUS NTAPI
StreetWfpNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID              *filterKey,
    _Inout_ FWPS_FILTER1         *filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// WFP Registration
// ---------------------------------------------------------------------------

static NTSTATUS
WfpRegister(PDEVICE_OBJECT devObj)
{
    NTSTATUS status;

    // Open the filter engine
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_WfpEngineHandle);
    if (!NT_SUCCESS(status)) return status;

    // Register our callout
    FWPS_CALLOUT1 callout = { 0 };
    const GUID CALLOUT_GUID = {
        0xf53ba53d, 0x17c0, 0x4b3e,
        { 0xa2, 0x4f, 0x1a, 0x7b, 0x4c, 0x3e, 0x9d, 0x01 }
    };
    callout.calloutKey          = CALLOUT_GUID;
    callout.classifyFn          = StreetWfpClassify;
    callout.notifyFn            = StreetWfpNotify;
    callout.flowDeleteFn        = NULL;
    callout.flags               = 0;

    status = FwpsCalloutRegister1(devObj, &callout, &g_WfpCalloutId);
    if (!NT_SUCCESS(status)) {
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        return status;
    }

    // Add callout to engine
    FWPM_CALLOUT0 mCallout = { 0 };
    mCallout.calloutKey        = CALLOUT_GUID;
    mCallout.displayData.name  = L"StreetKernel WFP Callout";
    mCallout.applicableLayer   = FWPM_LAYER_STREAM_V4;

    FwpmTransactionBegin0(g_WfpEngineHandle, 0);
    FwpmCalloutAdd0(g_WfpEngineHandle, &mCallout, NULL, NULL);

    // Add filter to bind callout to inbound stream
    FWPM_FILTER0 filter = { 0 };
    const GUID FILTER_GUID = {
        0xab3dce85, 0x2f11, 0x4d6a,
        { 0xbc, 0x11, 0x72, 0x3c, 0x4d, 0x2e, 0x8f, 0x11 }
    };
    filter.filterKey          = FILTER_GUID;
    filter.displayData.name   = L"StreetKernel Stream Filter";
    filter.layerKey            = FWPM_LAYER_STREAM_V4;
    filter.action.type         = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey   = CALLOUT_GUID;
    filter.weight.type         = FWP_EMPTY;
    filter.numFilterConditions = 0;  // match all streams

    FwpmFilterAdd0(g_WfpEngineHandle, &filter, NULL, &g_WfpFilterId);
    FwpmTransactionCommit0(g_WfpEngineHandle);

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// IOCTL dispatch — kernel ↔ userland
// ---------------------------------------------------------------------------

static NTSTATUS
StreetIoControl(PDEVICE_OBJECT devObj, PIRP irp)
{
    UNREFERENCED_PARAMETER(devObj);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    ULONG code               = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buf                = irp->AssociatedIrp.SystemBuffer;
    ULONG inLen              = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen             = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG_PTR info           = 0;
    NTSTATUS status          = STATUS_SUCCESS;

    switch (code) {

    case IOCTL_STREET_GET_EVENT: {
        // Userland polls for the next event (header only; payload returned separately)
        STREET_EVENT evt    = { 0 };
        PVOID payload       = NULL;
        ULONG payloadSize   = 0;

        if (!RingPop(&evt, &payload, &payloadSize)) {
            // No event — wait briefly
            LARGE_INTEGER timeout;
            timeout.QuadPart = -1 * 10 * 1000 * 500;  // 500ms
            KeWaitForSingleObject(&g_EventRing.DataReady, Executive, KernelMode, FALSE, &timeout);
            if (!RingPop(&evt, &payload, &payloadSize)) {
                status = STATUS_NO_MORE_ENTRIES;
                break;
            }
        }
        if (outLen >= sizeof(STREET_EVENT)) {
            RtlCopyMemory(buf, &evt, sizeof(STREET_EVENT));
            info = sizeof(STREET_EVENT);
        }
        // Payload is freed here — userland must issue IOCTL_STREET_GET_EVENT
        // multiple times with larger buffers to retrieve large payloads.
        // For simplicity we embed DataSize in the event header; full payload
        // transfer is handled by a separate IOCTL in the full implementation.
        if (payload) ExFreePool(payload);
        break;
    }

    case IOCTL_STREET_SET_TARGET: {
        // Set target image name filter (wide string)
        if (inLen > 0 && inLen <= sizeof(g_TargetImage) - 2) {
            RtlZeroMemory(g_TargetImage, sizeof(g_TargetImage));
            RtlCopyMemory(g_TargetImage, buf, inLen);
        }
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

// ---------------------------------------------------------------------------
// DriverUnload
// ---------------------------------------------------------------------------

static VOID
StreetDriverUnload(PDRIVER_OBJECT driverObj)
{
    UNREFERENCED_PARAMETER(driverObj);

    // Unregister WFP
    if (g_WfpEngineHandle) {
        FwpmTransactionBegin0(g_WfpEngineHandle, 0);
        if (g_WfpFilterId)  FwpmFilterDeleteById0(g_WfpEngineHandle, g_WfpFilterId);
        FwpmTransactionCommit0(g_WfpEngineHandle);
        FwpsCalloutUnregisterById0(g_WfpCalloutId);
        FwpmCalloutDeleteById0(g_WfpEngineHandle, g_WfpCalloutId);
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
    }

    // Unregister ObCallbacks
    if (g_ObCallbackHandle) {
        ObUnRegisterCallbacks(g_ObCallbackHandle);
        g_ObCallbackHandle = NULL;
    }

    // Unregister process notify
    PsSetCreateProcessNotifyRoutineEx(StreetProcessNotify, TRUE);

    // Remove device / symlink
    IoDeleteSymbolicLink(&g_DosLink);
    if (g_DeviceObject) IoDeleteDevice(g_DeviceObject);
}

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;

    RtlInitUnicodeString(&g_DeviceName, STREET_DEVICE_NAME);
    RtlInitUnicodeString(&g_DosLink,    STREET_DOS_LINK);

    // Create device object
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

    // Create symbolic link for userland access
    status = IoCreateSymbolicLink(&g_DosLink, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Hook IRP dispatch routines
    DriverObject->DriverUnload                         = StreetDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = StreetCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = StreetCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = StreetIoControl;

    // Initialize event ring
    RingInit();

    // Register process notify callback
    status = PsSetCreateProcessNotifyRoutineEx(StreetProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink(&g_DosLink);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    // Register ObCallbacks to protect our agent from target
    OB_OPERATION_REGISTRATION opReg = { 0 };
    OB_CALLBACK_REGISTRATION  cbReg = { 0 };
    opReg.ObjectType           = PsProcessType;
    opReg.Operations           = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation         = StreetObPreCallback;
    opReg.PostOperation        = NULL;
    cbReg.Version              = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.OperationRegistration      = &opReg;
    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"321000");
    cbReg.Altitude             = altitude;
    cbReg.RegistrationContext  = NULL;
    ObRegisterCallbacks(&cbReg, &g_ObCallbackHandle);

    // Register WFP callout
    status = WfpRegister(g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        // WFP optional — driver still useful without it
        DbgPrint("[StreetKernel] WFP register failed: 0x%X (continuing)\n", status);
    }

    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrint("[StreetKernel] Loaded. Device: %wZ\n", &g_DeviceName);
    return STATUS_SUCCESS;
}
