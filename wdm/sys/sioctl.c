/*++

Copyright (c) 1990-98  Microsoft Corporation All Rights Reserved

Module Name:

    sioctl.c

Abstract:

    Purpose of this driver is to demonstrate how the four different types
    of IOCTLs can be used, and how the I/O manager handles the user I/O
    buffers in each case. This sample also helps to understand the usage of
    some of the memory manager functions.

Environment:

    Kernel mode only.

--*/


//
// Include files.
//

#include <ntddk.h>          // various NT definitions
#include <string.h>

#include "sioctl.h"

#define NT_DEVICE_NAME      L"\\Device\\SIOCTL"
#define DOS_DEVICE_NAME     L"\\DosDevices\\IoctlTest"

#if DBG
#define SIOCTL_KDPRINT(_x_) \
                DbgPrint("SIOCTL.SYS: ");\
                DbgPrint _x_;

#else
#define SIOCTL_KDPRINT(_x_)
#endif

//
// Device driver routine declarations.
//

DRIVER_INITIALIZE DriverEntry;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH SioctlCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH SioctlDeviceControl;

DRIVER_UNLOAD SioctlUnloadDriver;

VOID
PrintIrpInfo(
    PIRP Irp
    );
VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, SioctlCreateClose)
#pragma alloc_text( PAGE, SioctlDeviceControl)
#pragma alloc_text( PAGE, SioctlUnloadDriver)
#pragma alloc_text( PAGE, PrintIrpInfo)
#pragma alloc_text( PAGE, PrintChars)
#endif // ALLOC_PRAGMA


NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING      RegistryPath
    )
/*++

Routine Description:
    This routine is called by the Operating System to initialize the driver.

    It creates the device object, fills in the dispatch entry points and
    completes the initialization.

Arguments:
    DriverObject - a pointer to the object that represents this device
    driver.

    RegistryPath - a pointer to our Services key in the registry.

Return Value:
    STATUS_SUCCESS if initialized; an error otherwise.

--*/

{
    NTSTATUS        ntStatus;
    UNICODE_STRING  ntUnicodeString;    // NT Device Name "\Device\SIOCTL"
    UNICODE_STRING  ntWin32NameString;    // Win32 Name "\DosDevices\IoctlTest"
    PDEVICE_OBJECT  deviceObject = NULL;    // ptr to device object

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString( &ntUnicodeString, NT_DEVICE_NAME );

    ntStatus = IoCreateDevice(
        DriverObject,                   // Our Driver Object
        0,                              // We don't use a device extension
        &ntUnicodeString,               // Device name "\Device\SIOCTL"
        FILE_DEVICE_UNKNOWN,            // Device type
        FILE_DEVICE_SECURE_OPEN,     // Device characteristics
        FALSE,                          // Not an exclusive device
        &deviceObject );                // Returned ptr to Device Object

    if ( !NT_SUCCESS( ntStatus ) )
    {
        SIOCTL_KDPRINT(("Couldn't create the device object\n"));
        return ntStatus;
    }

    //
    // Initialize the driver object with this driver's entry points.
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE] = SioctlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SioctlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SioctlDeviceControl;
    DriverObject->DriverUnload = SioctlUnloadDriver;

    //
    // Initialize a Unicode String containing the Win32 name
    // for our device.
    //

    RtlInitUnicodeString( &ntWin32NameString, DOS_DEVICE_NAME );

    //
    // Create a symbolic link between our device name  and the Win32 name
    //

    ntStatus = IoCreateSymbolicLink(
                        &ntWin32NameString, &ntUnicodeString );

    if ( !NT_SUCCESS( ntStatus ) )
    {
        //
        // Delete everything that this routine has allocated.
        //
        SIOCTL_KDPRINT(("Couldn't create symbolic link\n"));
        IoDeleteDevice( deviceObject );
    }


    return ntStatus;
}

NTSTATUS
SioctlCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    )
/*++

Routine Description:

    This routine is called by the I/O system when the SIOCTL is opened or
    closed.

    No action is performed other than completing the request successfully.

Arguments:

    DeviceObject - a pointer to the object that represents the device
    that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/

{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return STATUS_SUCCESS;
}

VOID
SioctlUnloadDriver(
    _In_ PDRIVER_OBJECT DriverObject
    )
/*++

Routine Description:

    This routine is called by the I/O system to unload the driver.

    Any resources previously allocated must be freed.

Arguments:

    DriverObject - a pointer to the object that represents our driver.

Return Value:

    None
--*/

{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING uniWin32NameString;

    PAGED_CODE();

    //
    // Create counted string version of our Win32 device name.
    //

    RtlInitUnicodeString( &uniWin32NameString, DOS_DEVICE_NAME );


    //
    // Delete the link from our device name to a name in the Win32 namespace.
    //

    IoDeleteSymbolicLink( &uniWin32NameString );

    if ( deviceObject != NULL )
    {
        IoDeleteDevice( deviceObject );
    }



}

#define PID_OFFSET 0x440
#define PS_ACTIVE_OFFSET 0x448
#define PFN_MASK(pe)((QWORD)((pe) & 0x0000FFFFFFFFF000UL))
#define PFN_SETZERO(pe)    ((QWORD)((pe) & 0xFFFF000000000FFFUL))
#define DTB_OFFSET 0x028
DWORD g_dwPid = 0;
QWORD g_qwVa = 0;
// Define QWORD if not already defined  
typedef unsigned int DWORD;
typedef unsigned __int64 QWORD;
typedef unsigned int DWORD;
typedef unsigned __int64 QWORD, * PQWORD;

typedef union _virt_addr_t
{
    QWORD value;
    struct
    {
        QWORD offset_4kb : 12;
        QWORD pt_index : 9;
        QWORD pd_index : 9;
        QWORD pdpt_index : 9;
        QWORD pml4_index : 9;
        QWORD reserved : 16;
    }a;

    struct
    {
        QWORD offset_2mb : 21;
        QWORD pd_index : 9;
        QWORD pdpt_index : 9;
        QWORD pml4_index : 9;
        QWORD reserved : 16;
    }b;

    struct
    {
        QWORD offset_1gb : 30;
        QWORD pdpt_index : 9;
        QWORD pml4_index : 9;
        QWORD reserved : 16;
    }c;

} virt_addr_t, * pvirt_addr_t;


// Make the function static to resolve VCR003  
#define DTB_OFFSET 0x028
QWORD GetProcessDirBase(QWORD eproc)
{
    QWORD	directoryTableBase;

    if (eproc == 0x0) {
        return 0x0;
    }

    directoryTableBase = *(QWORD*)(eproc + DTB_OFFSET);
    directoryTableBase = directoryTableBase & 0xfffffffff000;

    return directoryTableBase;
}

// Windows 10 19041 x64
#define PID_OFFSET 0x440
#define PS_ACTIVE_OFFSET 0x448
QWORD FindProcessEPROC(
    _In_ int nPID
)
{
    QWORD eproc = 0x00000000;
    int currentPID = 0;
    int startPID = 0;
    int iCount = 0;
    PLIST_ENTRY plistActiveProcs;

    eproc = (QWORD)PsGetCurrentProcess();
    startPID = (INT) * ((QWORD*)(eproc + (QWORD)PID_OFFSET));
    currentPID = startPID;
    for (;;)
    {
        if (nPID == currentPID)
        {
            return eproc;// found
        }
        else if ((iCount >= 1) && (startPID == currentPID))
        {
            break;
        }
        else {
            plistActiveProcs = (LIST_ENTRY*)(eproc + PS_ACTIVE_OFFSET);
            eproc = (QWORD)plistActiveProcs->Flink - PS_ACTIVE_OFFSET;
            currentPID = (INT) * ((QWORD*)(eproc + (QWORD)PID_OFFSET));
            iCount++;
        }
    }

    return 0;
}


NTSTATUS MmReadPhysical(PVOID targetAddress, ULONG64 sourceAddress, size_t size, size_t* bytesRead)
{
    PHYSICAL_ADDRESS address = { 0 };
    MM_COPY_ADDRESS copyInfo = { 0 };
    address.QuadPart = (LONGLONG)sourceAddress;
    copyInfo.PhysicalAddress = address;
    return MmCopyMemory(targetAddress, copyInfo, size, MM_COPY_MEMORY_PHYSICAL, bytesRead);
}


QWORD GetPfn(ULONG64 cr3, QWORD virtual_addr)
{
    size_t dummy;
    QWORD* ppml4 = NULL;
    QWORD   pdpt = 0;
    QWORD* ppdpt = NULL;
    QWORD   pd = 0;
    QWORD* ppd = NULL;
    QWORD   pt = 0;
    QWORD* ppt = NULL;
    QWORD   pfn = 0;

    virt_addr_t a;

    a.value = virtual_addr;

    size_t copySize = PAGE_SIZE;
    //    Int3();
    PVOID buffer = ExAllocatePool(NonPagedPool, copySize);

    //copy pml4
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "cr3 : %p\n", cr3);
    MmReadPhysical(buffer, cr3, copySize, &dummy);
    ppml4 = (PQWORD)buffer;
    pdpt = ppml4[a.a.pml4_index];
    pdpt = PFN_MASK(pdpt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppml4[%d]:%p\r\n", a.a.pml4_index, pdpt);
    MmReadPhysical(buffer, pdpt, copySize, &dummy);
    ppdpt = (PQWORD)buffer;
    pd = ppdpt[a.a.pdpt_index];
    pd = PFN_MASK(pd);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppdpt[%d]:%p\r\n", a.a.pdpt_index, pd);
    MmReadPhysical(buffer, pd, copySize, &dummy);
    ppd = (PQWORD)buffer;
    pt = ppd[a.a.pd_index];
    pt = PFN_MASK(pt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppd[%d]:%p\r\n", a.a.pd_index, pt);
    MmReadPhysical(buffer, pt, copySize, &dummy);
    ppt = (PQWORD)buffer;
    pfn = ppt[a.a.pt_index];
    pfn = PFN_MASK(pfn);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppt[%d].pfn:%p\r\n", a.a.pt_index, pfn);
    ExFreePool(buffer);

    return pfn;
}

static HANDLE hPhysicalhandle = NULL;

NTSTATUS GetPhysicalHandle()
{
    NTSTATUS status;
    UNICODE_STRING PhysicalMemoryString;
    OBJECT_ATTRIBUTES attributes;

    WCHAR PhysicalMemoryName[] = L"\\Device\\PhysicalMemory";
    RtlInitUnicodeString(&PhysicalMemoryString, PhysicalMemoryName);
    InitializeObjectAttributes(&attributes, &PhysicalMemoryString, 0, NULL, NULL);
    status = ZwOpenSection(&hPhysicalhandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &attributes);

    return status;
}

NTSTATUS WritePhysicalMemory2(DWORD64 PhysicalAddress, DWORD32 WriteData)
{
    NTSTATUS status;
    PVOID BaseAddress = NULL;
    DWORD32 offset;
    LARGE_INTEGER SectionOffset;
    SIZE_T size = 0x2000;

    status = GetPhysicalHandle();
    if (status < 0)
    {
        status = FALSE;
        goto Leave;
    }

    offset = PhysicalAddress & 0xFFF;

    SectionOffset.QuadPart = (ULONGLONG)(PhysicalAddress);

    status = ZwMapViewOfSection(
        hPhysicalhandle,
        NtCurrentProcess(),
        (PVOID*)&BaseAddress,
        0,
        size,
        &SectionOffset,
        &size,
        ViewShare,
        MEM_TOP_DOWN,
        PAGE_READWRITE);

    if (status < 0)
    {
        status = FALSE;
        goto Leave;
    }

    memmove_s((PVOID)((DWORD64)BaseAddress + offset), sizeof(DWORD32), &WriteData, sizeof(DWORD32));

    status = ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);

    if (status < 0)
    {
        status = FALSE;
    }

Leave:
    if (hPhysicalhandle != NULL)
    {
        ZwClose(hPhysicalhandle);
    }

    return status;
}

QWORD SetPfn(QWORD cr3, QWORD virtual_addr, QWORD new_pfn)
{
    size_t dummy;
    QWORD* ppml4 = NULL;
    QWORD   pdpt = 0;
    QWORD* ppdpt = NULL;
    QWORD   pd = 0;
    QWORD* ppd = NULL;
    QWORD   pt = 0;
    QWORD* ppt = NULL;
    QWORD  old_pfn = 0;
    QWORD  tmp_pfn = 0;
    QWORD  pt_entry = 0;

    virt_addr_t a;
    //MM_COPY_ADDRESS copyInfo = { 0 };

    a.value = virtual_addr;

    size_t copySize = PAGE_SIZE;
    //Int3();
    PVOID buffer = ExAllocatePool(NonPagedPool, copySize);

    //copy pml4
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "cr3 : %p\n", cr3);
    MmReadPhysical(buffer, cr3, copySize, &dummy);
    ppml4 = (PQWORD)buffer;
    pdpt = ppml4[a.a.pml4_index];
    pdpt = PFN_MASK(pdpt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppml4[%d]:%p\r\n", a.a.pml4_index, pdpt);
    MmReadPhysical(buffer, pdpt, copySize, &dummy);
    ppdpt = (PQWORD)buffer;
    pd = ppdpt[a.a.pdpt_index];
    pd = PFN_MASK(pd);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppdpt[%d]:%p\r\n", a.a.pdpt_index, pd);
    MmReadPhysical(buffer, pd, copySize, &dummy);
    ppd = (PQWORD)buffer;
    pt = ppd[a.a.pd_index];
    pt = PFN_MASK(pt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppd[%d]:%p\r\n", a.a.pd_index, pt);

    MmReadPhysical(buffer, pt, copySize, &dummy);
    ppt = (PQWORD)buffer;
    tmp_pfn = ppt[a.a.pt_index];
    old_pfn = PFN_MASK(tmp_pfn);
    tmp_pfn = PFN_SETZERO(tmp_pfn);
    new_pfn = new_pfn << 12;
    tmp_pfn = tmp_pfn | new_pfn;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppt[%d].old_pfn:%p tmp_pfn\r\n", a.a.pt_index, old_pfn, tmp_pfn);

    pt_entry = pt + 8 * a.a.pt_index;

    PHYSICAL_ADDRESS val2 = { 0, };
    val2.QuadPart = tmp_pfn;

    WritePhysicalMemory2(pt_entry, val2.LowPart);
    WritePhysicalMemory2(pt_entry + 4, val2.HighPart);

    MmReadPhysical(buffer, pt, copySize, &dummy);
    ppt = (PQWORD)buffer;
    tmp_pfn = ppt[a.a.pt_index];
    tmp_pfn = PFN_MASK(tmp_pfn);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppt[%d].new_pfn:%p\r\n", a.a.pt_index, tmp_pfn);

    ExFreePool(buffer);

    return old_pfn;
}


NTSTATUS
SioctlDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    )

/*++

Routine Description:

    This routine is called by the I/O system to perform a device I/O
    control function.

Arguments:

    DeviceObject - a pointer to the object that represents the device
        that I/O is to be done on.

    Irp - a pointer to the I/O Request Packet for this request.

Return Value:

    NT status code

--*/

{
    PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
    NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
    ULONG               inBufLength; // Input buffer length
    ULONG               outBufLength; // Output buffer length
    //PCHAR               inBuf, outBuf; // pointer to Input and output buffer

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    irpSp = IoGetCurrentIrpStackLocation( Irp );
    inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    if (!inBufLength || !outBufLength)
    {
        ntStatus = STATUS_INVALID_PARAMETER;
        goto End;
    }

    //
    // Determine which I/O control code was specified.
    //

 
    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_SET_PID:
    {
        unsigned int* pdwPid = NULL;
        pdwPid = Irp->AssociatedIrp.SystemBuffer;
        SIOCTL_KDPRINT(("\tData from User :"));
        DbgPrintEx(0, 0, "PID : %u", *pdwPid);
        g_dwPid = *pdwPid;
        Irp->IoStatus.Information = 0;
    }
        break;



    case IOCTL_SET_VA:
    {
        // SystemBuffer 가 METHOD_BUFFERED 로 할당된 버퍼 주소
        unsigned __int64* pun64Va = (unsigned __int64*)Irp->AssociatedIrp.SystemBuffer;

        // 올바르게 역참조
        g_qwVa = *pun64Va;
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "VA from user: 0x%llx\n", g_qwVa);

        // 프로세스 찾고, CR3 구하고, PFN 찾기 …
        QWORD eproc = FindProcessEPROC(g_dwPid);
        QWORD qwCr3 = GetProcessDirBase(eproc);
        QWORD qwPfn = GetPfn(qwCr3, g_qwVa);

        // 결과를 다시 SystemBuffer 에 복사
        RtlCopyBytes(Irp->AssociatedIrp.SystemBuffer, &qwPfn, sizeof(qwPfn));
        Irp->IoStatus.Information = sizeof(qwPfn);
    }
    break;

    case IOCTL_SET_PFN:
    {
        unsigned __int64* pun64NewPfn = NULL;
        char* outBuf = NULL;
        pun64NewPfn = Irp->AssociatedIrp.SystemBuffer;
        DbgPrintEx(0, 0, "New Pfn : %llx, g_dwPid: %u, g_qwVa: %llx", *pun64NewPfn, g_dwPid, g_qwVa);

        QWORD eproc = 0;
        eproc = FindProcessEPROC(g_dwPid);
        QWORD qwCr3 = 0;
        qwCr3 = GetProcessDirBase(eproc);


        SetPfn(qwCr3, g_qwVa, *pun64NewPfn);

        Irp->IoStatus.Information = 0;

    }
    break;






    default:

        //
        // The specified I/O control code is unrecognized by this driver.
        //

        ntStatus = STATUS_INVALID_DEVICE_REQUEST;
        SIOCTL_KDPRINT(("ERROR: unrecognized IOCTL %x\n",
            irpSp->Parameters.DeviceIoControl.IoControlCode));
        break;
    }

End:
    //
    // Finish the I/O operation by simply completing the packet and returning
    // the same status as in the packet itself.
    //

    Irp->IoStatus.Status = ntStatus;

    IoCompleteRequest( Irp, IO_NO_INCREMENT );

    return ntStatus;
}

VOID
PrintIrpInfo(
    PIRP Irp)
{
    PIO_STACK_LOCATION  irpSp;
    irpSp = IoGetCurrentIrpStackLocation( Irp );

    PAGED_CODE();

    SIOCTL_KDPRINT(("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
        Irp->AssociatedIrp.SystemBuffer));
    SIOCTL_KDPRINT(("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
        irpSp->Parameters.DeviceIoControl.Type3InputBuffer));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.InputBufferLength));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.OutputBufferLength ));
    return;
}

VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
    )
{
    PAGED_CODE();

    if (CountChars) {

        while (CountChars--) {

            if (*BufferAddress > 31
                 && *BufferAddress != 127) {

                KdPrint (( "%c", *BufferAddress) );

            } else {

                KdPrint(( ".") );

            }
            BufferAddress++;
        }
        KdPrint (("\n"));
    }
    return;
}



