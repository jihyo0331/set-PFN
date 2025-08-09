//testapp.c
/*++

Copyright (c) 1990-98  Microsoft Corporation All Rights Reserved

Module Name:

    testapp.c

Abstract:

Environment:

    Win32 console multi-threaded application

--*/
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include <sys\sioctl.h>


BOOLEAN
ManageDriver(
    _In_ LPCTSTR  DriverName,
    _In_ LPCTSTR  ServiceName,
    _In_ USHORT   Function
);

BOOLEAN
SetupDriverName(
    _Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation,
    _In_ ULONG BufferLength
);

char OutputBuffer[100];
char InputBuffer[100];

void dump(const void* mem, size_t length) {
    const unsigned char* data = (const unsigned char*)mem;
    size_t i, j;

    for (i = 0; i < length; i += 16) {
        // Print offset
        printf("%016p  ", (((char*)mem + i)));

        // Print hex bytes
        for (j = 0; j < 16; ++j) {
            if (i + j < length) {
                printf("%02x ", data[i + j]);
            }
            else {
                printf("   ");
            }
        }

        // Print ASCII characters
        printf(" ");
        for (j = 0; j < 16; ++j) {
            if (i + j < length) {
                unsigned char ch = data[i + j];
                printf("%c", isprint(ch) ? ch : '.');
            }
            else {
                printf(" ");
            }
        }

        printf("\n");
    }
}


typedef unsigned __int64 QWORD;

char* g_pVa = NULL;
QWORD g_qwNotepadPfn = 0;

VOID __cdecl
main(
    _In_ ULONG argc,
    _In_reads_(argc) PCHAR argv[]
)
{
    HANDLE hDevice;
    BOOL bRc;
    ULONG bytesReturned;
    DWORD errNum = 0;
    TCHAR driverLocation[MAX_PATH] = "";

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    //
    // open the device
    //

    if ((hDevice = CreateFile("\\\\.\\IoctlTest",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL)) == INVALID_HANDLE_VALUE) {

        errNum = GetLastError();

        if (errNum != ERROR_FILE_NOT_FOUND) {

            printf("CreateFile failed : %d\n", errNum);

            return;
        }

        //
        // The driver is not started yet so let us the install the driver.
        // First setup full path to driver name.
        //

        if (!SetupDriverName(driverLocation, sizeof(driverLocation))) {

            return;
        }

        if (!ManageDriver(DRIVER_NAME,
            driverLocation,
            DRIVER_FUNC_INSTALL
        )) {

            printf("Unable to install driver.\n");

            //
            // Error - remove driver.
            //

            ManageDriver(DRIVER_NAME,
                driverLocation,
                DRIVER_FUNC_REMOVE
            );

            return;
        }

        hDevice = CreateFile("\\\\.\\IoctlTest",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hDevice == INVALID_HANDLE_VALUE) {
            printf("Error: CreatFile Failed : %d\n", GetLastError());
            return;
        }

    }

    char cInput;
	BOOL bExit = FALSE;
    while (!bExit)
    {
        cInput = (char)getchar();
        switch (cInput)
        {
        case '1':
            printf("1\n");
            g_pVa = (char*)malloc(4096);
            printf("%p\n", g_pVa);
			
            break;

        case '2':
            dump(g_pVa, 4096);
            break;

        case '3':
        {
            unsigned int unPid = GetCurrentProcessId();

            bRc = DeviceIoControl(hDevice,
                (DWORD)IOCTL_SET_PID,
                &unPid,
                (DWORD)sizeof(unPid),
                &OutputBuffer,
                sizeof(OutputBuffer),
                &bytesReturned,
                NULL
            );
            printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
            unsigned __int64 un64Pfn = 0;
            bRc = DeviceIoControl(hDevice,
                (DWORD)IOCTL_SET_VA,
                &g_pVa,
                (DWORD)sizeof(g_pVa),
                &un64Pfn,
                sizeof(un64Pfn),
                &bytesReturned,
                NULL
            );

            if (!bRc)
            {
                printf("Error in DeviceIoControl : %d", GetLastError());
                return;
            }
            printf("    OutBuffer (%d), pfn : 0x%llx\n", bytesReturned, un64Pfn);

        }
        break;
        case '4':
        {
            QWORD qwNewPfn = g_qwNotepadPfn >> 12;

            bRc = DeviceIoControl(hDevice,
                (DWORD)IOCTL_SET_PFN,
                &qwNewPfn,
                (DWORD)sizeof(qwNewPfn),
                &OutputBuffer,
                sizeof(OutputBuffer),
                &bytesReturned,
                NULL
            );
            if (!bRc)
            {
                printf("Error in DeviceIoControl : %d", GetLastError());
                return;
            }
            printf("    OutBuffer (%d)\n", bytesReturned);

        }
        break;


        case 'q':
            bExit = TRUE;
            break;

        case '0':
            //notepad pid
        {
            StringCbCopy(InputBuffer, sizeof(InputBuffer),
                "This String is from User Application; using METHOD_BUFFERED");

            printf("\nCalling DeviceIoControl METHOD_BUFFERED:\n");

            memset(OutputBuffer, 0, sizeof(OutputBuffer));

            printf("PID : ");
            unsigned int unPid;
            scanf_s("%d", &unPid);

            printf("VA : ");
            unsigned __int64 un64Va;
            scanf_s("%llx", &un64Va);
            printf("pid : %u, va : %llx\n", unPid, un64Va);

            bRc = DeviceIoControl(hDevice,
                (DWORD)IOCTL_SET_PID,
                &unPid,
                (DWORD)sizeof(unPid),
                &OutputBuffer,
                sizeof(OutputBuffer),
                &bytesReturned,
                NULL
            );

            if (!bRc)
            {
                printf("Error in DeviceIoControl : %d", GetLastError());
                return;

            }
            printf("    OutBuffer (%d): %s\n", bytesReturned, OutputBuffer);
            unsigned __int64 un64Pfn = 0;
            bRc = DeviceIoControl(hDevice,
                (DWORD)IOCTL_SET_VA,
                &un64Va,
                (DWORD)sizeof(un64Va),
                &un64Pfn,
                sizeof(un64Pfn),
                &bytesReturned,
                NULL
            );

            if (!bRc)
            {
                printf("Error in DeviceIoControl : %d", GetLastError());
                return;

            }
            printf("    OutBuffer (%d), pfn : 0x%llx\n", bytesReturned, un64Pfn);
            g_qwNotepadPfn = un64Pfn;
        }
            break;
        }
    }

    //
    // Printing Input & Output buffer pointers and size
    //

    printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
        sizeof(InputBuffer));
    printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
        sizeof(OutputBuffer));
    //
    // Performing METHOD_BUFFERED
    //

    

    CloseHandle(hDevice);

    //
    // Unload the driver.  Ignore any errors.
    //

    ManageDriver(DRIVER_NAME,
        driverLocation,
        DRIVER_FUNC_REMOVE
    );


    //
    // close the handle to the device.
    //

}
