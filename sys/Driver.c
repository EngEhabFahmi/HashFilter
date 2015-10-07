#include "Rule.h"
#include "ioctl.h"
#include "Monitor.h"


#define IOCTL_APC_ENABLE   			 CTL_CODE( FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define IOCTL_APC_DISABLE 			 CTL_CODE( FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define IOCTL_APC_ADD_WHITE_PROCESS  CTL_CODE( FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS  )


//
// Software Tracing Definitions 
//
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(MsnMntrInit,(e7db16bb, 41be, 4c05, b73e, 5feca06f8207),  \
        WPP_DEFINE_BIT(TRACE_INIT)               \
        WPP_DEFINE_BIT(TRACE_SHUTDOWN) )

#include "Driver.tmh"

PDEVICE_OBJECT monitorDeviceObject;
UNICODE_STRING monitorSymbolicLink;

// ===========================================================================
//
// LOCAL PROTOTYPES
//
// ===========================================================================

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    IN  PDRIVER_OBJECT          driverObject,
    IN  PUNICODE_STRING         registryPath
    );

DRIVER_UNLOAD DriverUnload;
VOID
DriverUnload(
    IN  PDRIVER_OBJECT          driverObject
    );

// ===========================================================================
//
// PUBLIC FUNCTIONS
//
// ===========================================================================

NTSTATUS
DeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    );
	
	NTSTATUS
CreateClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    );
	
NTSTATUS
DriverEntry(
    IN  PDRIVER_OBJECT          driverObject,
    IN  PUNICODE_STRING         registryPath
    )
{
   NTSTATUS          status;
   UNICODE_STRING    deviceName;
   BOOLEAN           validSymbolicLink = FALSE;
   BOOLEAN           initializedCallouts = FALSE;

   //
   // This macro is required to initialize software tracing on XP and beyond
   // For XP and beyond use the DriverObject as the first argument.
   // 
   
   WPP_INIT_TRACING(driverObject,registryPath);

   DoTraceMessage(TRACE_INIT, "Initializing MsnMonitor Driver");

   monitorDeviceObject = NULL;

   UNREFERENCED_PARAMETER(registryPath);

   driverObject->DriverUnload = DriverUnload;

   // status = MonitorCtlDriverInit(driverObject);

   // if (!NT_SUCCESS(status))
   // {
      // goto cleanup;
   // }

   RtlInitUnicodeString(&deviceName,
                        MONITOR_DEVICE_NAME);

   status = IoCreateDevice(driverObject, 0, &deviceName, FILE_DEVICE_NETWORK, 0, FALSE, &monitorDeviceObject);
   if (!NT_SUCCESS(status))
   {
      goto cleanup;
   }

   status = NetworkMonitorInitialize(monitorDeviceObject);
   if (!NT_SUCCESS(status))
   {
      initializedCallouts = TRUE;
      goto cleanup;
   }

   RtlInitUnicodeString(&monitorSymbolicLink, MONITOR_SYMBOLIC_NAME);

   status = IoCreateSymbolicLink(&monitorSymbolicLink, &deviceName);

   if (!NT_SUCCESS(status))
   {
      goto cleanup;
   }
    validSymbolicLink = TRUE;
	InitRuleSpinLock();
	InitializePidHashMapListHead();
 	InitLogFile();
	PsSetCreateProcessNotifyRoutine(ProcessCallback, FALSE);
	
	driverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	

cleanup:
   if (!NT_SUCCESS(status))
   {
      DoTraceMessage(TRACE_INIT, "MsnMonitor Initialization Failed.");

      WPP_CLEANUP(driverObject);

      if (initializedCallouts)
      if (validSymbolicLink)
      {
         IoDeleteSymbolicLink(&monitorSymbolicLink);
      }

      if (monitorDeviceObject)
      {
         IoDeleteDevice(monitorDeviceObject);
      }
   }

   return status;
}

VOID
DriverUnload(
    IN  PDRIVER_OBJECT          driverObject
    )
{
   UNREFERENCED_PARAMETER(driverObject);

   NetworkMonitorUninitialize();
   PsSetCreateProcessNotifyRoutine(ProcessCallback, TRUE);
   
   IoDeleteDevice(monitorDeviceObject);
   IoDeleteSymbolicLink(&monitorSymbolicLink);
	CloseLogFilehandle();
   DoTraceMessage(TRACE_SHUTDOWN, "MsnMonitor Driver Shutting Down");

   WPP_CLEANUP(driverObject);
}




NTSTATUS
CreateClose(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )
{
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    
    return STATUS_SUCCESS;
}


NTSTATUS
DeviceControl(
    IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp
    )


{
    PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
    NTSTATUS            ntStatus = STATUS_SUCCESS;// Assume success
    ULONG               inBufLength; // Input buffer length
    PWCHAR               inBuf; // pointer to Input and output buffer 

    irpSp = IoGetCurrentIrpStackLocation( Irp );
    inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	inBuf = Irp->AssociatedIrp.SystemBuffer;
	

    switch ( irpSp->Parameters.DeviceIoControl.IoControlCode )
    {
    case IOCTL_SetProcessHashRule: 
			DbgPrintEx( DPFLTR_IHVVIDEO_ID,  DPFLTR_ERROR_LEVEL,"IOCTL_SetProcessHashRule\r\n");
			if(!SetProcessHashRule(inBuf,inBufLength))
				  ntStatus = STATUS_INVALID_PARAMETER;
			break;
	case IOCTL_NetworkMonitor_ENABLE: 
				DbgPrintEx( DPFLTR_IHVVIDEO_ID,  DPFLTR_ERROR_LEVEL,"IOCTL_NetworkMonitor_ENABLE\r\n");
				EnableNetworkMonitor();
			break;
	case IOCTL_NetworkMonitor_DISABLE: 
				DbgPrintEx( DPFLTR_IHVVIDEO_ID,  DPFLTR_ERROR_LEVEL,"IOCTL_NetworkMonitor_DISABLE\r\n");
				DisableNetworkMonitor();	
			break;
			
    default:
        ntStatus = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = ntStatus;
    IoCompleteRequest( Irp, IO_NO_INCREMENT );
    return ntStatus;
}
 

