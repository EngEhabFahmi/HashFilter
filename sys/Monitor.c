#include "Rule.h"
#include"sha1.h"
#include<Ntstrsafe.h>

//
// Software Tracing Definitions
//
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(MsnMntrMonitor,(dd65554d, 9925, 49d1, 83b6, 46125feb4207),  \
        WPP_DEFINE_BIT(TRACE_FLOW_ESTABLISHED)      \
        WPP_DEFINE_BIT(TRACE_STATE_CHANGE)      \
        WPP_DEFINE_BIT(TRACE_LAYER_NOTIFY) )

#include "Monitor.tmh"


UINT32 flowEstablishedId = 0;

VOID LogWorkRoutine(PVOID Parameter);
typedef struct _OSR_WORK_ITEM {
 
    WORK_QUEUE_ITEM    WorkItem;
    PVOID              Param1;
 
} OSR_WORK_ITEM, * POSR_WORK_ITEM;

#define TAG_NAME_CALLOUT 'CnoM'

#if(NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS MonitorCoFlowEstablishedCalloutV4(
   IN const FWPS_INCOMING_VALUES* inFixedValues,
   IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   IN VOID* packet,
   IN const void* classifyContext,
   IN const FWPS_FILTER* filter,
   IN UINT64 flowContext,
   OUT FWPS_CLASSIFY_OUT* classifyOut);
#else if(NTDDI_VERSION < NTDDI_WIN7)
NTSTATUS MonitorCoFlowEstablishedCalloutV4(
   IN const FWPS_INCOMING_VALUES* inFixedValues,
   IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   IN VOID* packet,
   IN const FWPS_FILTER* filter,
   IN UINT64 flowContext,
   OUT FWPS_CLASSIFY_OUT* classifyOut);
#endif


NTSTATUS MonitorCoFlowEstablishedNotifyV4(
    IN  FWPS_CALLOUT_NOTIFY_TYPE        notifyType,
    IN  const GUID*             filterKey,
    IN  const FWPS_FILTER*     filter)
{
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);

    return STATUS_SUCCESS;
}


NTSTATUS NetworkMonitorInitialize(PDEVICE_OBJECT deviceObject)
{	 
	FWPS_CALLOUT sCallout;
    NTSTATUS status = STATUS_SUCCESS;

    memset(&sCallout, 0, sizeof(FWPS_CALLOUT));

    sCallout.calloutKey = MSN_MONITOR_FLOW_ESTABLISHED_CALLOUT_V4;
    sCallout.flags = 0;
    sCallout.classifyFn = MonitorCoFlowEstablishedCalloutV4;
    sCallout.notifyFn = MonitorCoFlowEstablishedNotifyV4;
    sCallout.flowDeleteFn = NULL;

    status = FwpsCalloutRegister(deviceObject, &sCallout, &flowEstablishedId);

   return status;
}


void NetworkMonitorUninitialize()
{
  
  FwpsCalloutUnregisterByKey(&MSN_MONITOR_FLOW_ESTABLISHED_CALLOUT_V4);

}


#if(NTDDI_VERSION >= NTDDI_WIN7)
NTSTATUS MonitorCoFlowEstablishedCalloutV4(
   IN const FWPS_INCOMING_VALUES* inFixedValues,
   IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   IN VOID* packet,
   IN const void* classifyContext,
   IN const FWPS_FILTER* filter,
   IN UINT64 flowContext,
   OUT FWPS_CLASSIFY_OUT* classifyOut)

#else if(NTDDI_VERSION < NTDDI_WIN7)
NTSTATUS MonitorCoFlowEstablishedCalloutV4(
   IN const FWPS_INCOMING_VALUES* inFixedValues,
   IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   IN VOID* packet,
   IN const FWPS_FILTER* filter,
   IN UINT64 flowContext,
   OUT FWPS_CLASSIFY_OUT* classifyOut)
#endif

{

   NTSTATUS status = STATUS_SUCCESS;
   UINT64   flowHandle;
   UINT64   flowContextLocal;
   UINT64  processId64;
   SHA1Context  ProcessHash;
   UNREFERENCED_PARAMETER(packet);
   #if(NTDDI_VERSION >= NTDDI_WIN7)
   UNREFERENCED_PARAMETER(classifyContext);
   #endif
   UNREFERENCED_PARAMETER(filter);
   UNREFERENCED_PARAMETER(flowContext);
   
   
// icmp is pid 4 and  pid 4 is allow default
  
   if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues,FWPS_METADATA_FIELD_PROCESS_ID))
	{
		 processId64 = inMetaValues->processId;
	
			//DbgPrintEx( DPFLTR_IHVVIDEO_ID,  DPFLTR_ERROR_LEVEL,"pid ESTABLISHED %d\r\n",processId64);
	} 
	else
	{
		//DbgPrintEx( DPFLTR_IHVVIDEO_ID,  DPFLTR_ERROR_LEVEL,"error Established\r\n");
	}
	
	if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_PATH))
   {
		//DbgPrintEx( DPFLTR_IHVVIDEO_ID,  DPFLTR_ERROR_LEVEL,"pid ESTABLISHED %ws\r\n",inMetaValues->processPath->data); 
   }
   
   if (!CheckRuleIsBlock(processId64,&ProcessHash))
   {
		WCHAR*  processPath=NULL;
		char*     buffer;
		int  size;
		NTSTATUS ntstatus;
	    UINT32         index;
		ULONG       remoteAddressV4;
		USHORT      remotePort;
		USHORT      ipProto;
		
		size=inMetaValues->processPath->size;
		processPath=(WCHAR*)ExAllocatePoolWithTag(NonPagedPool,size+sizeof(WCHAR),'t');
		RtlZeroMemory(processPath,size+sizeof(WCHAR));
		memcpy(processPath,inMetaValues->processPath->data,inMetaValues->processPath->size);
		
	    classifyOut->actionType =FWP_ACTION_BLOCK;
		
		
		buffer=(char*)ExAllocatePoolWithTag(NonPagedPool ,size+100,'NA'); //calc exact size
		RtlZeroMemory(buffer,size+100);
		
		index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS;
		remoteAddressV4 = inFixedValues->incomingValue[index].value.uint32;

		index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT;
		remotePort = inFixedValues->incomingValue[index].value.uint16;

		index = FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL;
		ipProto = inFixedValues->incomingValue[index].value.uint16;
   
   
		ntstatus = RtlStringCbPrintfA(buffer,inMetaValues->processPath->size+100,"Block Process:%ws remoteAddressV4:%x remotePort:%x ipProto:%x hash:%08X %08X %08X %08X %08X\r\n",
						processPath,
						remoteAddressV4,
						remotePort,
						ipProto,
						ProcessHash.Message_Digest[0],
						ProcessHash.Message_Digest[1],
						ProcessHash.Message_Digest[2],
						ProcessHash.Message_Digest[3],
						ProcessHash.Message_Digest[4]);
		
		if(processPath)ExFreePool(processPath);
		
		if(NT_SUCCESS(ntstatus)) 
		{ 
			  POSR_WORK_ITEM OsrWorkItem;
			  OsrWorkItem = ExAllocatePool(NonPagedPool, sizeof(OSR_WORK_ITEM));
		 
			  OsrWorkItem->Param1 = (PVOID)buffer;
			  ExInitializeWorkItem(&OsrWorkItem->WorkItem,LogWorkRoutine,OsrWorkItem);
			  ExQueueWorkItem(&OsrWorkItem->WorkItem,DelayedWorkQueue);
		}
		return status;
   }
	
   DbgPrintEx( DPFLTR_IHVVIDEO_ID,  DPFLTR_ERROR_LEVEL,"pid %d Allow ESTABLISHED  path %ws \r\n",(int)processId64,inMetaValues->processPath->data); 
   classifyOut->actionType = FWP_ACTION_PERMIT;

   return status;
}


HANDLE   LogFilehandle;
VOID LogWorkRoutine(PVOID Parameter)
{
	IO_STATUS_BLOCK    ioStatusBlock;
    POSR_WORK_ITEM OsrWorkItem = (POSR_WORK_ITEM)Parameter;
	
	if(LogFilehandle!=NULL)
		ZwWriteFile(LogFilehandle, NULL, NULL, NULL, &ioStatusBlock, OsrWorkItem->Param1, strlen(OsrWorkItem->Param1), NULL, NULL);
     
	DbgPrintEx( DPFLTR_IHVVIDEO_ID,DPFLTR_ERROR_LEVEL,"%s\r\n",(WCHAR*)OsrWorkItem->Param1); 
	if(OsrWorkItem->Param1!=NULL) ExFreePool(OsrWorkItem->Param1);
    ExFreePool(OsrWorkItem);
   
}

BOOLEAN fileisOpen=FALSE;
void  InitLogFile()
{

	UNICODE_STRING     uniName;
    OBJECT_ATTRIBUTES  objAttr;
    NTSTATUS ntstatus;
    IO_STATUS_BLOCK    ioStatusBlock;
	
	if(fileisOpen==TRUE)return ;
    RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\log.txt");  // or L"\\SystemRoot\\example.txt"
    InitializeObjectAttributes(&objAttr, &uniName,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL, NULL);
	
	ntstatus = ZwCreateFile(&LogFilehandle,
                            FILE_APPEND_DATA,
                            &objAttr, &ioStatusBlock,
                            NULL,
                            FILE_ATTRIBUTE_NORMAL,
                            FILE_SHARE_READ|FILE_SHARE_WRITE,
                            FILE_OPEN_IF, 
                            FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL, 0);
    if(!NT_SUCCESS(ntstatus))
	{
       LogFilehandle=NULL;
    }
	else  fileisOpen=TRUE;
}


void CloseLogFilehandle()
{
	ZwClose(LogFilehandle);
}