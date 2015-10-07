#include"monitor.h"

NetHashProtection::NetHashProtection() { DeviceHandle=NULL; GlobalengineHandle =NULL;AddCallouts(); Handle=NULL;Connect(); }
NetHashProtection::~NetHashProtection() { RemoveCallouts();  }


int NetHashProtection::Connect()
{
	Handle = CreateFileW(MONITOR_DOS_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, NULL, NULL);
	if (Handle != INVALID_HANDLE_VALUE)
	{
		IsConnected=TRUE;  return ERROR_SUCCESS ;
	}
	else  Handle=NULL;
	return GetLastError();
}

BOOL NetHashProtection::EnableNetworkMonitor()
{
	DWORD retsize;
    if(!IsConnected)
		return false;	
	if(DeviceIoControl(Handle,IOCTL_NetworkMonitor_ENABLE,NULL,NULL,NULL,NULL,&retsize,NULL))
		return true;
	else return false;
}

BOOL NetHashProtection::DisableNetworkMonitor()
{
	DWORD retsize;
	    if(!IsConnected)
		return false;
	if(DeviceIoControl(Handle,IOCTL_NetworkMonitor_DISABLE,NULL,NULL,NULL,NULL,&retsize,NULL))
		return true;
	else return false;
}


BOOL NetHashProtection::SetProcessHashRule(PVOID buffer,DWORD size)
{
	DWORD retsize;
    if(!IsConnected)
		return false;
	
	if(DeviceIoControl(Handle,IOCTL_SetProcessHashRule,buffer,size,NULL,NULL,&retsize,NULL))
		return true;
	else return false;
}

DWORD NetHashProtection::AddCallouts()
{
   FWPM_CALLOUT callout;
   DWORD result;
   FWPM_DISPLAY_DATA displayData;
   HANDLE engineHandle = NULL;
   FWPM_SESSION session;
   RtlZeroMemory(&session, sizeof(FWPM_SESSION));

   session.displayData.name = L"Monitor Non-Dynamic Session";
   session.displayData.description = L"For Adding callouts";

   printf("Opening Filtering Engine\n");
   result =  FwpmEngineOpen(
                            NULL,
                            RPC_C_AUTHN_WINNT,
                            NULL,
                            &session,
                            &engineHandle
                            );

   if (NO_ERROR != result)
   {
      goto cleanup;
   }

   printf("Starting Transaction for adding callouts\n");
   result = FwpmTransactionBegin(engineHandle, 0);
   if (NO_ERROR != result)
   {
      goto abort;
   }

   printf("Successfully started the Transaction\n");

   RtlZeroMemory(&callout, sizeof(FWPM_CALLOUT));
   displayData.description = MONITOR_FLOW_ESTABLISHED_CALLOUT_DESCRIPTION;
   displayData.name = MONITOR_FLOW_ESTABLISHED_CALLOUT_NAME;

   callout.calloutKey = HASH_MONITOR_FLOW_ESTABLISHED_CALLOUT_V4;
   callout.displayData = displayData;
   callout.applicableLayer = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
   callout.flags = FWPM_CALLOUT_FLAG_PERSISTENT; // Make this a persistent callout.

   printf("Adding Persistent Flow Established callout through the Filtering Engine\n");

   result = FwpmCalloutAdd(engineHandle, &callout, NULL, NULL);
   if (NO_ERROR != result)
   {
      goto abort;
   }

   printf("Successfully Added Persistent Flow Established callout.\n");
   
   printf("Committing Transaction\n");
   result = FwpmTransactionCommit(engineHandle);
   if (NO_ERROR == result)
   {
      printf("Successfully Committed Transaction.\n");
   }
   goto cleanup;

abort:
   printf("Aborting Transaction\n");
   result = FwpmTransactionAbort(engineHandle);
   if (NO_ERROR == result)
   {
      printf("Successfully Aborted Transaction.\n");
   }

cleanup:

   if (engineHandle)
   {
      FwpmEngineClose(engineHandle);
   }
   return result;
}

DWORD NetHashProtection::RemoveCallouts()
{
   DWORD result;
   HANDLE engineHandle = NULL;
   FWPM_SESSION session;

   RtlZeroMemory(&session, sizeof(FWPM_SESSION));

   session.displayData.name = L" Monitor Non-Dynamic Session";
   session.displayData.description = L"For Adding callouts";

   printf("Opening Filtering Engine\n");
   result =  FwpmEngineOpen(
                            NULL,
                            RPC_C_AUTHN_WINNT,
                            NULL,
                            &session,
                            &engineHandle
                            );

   if (NO_ERROR != result)
   {
      goto cleanup;
   }

   printf("Starting Transaction for Removing callouts\n");

   result = FwpmTransactionBegin(engineHandle, 0);
   if (NO_ERROR != result)
   {
      goto abort;
   }
   printf("Successfully started the Transaction\n");

   printf("Deleting Flow Established callout\n");
   result = FwpmCalloutDeleteByKey(engineHandle,
                                    &HASH_MONITOR_FLOW_ESTABLISHED_CALLOUT_V4);
   if (NO_ERROR != result)
   {
      goto abort;
   }

   printf("Successfully Deleted Flow Established callout\n");

   printf("Deleting Stream callout\n");

   printf("Committing Transaction\n");
   result = FwpmTransactionCommit(engineHandle);
   if (NO_ERROR == result)
   {
      printf("Successfully Committed Transaction.\n");
   }
   goto cleanup;
   
abort:
   printf("Aborting Transaction\n");
   result = FwpmTransactionAbort(engineHandle);
   if (NO_ERROR == result)
   {
      printf("Successfully Aborted Transaction.\n");
   }

 cleanup:

    if (engineHandle)
    {
       FwpmEngineClose(engineHandle);
    }

   return result;
}

DWORD NetHashProtection::MonitorAppAddFilters(IN    HANDLE  engineHandle)
{
   DWORD result = NO_ERROR;
   FWPM_SUBLAYER monitorSubLayer;
   FWPM_FILTER filter;
   FWPM_FILTER_CONDITION filterConditions[3]; // We only need two for this call tcp / udp -- maybe  icmp tunel can bypass this :) --

   RtlZeroMemory(&monitorSubLayer, sizeof(FWPM_SUBLAYER)); 

   monitorSubLayer.subLayerKey = HASH_MONITOR_SUBLAYER;
   monitorSubLayer.displayData.name = L"HASH Monitor Sub layer";
   monitorSubLayer.displayData.description = L"HASH Monitor Sub layer";
   monitorSubLayer.flags = 0;
   // We don't really mind what the order of invocation is.
   monitorSubLayer.weight = 0;
   
   printf("Starting Transaction\n");

   result = FwpmTransactionBegin(engineHandle, 0);
   if (NO_ERROR != result)
   {
      goto abort;
   }
   printf("Successfully Started Transaction\n");

   printf("Adding Sublayer\n");

   result = FwpmSubLayerAdd(engineHandle, &monitorSubLayer, NULL);
   if (NO_ERROR != result)
   {
      goto abort;
   }
   
   printf("Sucessfully added Sublayer\n");
   
   RtlZeroMemory(&filter, sizeof(FWPM_FILTER));

   filter.layerKey = FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
   filter.displayData.name = L"Flow established filter.";
   filter.displayData.description = L"Sets up flow for traffic that we are interested in.";
   filter.action.type = FWP_ACTION_CALLOUT_TERMINATING; // We're only doing inspection.
   filter.action.calloutKey = HASH_MONITOR_FLOW_ESTABLISHED_CALLOUT_V4;
   filter.filterCondition = filterConditions;
   filter.subLayerKey = monitorSubLayer.subLayerKey;
   filter.weight.type = FWP_EMPTY; // auto-weight.
      
   filter.numFilterConditions = 3;

   RtlZeroMemory(filterConditions, sizeof(filterConditions));


   filterConditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
   filterConditions[0].matchType = FWP_MATCH_EQUAL;
   filterConditions[0].conditionValue.type = FWP_UINT8;
   filterConditions[0].conditionValue.uint8 = IPPROTO_UDP;

   filterConditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
   filterConditions[1].matchType = FWP_MATCH_EQUAL;
   filterConditions[1].conditionValue.type = FWP_UINT8;
   filterConditions[1].conditionValue.uint8 = IPPROTO_TCP;
   
   filterConditions[2].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
   filterConditions[2].matchType = FWP_MATCH_EQUAL;
   filterConditions[2].conditionValue.type = FWP_UINT8;
   filterConditions[2].conditionValue.uint8 = IPPROTO_ICMP;
   printf("Adding Flow Established Filter\n");

   result = FwpmFilterAdd(engineHandle,
                       &filter,
                       NULL,
                       NULL);

   if (NO_ERROR != result)
   {
      goto abort;
   }

   printf("Successfully added Flow Established filter\n");

   printf("Committing Transaction\n");
   result = FwpmTransactionCommit(engineHandle);
   if (NO_ERROR == result)
   {
      printf("Successfully Committed Transaction\n");
   }
   goto cleanup;

abort:
   printf("Aborting Transaction\n");
   result = FwpmTransactionAbort(engineHandle);
   if (NO_ERROR == result)
   {
      printf("Successfully Aborted Transaction\n");
   }

cleanup:
   
   return result;
}



DWORD  NetHashProtection::MonitorAppDoMonitoring()
{
   HANDLE            monitorDevice = NULL;

   DWORD             result;
   FWPM_SESSION     session;

   RtlZeroMemory(&session, sizeof(FWPM_SESSION));

   session.displayData.name = L"HASH File Monitor Session";
   session.displayData.description = L"Monitor HASH File Messenger Activity";

   // Let the Base Filtering Engine cleanup after us.
   session.flags = FWPM_SESSION_FLAG_DYNAMIC;

   printf("Opening Filtering Engine\n");
   result =  FwpmEngineOpen(
                            NULL,
                            RPC_C_AUTHN_WINNT,
                            NULL,
                            &session,
                            &GlobalengineHandle
                            );

   if (NO_ERROR != result)
   {
      goto cleanup;
	  GlobalengineHandle=NULL;
   }

   printf("Successfully opened Filtering Engine\n");

   printf("Adding Filters through the Filtering Engine\n");

   result = MonitorAppAddFilters(GlobalengineHandle);

   if (NO_ERROR != result)
   {
      goto cleanup;
   }

   printf("Successfully added Filters through the Filtering Engine\n");
   
cleanup:

   if (NO_ERROR != result)
   {
      printf("Monitor.\tError 0x%x occurred during execution\n", result);
   }
   
   return result;
}


DWORD  NetHashProtection::MonitorAppEndMonitoring()
{
	 DWORD             result;
	  if (GlobalengineHandle)
     {
        result =  FwpmEngineClose(GlobalengineHandle);
		if (NO_ERROR != result)
		{
			printf("MonitorAppEndMonitoring error %x\n", result);
		}
        GlobalengineHandle = NULL;
     }
	 return result;
}





void  __cdecl main()
{

	NetHashProtection NetHash;
	NetHash.MonitorAppDoMonitoring();

	
	
	 printf("end any key to end \r\n");
	 
	 int hash[5];
	 
	          
	 hash[0]=0x4122CF81;
	 hash[1]= 0x6AAA01E6; 
	 hash[2]= 0x3CFB76CD ;
	 hash[3]= 0x151F2851 ;
	 hash[4]= 0xBC055481;

	
	NetHash.SetProcessHashRule(hash,sizeof(hash));
	_getch();
	//NetHash.DisEnable();
	NetHash.MonitorAppEndMonitoring();
}
