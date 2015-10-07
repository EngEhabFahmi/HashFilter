#include "windows.h"
#include "winioctl.h"
#include "strsafe.h"

#ifndef _CTYPE_DISABLE_MACROS
#define _CTYPE_DISABLE_MACROS
#endif

#include "fwpmu.h"

#include "winsock2.h"
#include "ws2def.h"

#include <conio.h>
#include <stdio.h>


#define INITGUID
#include <guiddef.h>


#define MONITOR_FLOW_ESTABLISHED_CALLOUT_DESCRIPTION L"Process File Hash Monitor Flow Established Callout"
#define MONITOR_FLOW_ESTABLISHED_CALLOUT_NAME L"Flow Established Callout"


#pragma once

// b3241f1d-7cd2-4e7a-8721-2e97d07702e5
DEFINE_GUID(
    HASH_MONITOR_SUBLAYER,
    0xb3241f1d,
    0x7cd2,
    0x4e7a,
    0x87, 0x21, 0x2e, 0x97, 0xd0, 0x77, 0x02, 0xe5
);

// 3aaccbc0-2c29-455f-bb91-0e801c8994a4
DEFINE_GUID(
    HASH_MONITOR_FLOW_ESTABLISHED_CALLOUT_V4,
    0x3aaccbc0,
    0x2c29,
    0x455f,
    0xbb, 0x91, 0x0e, 0x80, 0x1c, 0x89, 0x94, 0xa4
);


#define MONITOR_DOS_NAME   L"\\\\.\\NetworkMonitor"

#define IOCTL_SetProcessHashRule  			 CTL_CODE( FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define IOCTL_NetworkMonitor_ENABLE 			 CTL_CODE( FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define IOCTL_NetworkMonitor_DISABLE  CTL_CODE( FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS  )


class NetHashProtection
{
	public:
		NetHashProtection();
		~NetHashProtection();
		DWORD   NetHashProtection::MonitorAppDoMonitoring();
		DWORD  NetHashProtection::MonitorAppEndMonitoring();
		BOOL NetHashProtection::DisableNetworkMonitor();
		BOOL NetHashProtection::EnableNetworkMonitor();
		BOOL NetHashProtection::SetProcessHashRule(PVOID buffer,DWORD size);
	private:
		HANDLE* DeviceHandle;
		HANDLE  GlobalengineHandle;
		DWORD   NetHashProtection::AddCallouts();
		DWORD   NetHashProtection::RemoveCallouts();
		DWORD   NetHashProtection::MonitorAppAddFilters(IN    HANDLE  engineHandle);	
		BOOL IsConnected;
		HANDLE Handle;
		
		int NetHashProtection::Connect();
		
};






