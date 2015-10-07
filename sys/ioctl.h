

#pragma once

#define MONITOR_DEVICE_NAME     L"\\Device\\NetworkMonitor"
#define MONITOR_SYMBOLIC_NAME   L"\\DosDevices\\Global\\NetworkMonitor"
#define MONITOR_DOS_NAME   L"\\\\.\\NetworkMonitor"

#define IOCTL_SetProcessHashRule  			 CTL_CODE( FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define IOCTL_NetworkMonitor_ENABLE 			 CTL_CODE( FILE_DEVICE_UNKNOWN, 0x904, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define IOCTL_NetworkMonitor_DISABLE  CTL_CODE( FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS  )


