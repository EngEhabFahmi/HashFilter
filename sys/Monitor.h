#pragma once

NTSTATUS NetworkMonitorInitialize(PDEVICE_OBJECT deviceObject);
VOID NetworkMonitorUninitialize();
VOID  InitLogFile();
void CloseLogFilehandle();