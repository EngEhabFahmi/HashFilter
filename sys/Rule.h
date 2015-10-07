#include"sha1.h"	
#include<ntifs.h>
#include <fwpmk.h>

#pragma warning(push)
#pragma warning(disable:4201)       // unnamed struct/union

#include <fwpsk.h>

#pragma warning(pop)
//#include<ntifs.h>
//#include <ioctl.h>

#include "Monitor.h"

#include<Ntstrsafe.h>
#define INITGUID
#include <guiddef.h>
#include "mntrguid.h"
VOID ProcessCallback(IN HANDLE  hParentId, IN HANDLE  hProcessId, IN BOOLEAN bCreate);


BOOLEAN CheckRuleIsBlock(UINT64 pid,SHA1Context*  ProcessHash);
void InitRuleSpinLock();
void InitializePidHashMapListHead();
BOOLEAN SetProcessHashRule(void* Buffer , int  size);
void EnableNetworkMonitor();
void DisableNetworkMonitor();