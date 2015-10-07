#include"rule.h"

//#include<ntifs.h>



typedef struct 
{
	DWORD PID;
    DWORD HASH[5];
	LIST_ENTRY ListEntry;
} PID_HASH_ENTRY, *PPID_HASH_ENTRY;

LIST_ENTRY PidHashMapListHead;


int ProcessRuleHashSize;
int* ProcessHashRule=NULL;




void GetProcessFileHashWithPID(DWORD pid,SHA1Context * Exesha1 );
BOOLEAN  GetFileHash(SHA1Context* exesha1,PUNICODE_STRING currentprocesspath);
NTSTATUS GetProcessImageName(HANDLE processId, PUNICODE_STRING ProcessImageName);
PVOID GetProcessPath(int hProcessId,PUNICODE_STRING processImagePath);

void PushPidHashEntry(DWORD hProcessId,SHA1Context* ProcessHash);
VOID FindRemovePidHashEntry(DWORD pid,SHA1Context*  ProcessHash, BOOLEAN remove);


typedef NTSTATUS (*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );
	
QUERY_INFO_PROCESS ZwQueryInformationProcess;

void UpdateHashPidList(DWORD hProcessId,SHA1Context* ProcessFileHash, BOOLEAN AddRule );

VOID ProcessCallback(IN HANDLE  hParentId, IN HANDLE  hProcessId, IN BOOLEAN bCreate)
{
	SHA1Context ProcessFileHash={0};
	
	if(bCreate)
	{
		GetProcessFileHashWithPID((DWORD)hProcessId,&ProcessFileHash);
		UpdateHashPidList((DWORD)hProcessId,&ProcessFileHash,TRUE);
	}
	else  
	{
		UpdateHashPidList((DWORD)hProcessId,&ProcessFileHash,FALSE);
	}

}

KSPIN_LOCK RuleSpinLock;
void InitRuleSpinLock()
{
	KeInitializeSpinLock(&RuleSpinLock);
}

void InitializePidHashMapListHead()
{
	InitializeListHead(&PidHashMapListHead);
}

void UpdateHashPidList(DWORD hProcessId,SHA1Context* PrrocessFileHash, BOOLEAN AddRule)
{
	 if(AddRule)
	 {
		 // fill
		 PushPidHashEntry(hProcessId,PrrocessFileHash);
	 }
	 else 
	 {
		 FindRemovePidHashEntry(hProcessId,PrrocessFileHash,!AddRule); // AddRule is false 
	 }
}


void PushPidHashEntry(DWORD hProcessId,SHA1Context* ProcessHash)
{
	int i=0;
	KIRQL   oldIrql;
	PID_HASH_ENTRY  *PidHashEntry;
	PidHashEntry=(PPID_HASH_ENTRY)ExAllocatePoolWithTag(NonPagedPool, sizeof(PID_HASH_ENTRY), 'g');
	PidHashEntry->PID=hProcessId;
	for (i=0;i<5;i++)
		PidHashEntry->HASH[i]=ProcessHash->Message_Digest[i];
	
	 KeAcquireSpinLock(&RuleSpinLock, &oldIrql);
		InsertTailList(&PidHashMapListHead, &(PidHashEntry->ListEntry));
	 KeReleaseSpinLock(&RuleSpinLock, oldIrql);
}

VOID FindRemovePidHashEntry(DWORD pid,SHA1Context*  ProcessHash, BOOLEAN remove)
{
	PLIST_ENTRY         thisEntry, nextEntry;
	KIRQL   oldIrql;
	PID_HASH_ENTRY* PidHashEntry;
	int i=0;
	
	 KeAcquireSpinLock(&RuleSpinLock, &oldIrql);
	for (thisEntry = PidHashMapListHead.Flink;
         thisEntry != &PidHashMapListHead;
         thisEntry = nextEntry)
    {
        nextEntry = thisEntry->Flink;
        PidHashEntry = CONTAINING_RECORD(thisEntry, PID_HASH_ENTRY, ListEntry);
		if(PidHashEntry->PID==pid)
		{
			if(remove)
			{
				RemoveEntryList(thisEntry);
				ExFreePoolWithTag(PidHashEntry, 't');
				break;
			}
			else 
			{
				for (i=0;i<5;i++)
					ProcessHash->Message_Digest[i]=PidHashEntry->HASH[i];
				break;
			}	
		}
	}
	
	KeReleaseSpinLock(&RuleSpinLock, oldIrql);
}


BOOLEAN SetProcessHashRule(void* Buffer , int  size)
{
	int* temp;
	KIRQL               oldIrql;
	if(((size%sizeof(int))%5)!=0)return FALSE ; //every hash has 5 int  so  number  of int in  size must be dividable  to 5 
	
	temp=(int*)ExAllocatePoolWithTag(NonPagedPool, size, 'sha1');
	
	 KeAcquireSpinLock(&RuleSpinLock, &oldIrql);
		if(ProcessHashRule)ExFreePoolWithTag(ProcessHashRule,'sha1');
		RtlCopyMemory(temp,Buffer,size);
		ProcessHashRule=temp;
		ProcessRuleHashSize=size;
	 KeReleaseSpinLock(&RuleSpinLock, oldIrql);
	 return TRUE;
}

//prevent memory leak after driver unload :)
void FreeProcessHash()
{
	if(ProcessHashRule)ExFreePoolWithTag(ProcessHashRule,'sha1');
}


void FreePidHashMapListHead()
{
	// free PidHashMapListHead  list ? 
}



BOOLEAN NetworkMonitorIsDisable = FALSE;
void EnableNetworkMonitor()
{
	NetworkMonitorIsDisable=FALSE;
	
}

void DisableNetworkMonitor()
{
		NetworkMonitorIsDisable=TRUE;
}



BOOLEAN CheckRuleIsBlock(UINT64 pid,SHA1Context*  ProcessHash)
{
	int i=0;
	KIRQL    oldIrql;
	BOOLEAN retval=FALSE;
	int NumberOfHash;
	
	
	///////
	///////
	//////////////
	///////
	///////
	
	return FALSE;
	
	///////
	//////////////
	///////
	///////
	
	if(NetworkMonitorIsDisable)
		return FALSE;

	
	
	FindRemovePidHashEntry((DWORD)pid,ProcessHash,FALSE);
		
	KeAcquireSpinLock(&RuleSpinLock, &oldIrql);
	
	if(!ProcessHashRule)
	{
		KeReleaseSpinLock(&RuleSpinLock, oldIrql);
		return FALSE;  // no rule :)
	}
   	
	NumberOfHash=ProcessRuleHashSize/sizeof(int)/5;
		for(i=0;i<NumberOfHash;i++)
		{
			if(ProcessHash->Message_Digest[0]==ProcessHashRule[i]&& 
			   ProcessHash->Message_Digest[1]==ProcessHashRule[i+1]&&
			   ProcessHash->Message_Digest[2]==ProcessHashRule[i+2]&&
			   ProcessHash->Message_Digest[3]==ProcessHashRule[i+3]&&
			   ProcessHash->Message_Digest[4]==ProcessHashRule[i+4]
			   )
			   retval=TRUE;
		}
	 
	 KeReleaseSpinLock(&RuleSpinLock, oldIrql);
	return retval;	
}
	
void GetProcessFileHashWithPID(DWORD pid,SHA1Context * Exesha1 )
{
  
	UNICODE_STRING currentprocesspath;
	
	NTSTATUS ntstatus;
	
	currentprocesspath.Buffer=NULL;	
	currentprocesspath.Length=0;
	currentprocesspath.MaximumLength =0;
	
	GetProcessPath((ULONG)pid,&currentprocesspath);
    if(!GetFileHash(Exesha1,&currentprocesspath))
	{
		if(currentprocesspath.Buffer!=NULL)ExFreePoolWithTag(currentprocesspath.Buffer,'p'); 
		return ; 
	}
	
	if(currentprocesspath.Buffer!=NULL)ExFreePoolWithTag(currentprocesspath.Buffer,'p');
}
 
  
BOOLEAN  GetFileHash(SHA1Context* exesha1,PUNICODE_STRING currentprocesspath)
{

	UNICODE_STRING     uniName;
    OBJECT_ATTRIBUTES  objAttr;
    NTSTATUS ntstatus;
    LARGE_INTEGER offset;
    IO_STATUS_BLOCK    ioStatusBlock;
	HANDLE Filehandle;
	char* pFileBuffer;
    InitializeObjectAttributes(&objAttr, currentprocesspath,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL, NULL);
	SHA1Reset(exesha1);
	ntstatus = ZwCreateFile(&Filehandle,
                            FILE_READ_DATA,
                            &objAttr, &ioStatusBlock,
                            NULL,
                            FILE_ATTRIBUTE_NORMAL,
                            FILE_SHARE_READ|FILE_SHARE_DELETE|FILE_SHARE_WRITE,
                            FILE_OPEN, 
                            FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL, 0);
    if(NT_SUCCESS(ntstatus))
	{
		offset.QuadPart = 0;
		pFileBuffer =(char*)ExAllocatePoolWithTag(NonPagedPool, 4096, 'sha1');
		do
		{
			ntstatus=ZwReadFile(Filehandle, NULL, NULL, NULL, &ioStatusBlock,pFileBuffer, 4096, &offset, NULL);
				if(NT_SUCCESS(ntstatus))
				{
						SHA1Input(exesha1,(const unsigned char *)pFileBuffer,(int)ioStatusBlock.Information);
						offset.QuadPart +=ioStatusBlock.Information;
						if(ioStatusBlock.Information==0)break;
				}

		}while(NT_SUCCESS(ntstatus));
		ZwClose(Filehandle);
		if(pFileBuffer!=NULL)ExFreePoolWithTag(pFileBuffer,'NA');
		if (SHA1Result(exesha1))
		{
			return TRUE;
		}
	
	}
	return FALSE;
}


NTSTATUS GetProcessImageName(HANDLE processId, PUNICODE_STRING ProcessImageName)
{
    NTSTATUS status;
    ULONG returnedLength;
    ULONG bufferLength;
	HANDLE hProcess;
    PVOID buffer;
	PEPROCESS eProcess;
    PUNICODE_STRING imageName;
   
    PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process
	
	status = PsLookupProcessByProcessId(processId, &eProcess);

	if(NT_SUCCESS(status))
	{
		status = ObOpenObjectByPointer(eProcess,0, NULL, 0,0,KernelMode,&hProcess);
		if(NT_SUCCESS(status))
		{
		} else {
			DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
		}
		ObDereferenceObject(eProcess);
	} else {
		DbgPrint("PsLookupProcessByProcessId Failed: %08x\n", status);
	}
	

    if (NULL == ZwQueryInformationProcess) {

        UNICODE_STRING routineName;

        RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");

        ZwQueryInformationProcess =
               (QUERY_INFO_PROCESS) MmGetSystemRoutineAddress(&routineName);

        if (NULL == ZwQueryInformationProcess) {
            DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
        }
    }
    
	/* Query the actual size of the process path */
    status = ZwQueryInformationProcess( hProcess,
                                        ProcessImageFileName,
                                        NULL, // buffer
                                        0, // buffer size
                                        &returnedLength);

    if (STATUS_INFO_LENGTH_MISMATCH != status) {
        return status;
    }

    /* Check there is enough space to store the actual process
	   path when it is found. If not return an error with the
	   required size */
    bufferLength = returnedLength - sizeof(UNICODE_STRING);
    if (ProcessImageName->MaximumLength < bufferLength)
	{
        ProcessImageName->MaximumLength = (USHORT) bufferLength;
        return STATUS_BUFFER_OVERFLOW;   
    }

    /* Allocate a temporary buffer to store the path name */
    buffer = ExAllocatePoolWithTag(NonPagedPool, returnedLength, 'g');

    if (NULL == buffer) 
	{
        return STATUS_INSUFFICIENT_RESOURCES;   
    }

    /* Retrieve the process path from the handle to the process */
    status = ZwQueryInformationProcess( hProcess,
                                        ProcessImageFileName,
                                        buffer,
                                        returnedLength,
                                        &returnedLength);

    if (NT_SUCCESS(status)) 
	{
        /* Copy the path name */
        imageName = (PUNICODE_STRING) buffer;
        RtlCopyUnicodeString(ProcessImageName, imageName);
    }

    /* Free the temp buffer which stored the path */
    ExFreePoolWithTag(buffer, 'p');

    return status;
}
 PVOID GetProcessPath(int hProcessId,PUNICODE_STRING processImagePath)
{
	NTSTATUS status;
	processImagePath->Length = 0;
	processImagePath->MaximumLength = 0;
	processImagePath->Buffer=NULL;
	status = GetProcessImageName((HANDLE)hProcessId, processImagePath);
	if(status == STATUS_BUFFER_OVERFLOW)
	{
		processImagePath->Buffer = ExAllocatePoolWithTag(NonPagedPool, processImagePath->MaximumLength, 'p');
		if(processImagePath->Buffer != NULL)
			status = GetProcessImageName((HANDLE)hProcessId, processImagePath);
	}
    return 0;
}