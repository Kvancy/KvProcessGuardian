#pragma once
#include<ntifs.h>
#include<ntimage.h>
#define kPrint(X,...) DbgPrintEx(77,0,X,__VA_ARGS__)
extern "C" UCHAR * PsGetProcessImageFileName(PEPROCESS EProcess);
struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;                                             //0x0
			ULONGLONG Waiting : 1;                                            //0x0
			ULONGLONG Waking : 1;                                             //0x0
			ULONGLONG MultipleShared : 1;                                     //0x0
			ULONGLONG Shared : 60;                                            //0x0
		};
		ULONGLONG Value;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
};
typedef struct _HANDLE_TABLE_ENTRY_INFO {
	ACCESS_MASK AuditMask;
} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;
typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks; //驱动双向链表
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
	PVOID DllBase; //驱动基址
	PVOID EntryPoint; //驱动入口点
	ULONG SizeOfImage; //驱动大小
	UNICODE_STRING FullDllName; //完整驱动路径
	UNICODE_STRING BaseDllName; // 驱动名称
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
struct _HANDLE_TABLE_FREE_LIST
{
	struct _EX_PUSH_LOCK FreeListLock;                                      //0x0
	union _HANDLE_TABLE_ENTRY* FirstFreeHandleEntry;                        //0x8
	union _HANDLE_TABLE_ENTRY* LastFreeHandleEntry;                         //0x10
	LONG HandleCount;                                                       //0x18
	ULONG HighWaterMark;                                                    //0x1c
};
typedef struct _HANDLE_TABLE
{
	ULONG NextHandleNeedingPool;                                            //0x0
	LONG ExtraInfoPages;                                                    //0x4
	volatile ULONGLONG TableCode;                                           //0x8
	struct _EPROCESS* QuotaProcess;                                         //0x10
	struct _LIST_ENTRY HandleTableList;                                     //0x18
	ULONG UniqueProcessId;                                                  //0x28
	union
	{
		ULONG Flags;                                                        //0x2c
		struct
		{
			UCHAR StrictFIFO : 1;                                             //0x2c
			UCHAR EnableHandleExceptions : 1;                                 //0x2c
			UCHAR Rundown : 1;                                                //0x2c
			UCHAR Duplicated : 1;                                             //0x2c
			UCHAR RaiseUMExceptionOnInvalidHandleClose : 1;                   //0x2c
		};
	};
	struct _EX_PUSH_LOCK HandleContentionEvent;                             //0x30
	struct _EX_PUSH_LOCK HandleTableLock;                                   //0x38
	union
	{
		struct _HANDLE_TABLE_FREE_LIST FreeLists[1];                        //0x40
		struct
		{
			UCHAR ActualEntry[32];                                          //0x40
			struct _HANDLE_TRACE_DEBUG_INFO* DebugInfo;                     //0x60
		};
	};
}HANDLE_TABLE, * PHANDLE_TABLE;
struct _EXHANDLE
{
	union
	{
		struct
		{
			ULONG TagBits : 2;                                                //0x0
			ULONG Index : 30;                                                 //0x0
		};
		VOID* GenericHandleOverlay;                                         //0x0
		ULONGLONG Value;                                                    //0x0
	};
};
union _HANDLE_TABLE_ENTRY
{
	volatile LONGLONG VolatileLowValue;                                     //0x0
	LONGLONG LowValue;                                                      //0x0
	struct
	{
		struct _HANDLE_TABLE_ENTRY_INFO* volatile InfoTable;                //0x0
		LONGLONG HighValue;                                                     //0x8
		union _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;                         //0x8
		struct _EXHANDLE LeafHandleValue;                                   //0x8
	};
	LONGLONG RefCountField;                                                 //0x0
	ULONGLONG Unlocked : 1;                                                   //0x0
	ULONGLONG RefCnt : 16;                                                    //0x0
	ULONGLONG Attributes : 3;                                                 //0x0
	struct
	{
		ULONGLONG ObjectPointerBits : 44;                                     //0x0
		ULONG GrantedAccessBits : 25;                                             //0x8
		ULONG NoRightsUpgrade : 1;                                                //0x8
		ULONG Spare1 : 6;                                                     //0x8
	};
	ULONG Spare2;                                                           //0xc
};
typedef union _HANDLE_TABLE_ENTRY* PHANDLE_TABLE_ENTRY;
typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(
#if !defined(_WIN7_)
	IN PHANDLE_TABLE HandleTable,
#endif
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
	);
extern "C" NTKERNELAPI BOOLEAN NTAPI ExEnumHandleTable(__in PHANDLE_TABLE HandleTable, __in EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure, __in PVOID EnumParameter, __out_opt PHANDLE Handle
);
extern "C" UCHAR * PsGetProcessImageFileName(PEPROCESS EProcess);
extern "C" NTKERNELAPI POBJECT_TYPE NTAPI ObGetObjectType(_In_ PVOID Object);
extern "C" NTKERNELAPI VOID FASTCALL ExfUnblockPushLock(__inout PULONG_PTR PushLock, __inout_opt PVOID  WaitBlock);
extern "C" POBJECT_TYPE * PsProcessType;

#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  

ULONG32 GetPidOffset()
{
	UNICODE_STRING func;
	RtlInitUnicodeString(&func, L"PsGetProcessId");
	PUCHAR _PsGetProcessId = (PUCHAR)MmGetSystemRoutineAddress(&func);
	for (size_t i = 0; i < 100; i++)
	{
		if (_PsGetProcessId[i] == 0x48 && _PsGetProcessId[i + 1] == 0x8B && _PsGetProcessId[i + 2] == 0x81)
		{
			int* offset = reinterpret_cast<int*>(_PsGetProcessId + i + 3);
			return *offset;
		}
	}
	return 0;

}

NTSTATUS ProtectProcessByChangePid(const int Pid,int** pid_ptr)
{
	PEPROCESS pe;
	NTSTATUS st = PsLookupProcessByProcessId((HANDLE)Pid, &pe);

	if (pe)
	{
		*pid_ptr = reinterpret_cast<int*>(((PCHAR)pe + GetPidOffset()));
		kPrint("pid_ptr:0x%x\r\n",*pid_ptr);
		**pid_ptr = -1;//隐藏pid到-1
		return st;
	}
	else
	{
		return STATUS_NOT_FOUND;
	}
}

NTSTATUS UnProtectProcessByChangePid(const int Pid)
{
	PEPROCESS pe;
	NTSTATUS st = PsLookupProcessByProcessId((HANDLE)-1, &pe);

	if (pe)
	{
		auto pid_ptr = reinterpret_cast<int*>(((PCHAR)pe + GetPidOffset()));
		*pid_ptr = Pid;//隐藏pid到-1
		return st;
	}
	else
	{
		return STATUS_NOT_FOUND;
	}
}

VOID OB_POST_OPERATION_CALLBACK(
	_In_ PVOID RegistrationContext,
	_In_ POB_POST_OPERATION_INFORMATION OperationInformation
)
{

}

OB_PREOP_CALLBACK_STATUS OB_PRE_OPERATION_CALLBACK(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	PEPROCESS CurProcess = IoGetCurrentProcess();
	PEPROCESS TargetProcess = (PEPROCESS)OperationInformation->Object;
	PUCHAR curName = PsGetProcessImageFileName(CurProcess);
	PUCHAR tarName = PsGetProcessImageFileName(TargetProcess); 
	ULONG64 TargetPid = (ULONG64)PsGetProcessId(TargetProcess);
	ULONG64 protectProcPid = (ULONG64)RegistrationContext;
	kPrint("protectProcPid:%d protectProcPid:%d\r\n", TargetPid, protectProcPid);
	if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
	{
		if (strstr((PCHAR)curName, "cheatengine") != NULL && protectProcPid == TargetPid)
		{
			kPrint("open:curName:%s,tarName:%s,protectProcPid:%p\r\n", curName, tarName, protectProcPid);
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;//
			OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0;
		}
	}
	else
	{
		if (strstr((PCHAR)curName, "cheatengine") != NULL && protectProcPid == TargetPid)
		{
			kPrint("dump:curName:%s,tarName:%s,protectProcPid:%p\r\n", curName, tarName, protectProcPid);
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
			OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0;
		}
	}
	return OB_PREOP_SUCCESS;
}

//创建句柄回调
NTSTATUS KvObRegisterCallbacks(PVOID* RegistrationHandle, POB_POST_OPERATION_CALLBACK postCallback, POB_PRE_OPERATION_CALLBACK preCallback, PVOID RegistrationContext = NULL, PWCH Altitude = L"12345")
{
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	OB_CALLBACK_REGISTRATION obCallbackRegisteration;
	RtlInitUnicodeString(&obCallbackRegisteration.Altitude, Altitude);
	obCallbackRegisteration.Version = ObGetFilterVersion();
	OB_OPERATION_REGISTRATION obCallInfo = { 0 };
	obCallInfo.ObjectType = PsProcessType;
	obCallInfo.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	obCallInfo.PostOperation = postCallback;
	obCallInfo.PreOperation = preCallback;
	obCallbackRegisteration.OperationRegistrationCount = 1;
	obCallbackRegisteration.RegistrationContext = RegistrationContext;
	obCallbackRegisteration.OperationRegistration = &obCallInfo;
	st = ObRegisterCallbacks(&obCallbackRegisteration, RegistrationHandle);
	return st;
}

PEPROCESS FindProcessByName(const PWCH pName)
{
	PEPROCESS pe = NULL;
	PEPROCESS retProcess = NULL;
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	for (size_t i = 12; i < 0x100000; i += 4)//跳过系统进程，要不然比较的时候会蓝屏
	{
		st = PsLookupProcessByProcessId((HANDLE)i, &pe);
		if (!NT_SUCCESS(st)) continue;
		if (PsGetProcessExitStatus(pe) != STATUS_PENDING)//进程处于退出状态
		{
			ObDereferenceObject(pe);
			continue;
		}
		PUNICODE_STRING uName = NULL;
		st = SeLocateProcessImageName(pe, &uName);
		if (!NT_SUCCESS(st))
		{
			ObDereferenceObject(pe);
			continue;
		}
		PWCH baseName = wcsrchr(uName->Buffer, L'\\');
		if (baseName)
		{
			baseName += 1;
			if (!_wcsicmp(baseName, pName))
			{
				retProcess = pe;
			}
		}
		ExFreePool(uName);
		if (retProcess) break;
	}
	return retProcess;

}
//句柄枚举
BOOLEAN Local_FEX_ENUMERATE_HANDLE_ROUTINE(
	__in PHANDLE_TABLE HandleTable,
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
)
{
	//先通过HandleTableEntry获取对象头objectHeader->对象类型筛选->提权/降权
	if (MmIsAddressValid(HandleTableEntry))
	{
		PVOID objectHeader = (PVOID)(*(PLONG64)HandleTableEntry >> 0x10);//解密object地址 WIN10 22H2解密方式，有符号的右移16位
		PVOID object = (PUCHAR)objectHeader + 0x30;
		if (MmIsAddressValid(object)/* && MmIsAddressValid(objectHeader)*/)
		{
			if (ObGetObjectType(object) == *PsProcessType)
			{
				ULONG64 pid = *(ULONG64*)((PCHAR)object + 0x440);
				if (pid == (ULONG64)EnumParameter)
				{
					HandleTableEntry->GrantedAccessBits &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE);
					kPrint("OK protected %s\r\n", EnumParameter);
				}
			}
		}
	}
	// Release implicit locks
	_InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
	if (HandleTable != NULL && HandleTable->HandleContentionEvent.Locked)
		ExfUnblockPushLock((PULONG_PTR)&HandleTable->HandleContentionEvent, NULL);

	return FALSE;
}