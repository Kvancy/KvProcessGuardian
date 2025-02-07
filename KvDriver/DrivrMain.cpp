#pragma once
#include<ntifs.h>
#include"Process.h"
#define IOCTL_ChangePid CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UnChangePid CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HandleCallBack CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UnHandleCallBack CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HandleDepower CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UnHandleDepower CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define SYMBOLICLINKNAME L"\\??\\KvDriver"
typedef struct _ioIn
{
	int pid;
}ioIn, * pioIn;

UNICODE_STRING DeviceName;
UNICODE_STRING SymbolicliName;
int* pid_ptr = nullptr;
PVOID RegistrationHandle = NULL;

// ����һ��ȫ�ֱ�־���������ڿ����̵߳�ֹͣ
volatile LONG g_StopThread = 0;
// �̺߳���
NTSTATUS NTAPI ThreadFunction(PVOID StartContext)
{
	PEPROCESS keProc = NULL;
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	LARGE_INTEGER li = { 0 };
	li.QuadPart = -10000000; // 1���100���뵥λ

	/*kPrint("Thread start...\r\n");
	kPrint("Context:%lld\r\n", (ULONG64)StartContext);*/

	while (InterlockedCompareExchange(&g_StopThread, 0, 0) == 0)
	{
		// ���ҽ���
		keProc = FindProcessByName(L"cheatengine-x86_64-SSE4-AVX2.exe");
		if (keProc)
		{
			//kPrint("FindProcess cheatengine\r\n");
			st = STATUS_SUCCESS;
			// ��ȡ�����
			PHANDLE_TABLE pHandleTable = *(PHANDLE_TABLE*)((PCHAR)keProc + 0x570); // ObjectTable offset;
			ExEnumHandleTable(pHandleTable, Local_FEX_ENUMERATE_HANDLE_ROUTINE, StartContext, NULL);
		}

		//kPrint("going!!!\r\n");

		// �ȴ�һ��ʱ���ټ��
		KeDelayExecutionThread(KernelMode, FALSE, &li);
	}

	//kPrint("Thread stopping...\r\n");
	return st;
}

NTSTATUS CreateThreadForOperation(PVOID Context)
{
	HANDLE hThread = NULL;
	NTSTATUS status;

	// ����ϵͳ�߳�
	status = PsCreateSystemThread(
		&hThread,                  // �߳̾��
		THREAD_ALL_ACCESS,         // �߳�Ȩ��
		NULL,                      // ��ȫ����
		NULL,                      // ���̾����NULL ��ʾ��ǰ���̣�
		NULL,                      // �߳� ID
		(PKSTART_ROUTINE)ThreadFunction,            // �̺߳���
		Context                    // �߳�������
	);

	if (!NT_SUCCESS(status))
	{
		kPrint("Failed to create thread: %x\n", status);
		return status;
	}

	// �ȴ��߳���ɣ���ѡ��
	ZwClose(hThread);

	return status;

}
NTSTATUS driverDispatch(
	_In_ struct _DEVICE_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp
)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS st = STATUS_SUCCESS;
	if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL)
	{
		switch (stack->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_ChangePid:
		{
			pioIn input = (pioIn)Irp->AssociatedIrp.SystemBuffer;
			st = ProtectProcessByChangePid(input->pid,&pid_ptr);
			if (NT_SUCCESS(st))
			{
				kPrint("pid %d -> %d\r\n", input->pid, -1);
			}
		}
		break;
		case IOCTL_UnChangePid:
		{
			pioIn input = (pioIn)Irp->AssociatedIrp.SystemBuffer;
			st = STATUS_UNSUCCESSFUL;
			if (pid_ptr)
			{
				kPrint("pid_ptr:0x%x\r\n", pid_ptr);
				*pid_ptr = input->pid;
				st = STATUS_SUCCESS;
				kPrint("pid %d -> %d\r\n", -1, input->pid);
			}
		}
		break;
		case IOCTL_HandleCallBack:
		{
			kPrint("IOCTL_HandleCallBack\r\n");
			pioIn input = (pioIn)Irp->AssociatedIrp.SystemBuffer;
			kPrint("input->pid:%p\r\n", &input->pid);
			st = KvObRegisterCallbacks(&RegistrationHandle, OB_POST_OPERATION_CALLBACK, OB_PRE_OPERATION_CALLBACK,(PVOID)input->pid);	
		}
		break;
		case IOCTL_UnHandleCallBack:
		{
			kPrint("IOCTL_UnHandleCallBack\r\n");
			if (RegistrationHandle) ObUnRegisterCallbacks(RegistrationHandle);
		}
		break;
		case IOCTL_HandleDepower:
		{
			kPrint("IOCTL_HandleDepower\r\n");
			InterlockedExchange(&g_StopThread, 0);
			pioIn input = (pioIn)Irp->AssociatedIrp.SystemBuffer;
			NTSTATUS status = CreateThreadForOperation((PVOID)input->pid);
		}
		break;
		case IOCTL_UnHandleDepower:
		{
			kPrint("IOCTL_UnHandleDepower\r\n");
			InterlockedExchange(&g_StopThread, 1);
		}
		break;
		default:
			st = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}
	}

	IoCompleteRequest(Irp, 0);
	return st;
}

NTSTATUS KvRegisterIoControl(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING DeviceName, PUNICODE_STRING SymbolicLinkName, PDRIVER_DISPATCH DisPatch)
{
	NTSTATUS st = STATUS_SUCCESS;

	PDEVICE_OBJECT pDeviceObject = NULL;
	st = IoCreateDevice(DriverObject, 0, DeviceName, FILE_DEVICE_UNKNOWN, 0, 0, &pDeviceObject);
	if (!NT_SUCCESS(st))
	{
		kPrint("[kv]:IoCreateDevice failed STATUS = 0x%x\r\n", st);
		return STATUS_UNSUCCESSFUL;
	}
	st = IoCreateSymbolicLink(SymbolicLinkName, DeviceName);
	if (!NT_SUCCESS(st))
	{
		kPrint("[kv]:IoCreateSymbolicLink failed  STATUS = 0x%x\r\n", st);
		IoDeleteDevice(pDeviceObject);
		return STATUS_UNSUCCESSFUL;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DisPatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DisPatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DisPatch;
	return st;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	if (RegistrationHandle) ObUnRegisterCallbacks(RegistrationHandle);

	if (DriverObject->DeviceObject)
	{
		IoDeleteSymbolicLink(&SymbolicliName);
		IoDeleteDevice(DriverObject->DeviceObject);
	}
}

extern "C" NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	RtlInitUnicodeString(&DeviceName, L"\\Device\\KvDriver");
	RtlInitUnicodeString(&SymbolicliName, L"\\??\\KvDriver"); // symbolicLinkName:ȫ�ֵ�UNICODE_STRING����
	pid_ptr = (int*)ExAllocatePool(NonPagedPool, sizeof(int*));
	memset(pid_ptr, 0, sizeof(pid_ptr));
	NTSTATUS st = KvRegisterIoControl(DriverObject, &DeviceName, &SymbolicliName, driverDispatch);//driverDispatch��
	kPrint("LoadDriver Success\r\n");
	//ע��ص�
	PKLDR_DATA_TABLE_ENTRY Section = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	Section->Flags |= 0x20;// ע��ص�������Ҫ������ǩ�����
	
	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}