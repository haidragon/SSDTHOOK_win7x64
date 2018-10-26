#include <ntddk.h>

typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

typedef struct _SERVICE_DESCRIPTOR_TABLE {
	SYSTEM_SERVICE_TABLE ntoskrnl;  // ntoskrnl.exe (native api)
	SYSTEM_SERVICE_TABLE win32k;    // win32k.sys   (gdi/user)
	SYSTEM_SERVICE_TABLE Table3;    // not used
	SYSTEM_SERVICE_TABLE Table4;    // not used
}SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

//NtTerminateProcess
typedef NTSTATUS(__fastcall *NTTERMINATEPROCESS)(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus);

NTKERNELAPI UCHAR * PsGetProcessImageFileName(PEPROCESS Process);

//SSDT表基址
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;
NTTERMINATEPROCESS NtTerminateProcess = NULL;
ULONG OldTpVal;

//自己的NtTerminateProcess
NTSTATUS __fastcall Fuck_NtTerminateProcess(IN HANDLE ProcessHandle, IN NTSTATUS ExitStatus)
{
	PEPROCESS Process;
	NTSTATUS st = ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, KernelMode, &Process, NULL);
	DbgPrint("Fake_NtTerminateProcess called!");
	if (NT_SUCCESS(st))
	{
		if (!_stricmp(PsGetProcessImageFileName(Process), "calc.exe"))
			return STATUS_ACCESS_DENIED;
		else
			return NtTerminateProcess(ProcessHandle, ExitStatus);
	}
	else
		return STATUS_ACCESS_DENIED;
}
//关闭写保护
KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}
//开启写保护
void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

ULONGLONG GetKeServiceDescriptorTable64() //我的方法
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress;i < EndSearchAddress;i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15) //4c8d15
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return addr;
			}
		}
	}
	return 0;
}

//获取SSDT中的函数地址
ULONGLONG GetSSDTFuncCurAddr(ULONG id)
{
	LONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = ServiceTableBase[id];
	dwtmp = dwtmp >> 4;
	return (LONGLONG)dwtmp + (ULONGLONG)ServiceTableBase;
}

ULONG GetOffsetAddress(ULONGLONG FuncAddr)
{
	ULONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = (ULONG)(FuncAddr - (ULONGLONG)ServiceTableBase);
	return dwtmp << 4;
}

//InlineHook_KeBugCheckEx
VOID FuckKeBugCheckEx()
{
	KIRQL irql;
	ULONGLONG myfun;
	UCHAR jmp_code[] = "\x48\xB8\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xE0";
	myfun = (ULONGLONG)Fuck_NtTerminateProcess;//替换成自己的函数地址
	memcpy(jmp_code + 2, &myfun, 8);
	irql = WPOFFx64();
	memset(KeBugCheckEx, 0x90, 15);
	memcpy(KeBugCheckEx, jmp_code, 12);
	WPONx64(irql);
}

VOID HookSSDT()
{
	KIRQL irql;
	ULONGLONG dwtmp = 0;
	PULONG ServiceTableBase = NULL;
	//get old address
	NtTerminateProcess = (NTTERMINATEPROCESS)GetSSDTFuncCurAddr(41);
	DbgPrint("Old_NtTerminateProcess: %llx", (ULONGLONG)NtTerminateProcess);
	//set kebugcheckex
	FuckKeBugCheckEx();
	//show new address
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	OldTpVal = ServiceTableBase[41];	//record old offset value
	irql = WPOFFx64();
	ServiceTableBase[41] = GetOffsetAddress((ULONGLONG)KeBugCheckEx);
	WPONx64(irql);
	DbgPrint("KeBugCheckEx: %llx", (ULONGLONG)KeBugCheckEx);
	DbgPrint("New_NtTerminateProcess: %llx", GetSSDTFuncCurAddr(41));
}

VOID UnhookSSDT()
{
	KIRQL irql;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	//set value
	irql = WPOFFx64();
	ServiceTableBase[41] = GetOffsetAddress((ULONGLONG)NtTerminateProcess);	//OldTpVal;	//直接填写这个旧值也行
	WPONx64(irql);
	//没必要恢复KeBugCheckEx的内容了，反正执行到KeBugCheckEx时已经完蛋了。
	DbgPrint("NtTerminateProcess: %llx", GetSSDTFuncCurAddr(41));
}