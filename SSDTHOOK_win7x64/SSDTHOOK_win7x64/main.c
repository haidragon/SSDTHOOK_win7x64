#include <hookssdt.h>


//驱动卸载函数
VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	UnhookSSDT();
	DbgPrint("Driver Unload\n");
}

//驱动入口函数
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pPath)
{
	DbgPrint("Hello World\n");
	//获取KeServiceDescriptorTable
	KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTable64();
	//开启Hook
	HookSSDT();
	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}