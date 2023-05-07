#include "memory_utils.h"

#define SystemModuleInformation 0x0B
__kernel_entry NTSTATUS ZwQuerySystemInformation(IN ULONG SystemInformationClass, OUT VOID* SystemInformation, IN ULONG SystemInformationLength, OUT ULONG* ReturnLength);

typedef LDR_DATA_TABLE_ENTRY* (*MiLookupDataTableEntry_fn)(IN VOID* Address, IN BOOLEAN);
MiLookupDataTableEntry_fn MiLookupDataTableEntry;

QWORD g_callback_address = 0;

void PcreateProcessNotifyRoutine(
	HANDLE ParentId,
	HANDLE ProcessId,
	BOOLEAN Create)
{
	UNREFERENCED_PARAMETER(Create);
	DbgPrint("[+] [callback] CreateProcessNotifyRoutine ParentId: %d\n", ParentId);
	DbgPrint("[+] [callback] CreateProcessNotifyRoutine ProcessId: %d\n", ProcessId);
}

VOID* get_module_list()
{
	// We call the function once to get a rough estimate of the size of the structure, then we add a few kb
	ULONG length = 0;
	ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &length);
	length += (10 * 1024);

	VOID* module_list = ExAllocatePool(PagedPool | POOL_COLD_ALLOCATION, length);
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, module_list, length, &length);

	if (status)
	{
		DbgPrint("[-] Failed ZwQuerySystemInformation with 0x%lX\n", status);
		if (module_list) ExFreePool(module_list);
		return 0;
	}

	if (!module_list)
	{
		DbgPrint("[-] Module list is empty\n");
		return 0;
	}

	return module_list;
}

BOOLEAN apply_codecaves()
{
	VOID* module_list = get_module_list();
	if (!module_list) return FALSE;
	RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)module_list;

	/*
		We need to find 1 16 byte codecaves, preferably in the same module:
		g_callback_address will be the detour to the PsSetCreateProcessNotifyRoutine callback
	*/
	for (ULONG i = 1; i < modules->NumberOfModules; ++i)
	{
		RTL_PROCESS_MODULE_INFORMATION* module = &modules->Modules[i];

		CHAR driver_name[0x0100] = { 0 };
		to_lower(module->FullPathName, driver_name);
		if (!strstr(driver_name, ".sys") || is_pg_protected(driver_name)) continue;

		g_callback_address = find_codecave(module->ImageBase, 16, 0);
		if (!g_callback_address) continue;

		LDR_DATA_TABLE_ENTRY* ldr = MiLookupDataTableEntry((VOID*)g_callback_address, FALSE);
		if (!ldr)
		{
			g_callback_address = 0;
			continue;
		}

		// Setting the 0x20 data table entry flag makes MmVerifyCallbackFunction pass
		ldr->Flags |= 0x20;
		DbgPrint("[+] Found g_callback_address code cave in module %s\n", driver_name + module->OffsetToFileName);

		break;
	}

	ExFreePool(module_list);

	/*
		Instead of just stopping we could loosen our restrictions and search for 2 code caves in separate modules
		But in practice, 16 byte code caves are quite common, so this shouldn't really happen
	*/
	if (!g_callback_address)
	{
		DbgPrint("[-] Failed to find all required code caves in any driver module!\n");
		return FALSE;
	}

	if (!patch_codecave_detour(g_callback_address, (QWORD)&PcreateProcessNotifyRoutine))
	{
		DbgPrint("[-] Failed patching in create_process_callback redirection code cave!\n");
		return FALSE;
	}

	PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)g_callback_address, FALSE);

	DbgPrint("[+] Patched g_callback_address code cave succesfully\n");

	return TRUE;
}

// Custom entry point, don't create a driver object here because that would just add another detection vector
NTSTATUS DriverEntry(_In_ DRIVER_OBJECT* driver_object, _In_ UNICODE_STRING* registry_path)
{
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(registry_path);

	VOID* module_list = get_module_list();
	if (!module_list) return STATUS_UNSUCCESSFUL;
	RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)module_list;

	// First module is always ntoskrnl.exe
	RTL_PROCESS_MODULE_INFORMATION* module = &modules->Modules[0];

	QWORD address = find_pattern_nt("48 8B C4 48 89 58 08 48 89 70 18 57 48 83 EC 20 33 F6", (QWORD)module->ImageBase, module->ImageSize);
	if (!address)
	{
		DbgPrint("[-] Could not find MiLookupDataTableEntry\n");
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrint("[+] Found MiLookupDataTableEntry at 0x%p\n", (VOID*)address);
	MiLookupDataTableEntry = (MiLookupDataTableEntry_fn)address;

	ExFreePool(module_list);
	if (!apply_codecaves()) DbgPrint("[-] Failed applying code caves\n");

	return STATUS_UNSUCCESSFUL;
}