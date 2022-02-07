#include <Windows.h>
#include <iostream>

typedef void(__stdcall* TrueSleep)(DWORD);

TrueSleep oSleep;

void __stdcall MySleep(DWORD dwMilliseconds)
{
	printf("HOOKED SLEEP!!!\n");
	printf("Sleep for: %d milliseconds\n", dwMilliseconds);
	
	oSleep(dwMilliseconds);
}

bool HookIAT(const char* module_name, const char* func_name, void* new_func, void** old_func)
{
	DWORD module_base = (DWORD)GetModuleHandleA(NULL);
	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_base;
	IMAGE_NT_HEADERS32* pe_header = (IMAGE_NT_HEADERS32*)(module_base + dos_header->e_lfanew);

	if (pe_header->Signature != IMAGE_NT_SIGNATURE)
		return false;

	// grab the pointer to the import data directory
	IMAGE_IMPORT_DESCRIPTOR* import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)(module_base + pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
	for (DWORD i = 0; import_descriptor[i].Characteristics != 0; ++i)
	{
		char* dll_name = (char*)(module_base + import_descriptor[i].Name);

		if (_strcmpi(dll_name, module_name) != 0)
			continue;

		if (!import_descriptor[i].FirstThunk || !import_descriptor[i].OriginalFirstThunk)
			return false;

		IMAGE_THUNK_DATA32* thunk = (IMAGE_THUNK_DATA32*)(module_base + import_descriptor[i].FirstThunk);
		IMAGE_THUNK_DATA32* orig_thunk = (IMAGE_THUNK_DATA32*)(module_base + import_descriptor[i].OriginalFirstThunk);

		for (; orig_thunk->u1.Function != 0; ++thunk, ++orig_thunk)
		{
			if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
				continue;

			IMAGE_IMPORT_BY_NAME* _import = (IMAGE_IMPORT_BY_NAME*)(module_base + orig_thunk->u1.AddressOfData);

			if (_strcmpi(func_name, (char*)_import->Name) != 0)
				continue;

			DWORD junk;
			MEMORY_BASIC_INFORMATION mbi;
			
			VirtualQuery(thunk, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
			if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect))
				return false;

			*old_func = (void*)thunk->u1.Function;
			thunk->u1.Function = (DWORD)new_func;

			if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &junk))
				return true;
		}
	}
	return false;
}

int main()
{
	if (!HookIAT("kernel32.dll", "Sleep", &MySleep, (void**)&oSleep))
		printf("[-] hooking failed, error = %d\n", GetLastError());
	else
	{
		printf("[+] old_addr = 0x%p, new_addr = 0x%p\n", oSleep, &MySleep);
		Sleep(1000);
	}
}