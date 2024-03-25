#include <Windows.h>

#include "..\Includes\FastPFHook.h"

int main()
{
	InstallHook(&MessageBoxA);

	DWORD oldProtect = 0;
	VirtualProtect(&MessageBoxA, 1, PAGE_READWRITE, &oldProtect);

	MessageBoxA(nullptr, "Testing", nullptr, MB_ICONWARNING);

	VirtualProtect(&MessageBoxA, 1, PAGE_EXECUTE_READWRITE, &oldProtect);

	return 0;
}