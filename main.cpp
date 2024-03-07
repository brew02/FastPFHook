#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

#include <Zydis/Zydis.h>

#include "Internal/hook.h"
#include "Internal/translate.h"

// Add credits to MinHook author and SMAP Btbd

void* gExceptionHandlerHandle = nullptr;
LIST_ENTRY gHookList{ nullptr, nullptr };

// More TODOs: Add multi-threading support (locks), split code into different files, 
// read comment about unconditional branches below (somewhere)
// Use classes for the Disassembler struct and the HookData struct

// Address: An address within the original page or the new pages
PFHook* FindHook(void* address)
{
	for (LIST_ENTRY* entry = gHookList.Flink; entry != &gHookList; entry = entry->Flink)
	{
		PFHook* hook = CONTAINING_RECORD(entry, PFHook, listEntry);
		if ((address >= hook->OriginalPage() && address < hook->OriginalPageEnd()) ||
			address >= hook->mNewPages && address < hook->NewPagesEnd())
		{
			return hook;
		}
	}

	return nullptr;
}

// Create separate functions for access violations, breakpoints, and single-steps
long __stdcall ExceptionHandler(EXCEPTION_POINTERS* exceptionInfo)
{
	EXCEPTION_RECORD* exceptionRecord = exceptionInfo->ExceptionRecord;
	CONTEXT* contextRecord = exceptionInfo->ContextRecord;
	UINT8* rip = reinterpret_cast<UINT8*>(contextRecord->Rip);
	PFHook* hook = FindHook(rip);

	if (!hook)
		return EXCEPTION_CONTINUE_SEARCH;

	if (exceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
		(rip >= hook->OriginalPageInstructions() && rip < hook->OriginalPageEnd()))
	{
		if (exceptionRecord->NumberParameters == 0 || 
			exceptionRecord->ExceptionInformation[0] != EXCEPTION_INFORMATION_EXECUTION)
		{
			return EXCEPTION_CONTINUE_SEARCH;
		}

		contextRecord->Rip = reinterpret_cast<UINT64>(hook->OriginalToNew(rip, true));
		hook->IncrementThreadCount();

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// We may need to make some changes to the conditions that we check for the top and bottom
	// instruction on the new page.

	// We may want to be more clear as to why we are saving the originalRIP and how we use it
	// 
	// There are some bugs here or with the branch handling that
	// deviat from intended behavior, but the program still works.
	// If we translate a relative instruction to an absolute one, we don't need to 
	// single step it or use breakpoints
	else if (exceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT &&
		(rip >= hook->mNewPages && rip < hook->NewPagesInstructionsEnd()))
	{
		UINT8* originalRIP = hook->NewToOriginal(rip);
		// Perform additional analysis on rip and the branch to work
		ParseAndTranslateSafe(hook, originalRIP, true);
		contextRecord->EFlags |= TRAP_FLAG;
		contextRecord->Rip = reinterpret_cast<UINT64>(hook->OriginalToNew(originalRIP, true));

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else if (exceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) 
	{
		UINT8* originalRIP = hook->NewToOriginal(rip);

		if (rip >= hook->mNewPages && rip < hook->NewPagesInstructionsEnd())
		{
			ParseAndTranslateSafe(hook, hook->NewToOriginal(rip), false);
		}
		
		contextRecord->EFlags &= ~(TRAP_FLAG);
		contextRecord->Rip = reinterpret_cast<UINT64>(hook->OriginalToNew(originalRIP, true));

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

bool InitializePFH()
{
	gExceptionHandlerHandle = AddVectoredExceptionHandler(true, ExceptionHandler);
	if (!gExceptionHandlerHandle)
		return false;

	return true;
}

void UninitializePFH()
{
	RemoveVectoredExceptionHandler(gExceptionHandlerHandle);
}

PFHook* InstallHook(void* address)
{
	if (!gExceptionHandlerHandle)
	{
		if (!InitializePFH())
			return nullptr;

		InitializeListHead(&gHookList);
	}

	PFHook* hook = FindHook(address);
	if (!hook)
	{
		void* newPage = VirtualAlloc(nullptr, INITIAL_HOOK_SIZE,
			MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!newPage)
			return nullptr;

		memset(newPage, 0xCC, INITIAL_HOOK_SIZE);

		hook = new PFHook(newPage, address, INITIAL_HOOK_SIZE);
		InsertListHead(&gHookList, &hook->listEntry);
	}

	// Maybe add a check here (not sure if all 'false' returns are actually bad right now)
	ParseAndTranslateSafe(hook, address, false);

	return hook;
}

void RemoveHook(void* address)
{
	UNREFERENCED_PARAMETER(address);
	// Finish this later
}

int main()
{
	InstallHook(&MessageBoxA);

	DWORD oldProtect = 0;
	VirtualProtect(&MessageBoxA, 1, PAGE_READWRITE, &oldProtect);

	MessageBoxA(nullptr, "Test", nullptr, MB_ICONWARNING);

	VirtualProtect(&MessageBoxA, 1, oldProtect, &oldProtect);

	//UINT8* messageBoxA = tempPFHook->OriginalToNew(&MessageBoxA);
	//((decltype(MessageBoxA)*)(messageBoxA))(nullptr, "Test", nullptr, MB_ICONWARNING);

	UninitializePFH();

	PFHook* hook = FindHook(&MessageBoxA);
	printf("Thread Count: %llu\n", hook->mThreadCount);

	return 0;
}