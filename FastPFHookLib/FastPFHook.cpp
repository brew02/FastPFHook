﻿#include <Windows.h>
#include <stdio.h>
#include <intrin.h>

#include <Zydis/Zydis.h>

#include "..\Includes\FastPFHook.h"
#include "hook.h"
#include "translate.h"

// Add credits to MinHook author and SMAP Btbd

void* gExceptionHandlerHandle = nullptr;

// More TODOs: Add multi-threading support (locks), read comment about unconditional branches below (somewhere)
// Make the mutexes shareable for better reader performance (some of them)

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
		exceptionRecord->NumberParameters != 0 &&
		exceptionRecord->ExceptionInformation[0] == EXCEPTION_INFORMATION_EXECUTION)
	{
		uint8_t* newPages = hook->FindThreadNewPages();
		if (!newPages)
		{
			hook->InsertCurrentThread();
			newPages = hook->FindThreadNewPages();
		}

		if ((rip >= hook->OriginalPageInstructions() && rip < hook->OriginalPageEnd()))
		{
			contextRecord->Rip = reinterpret_cast<UINT64>(hook->OriginalToNew(rip, true));
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else
		{
			if (rip >= newPages && rip < (newPages + hook->mNewPagesSize))
			{
				// Might want to actually acquire the lock here (maybe in
				// other places as well)
				// This won't really be necessary if we just suspend threads
				// when parsing and translating (make that change)
				while (hook->PeakWriteLock())
				{
					Sleep(10);
				}

				rip = hook->mNewPages + (rip - newPages);
				hook->SetThreadNewPages(hook->mNewPages);
				contextRecord->Rip = reinterpret_cast<UINT64>(rip);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
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
		// Perform additional analysis on rip and the branch to deal with certain obfuscation
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

bool InstallHook(void* address)
{
	if (!gExceptionHandlerHandle)
		if (!InitializePFH())
			return false;

	PFHook* hook = FindHook(address);
	if (!hook)
	{
		void* newPages = VirtualAlloc(nullptr, INITIAL_HOOK_SIZE, 
			MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!newPages)
		{
			UninitializePFH();
			return false;
		}

		hook = new PFHook(newPages, address);
		InsertHook(hook);
	}
	else
	{
		// Add multiple possible hook addresses or maybe just a reference count
	}

	// Maybe add a check here (not sure if all 'false' returns are actually bad right now)
	ParseAndTranslateSafe(hook, address, false);

	return true;
}

void RemoveHook(void* address)
{
	UNREFERENCED_PARAMETER(address);
	// Finish this later
}