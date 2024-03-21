#include "hook.h"

void PFHook::InsertTranslation(const PFHook::Translation& translation)
{
	mTranslationMutex.lock();
	mTranslations.push_back(translation);
	mTranslationMutex.unlock();
}

uint32_t PFHook::FindTranslationOffset(uint8_t* originalAddress)
{
	uint32_t offset = static_cast<uint32_t>(
		originalAddress - OriginalPageInstructions());

	mTranslationMutex.lock();

	for (Translation& translation : mTranslations)
	{
		if (translation.originalAddress == originalAddress)
		{
			offset = translation.newOffset;
			break;
		}
	}

	mTranslationMutex.unlock();
	return offset;
}

bool PFHook::Relocate(const void* buffer, size_t length)
{
	if ((mRelocCursor + length) >= NewPagesEnd())
	{
		// extend
		mNewPagesSize += PAGE_SIZE;

		UINT8* oldNewPages = mNewPages;

		mNewPages = reinterpret_cast<UINT8*>(VirtualAlloc(nullptr,
			mNewPagesSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));

		if (!mNewPages)
			return false;

		memset(mNewPages, 0xCC, mNewPagesSize);
		memcpy(mNewPages, oldNewPages, mNewPagesSize - PAGE_SIZE);

		mRelocCursor = mNewPages + (mRelocCursor - oldNewPages);

		VirtualFree(oldNewPages, 0, MEM_RELEASE);
	}

	memcpy(mRelocCursor, buffer, length);
	mRelocCursor += length;

	return true;
}

bool PFHook::PlaceRelativeJump(INT32 offset)
{
	// jmp offset
	UINT8 instruction[JMP_SIZE_32] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	*(INT32*)(&instruction[1]) = offset;

	return Relocate(instruction, JMP_SIZE_32);
}

bool PFHook::PlaceAbsoluteJump(UINT64 address)
{
	// jmp [rip]
	// rip -> address
	UINT8 instruction[JMP_SIZE_ABS] =
	{
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00 , 0x00, 0x00, 0x00, 0x00
	};

	*(UINT64*)(&instruction[6]) = address;

	return Relocate(instruction, JMP_SIZE_ABS);
}

bool PFHook::PlaceAbsoluteJumpAndBreak(UINT64 address)
{
	// jmp [rip]
	// rip -> address
	UINT8 instruction[JMP_SIZE_ABS] =
	{
		0xCC, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00 , 0x00, 0x00, 0x00, 0x00
	};

	*(UINT64*)(&instruction[6]) = address;

	return Relocate(instruction, JMP_SIZE_ABS);
}

bool PFHook::PlaceManualReturnAddress(UINT64 returnAddress)
{
	// push imm
	// mov dword ptr [rsp, 4], imm
	UINT8 instructions[MANUAL_RET_SIZE] =
	{
		0x68, 0x00, 0x00, 0x00, 0x00, 0xC7, 0x44,
		0x24, 0x04, 0x00, 0x00, 0x00, 0x00
	};

	*reinterpret_cast<UINT32*>(&instructions[1]) = static_cast<UINT32>(returnAddress);
	*reinterpret_cast<UINT32*>(&instructions[9]) = static_cast<UINT32>(returnAddress >> 32);

	return Relocate(instructions, MANUAL_RET_SIZE);
}

void PFHook::InsertCurrentThread()
{
	mThreadMutex.lock();
	mThreads.push_back(Thread{ __readgsqword(0x48), mNewPages });
	mThreadMutex.unlock();
}

uint8_t* PFHook::FindThreadNewPages()
{
	uint8_t* newPages = nullptr;

	mThreadMutex.lock();

	for (Thread& thread : mThreads)
	{
		if (thread.threadID == __readgsqword(0x48))
		{
			newPages = thread.newPages;
			break;
		}
	}

	mThreadMutex.unlock();
	return newPages;
}

void PFHook::SetThreadNewPages(uint8_t* newPages)
{
	mThreadMutex.lock();
	for (Thread& thread : mThreads)
	{
		if (thread.threadID == __readgsqword(0x48))
		{
			thread.newPages = newPages;
			break;
		}
	}

	mThreadMutex.unlock();
}

std::mutex gHookMutex;
std::vector<PFHook*> gHooks;

void InsertHook(PFHook* hook)
{
	gHookMutex.lock();
	gHooks.push_back(hook);
	gHookMutex.unlock();
}

// Address: An address within the original page or the new pages
PFHook* FindHook(void* address)
{
	PFHook* hookRet = nullptr;
	gHookMutex.lock();

	for (PFHook* hook : gHooks)
	{
		if ((address >= hook->OriginalPage() && address < hook->OriginalPageEnd()) ||
			address >= hook->mNewPages && address < hook->NewPagesEnd())
		{
			hookRet = hook;
			break;
		}
	}

	gHookMutex.unlock();
	return hookRet;
}