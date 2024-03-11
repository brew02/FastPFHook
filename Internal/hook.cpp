#include "hook.h"

void PFHook::NewTranslation(UINT8* originalAddress, UINT32 newOffset)
{
	Translation* translation = new Translation;
	translation->originalAddress = originalAddress;
	translation->newOffset = newOffset;
	InsertListHead(&mTranslationList, &translation->listEntry);
}

UINT32 PFHook::GetTranslationOffset(UINT8* originalAddress)
{
	for (LIST_ENTRY* entry = mTranslationList.Flink; entry != &mTranslationList; entry = entry->Flink)
	{
		Translation* translation = CONTAINING_RECORD(entry, Translation, listEntry);
		if (translation->originalAddress == originalAddress)
			return translation->newOffset;
	}

	return static_cast<UINT32>(originalAddress - OriginalPageInstructions());
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

void PFHook::AcquireWriteLock()
{
	while (TryWriteLock())
		Sleep(10);

	VirtualProtect(mNewPages, mNewPagesSize, PAGE_READWRITE, &mPageProtection);
}

void PFHook::ReleaseWriteLock()
{
	VirtualProtect(mNewPages, mNewPagesSize, mPageProtection, &mPageProtection);
	InterlockedBitTestAndReset(&mWriteLock, 0);
}

// Use different locks for this list and all others
void PFHook::NewThread()
{
	Thread* thread = new Thread;

	thread->threadID = reinterpret_cast<void*>(__readgsqword(0x48));
	thread->newPages = mNewPages;

	InsertListHead(&mThreadList, &thread->listEntry);
}