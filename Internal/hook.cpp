#include "hook.h"

bool PFHook::Relocate(const void* buffer, size_t length)
{
	if ((mRelocCursor + length) >= NewPagesEnd())
	{
		// extend
		mNewPageSize += PAGE_SIZE;

		UINT8* oldNewPages = mNewPages;

		mNewPages = reinterpret_cast<UINT8*>(VirtualAlloc(nullptr,
			mNewPageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

		if (!mNewPages)
			return false;

		memset(mNewPages, 0xCC, mNewPageSize);
		memcpy(mNewPages, oldNewPages, mNewPageSize - PAGE_SIZE);

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