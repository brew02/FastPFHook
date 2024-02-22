#pragma once
#include <Windows.h>

#include <Zydis/Zydis.h>

#include "common.h"

class PFHook
{
public:
	UINT8* mNewPages;
	UINT8* mOriginalAddress;
	UINT8* mRelocCursor;
	UINT64 mNewPageSize;

	PFHook(void* newPages, void* originalAddress, UINT64 newPageSize)
	{
		mNewPages = reinterpret_cast<UINT8*>(newPages);
		mOriginalAddress = reinterpret_cast<UINT8*>(originalAddress);
		mRelocCursor = mNewPages + PAGE_SIZE + ZYDIS_MAX_INSTRUCTION_LENGTH * 2 + JMP_SIZE_ABS;
		mNewPageSize = newPageSize;
	}

	__forceinline UINT8* NewPagesEnd()
	{
		return mNewPages + mNewPageSize;
	}

	__forceinline UINT8* OriginalPage()
	{
		return reinterpret_cast<UINT8*>(PAGE_ALIGN(mOriginalAddress));
	}

	__forceinline UINT8* OriginalPageEnd()
	{
		return OriginalPage() + PAGE_SIZE;
	}

	__forceinline UINT8* NewPagesInstructions()
	{
		return mNewPages + ZYDIS_MAX_INSTRUCTION_LENGTH;
	}

	__forceinline UINT8* NewPagesInstructionsEnd()
	{
		return NewPagesInstructions() + PAGE_SIZE;
	}

	// Might require further changes or an additional function/parameter
	// for small relative instructions converted to a larger one.
	__forceinline UINT8* OriginalToNew(void* originalAddress)
	{
		return NewPagesInstructions() + (reinterpret_cast<UINT8*>(originalAddress) - OriginalPage());
	}

	// This might need changes for top instruction support
	__forceinline UINT8* NewToOriginal(void* newAddress)
	{
		return OriginalPage() + (reinterpret_cast<UINT8*>(newAddress) - NewPagesInstructions());
	}

	bool Relocate(const void* buffer, size_t length);

	bool PlaceRelativeJump(INT32 offset);
	bool PlaceAbsoluteJump(UINT64 address);
	bool PlaceAbsoluteJumpAndBreak(UINT64 address);
	bool PlaceManualReturnAddress(UINT64 returnAddress);
};