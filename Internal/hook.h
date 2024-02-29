#pragma once
#include <Windows.h>

#include <Zydis/Zydis.h>

#include "common.h"

#define BOUNDARY_INSTRUCTION_LENGTH (ZYDIS_MAX_INSTRUCTION_LENGTH - 1)

class PFHook
{
private:
	struct Translation
	{
		LIST_ENTRY listEntry;
		UINT8* originalAddress;
		UINT32 newOffset;
	};

	LIST_ENTRY mTranslationList;

public:
	UINT8* mNewPages;
	UINT8* mOriginalAddress;
	UINT8* mRelocCursor;
	UINT64 mNewPageSize;

	void NewTranslation(UINT8* originalAddress, UINT32 newOffset);
	UINT32 GetTranslationOffset(UINT8* originalAddress);

	bool Relocate(const void* buffer, size_t length);

	bool PlaceRelativeJump(INT32 offset);
	bool PlaceAbsoluteJump(UINT64 address);
	bool PlaceAbsoluteJumpAndBreak(UINT64 address);
	bool PlaceManualReturnAddress(UINT64 returnAddress);

	PFHook(void* newPages, void* originalAddress, UINT64 newPageSize)
	{
		mNewPages = reinterpret_cast<UINT8*>(newPages);
		mOriginalAddress = reinterpret_cast<UINT8*>(originalAddress);
		mRelocCursor = mNewPages + PAGE_SIZE + BOUNDARY_INSTRUCTION_LENGTH * 2 + JMP_SIZE_ABS;
		mNewPageSize = newPageSize;
		InitializeListHead(&mTranslationList);

		mRelocCursor = (mNewPages + 2 * PAGE_SIZE) - 2 * JMP_SIZE_ABS;
	}

	__forceinline UINT8* NewPagesEnd()
	{
		return mNewPages + mNewPageSize;
	}

	__forceinline UINT8* NewPagesInstructionsEnd()
	{
		return mNewPages + BOUNDARY_INSTRUCTION_LENGTH + PAGE_SIZE;
	}

	__forceinline UINT8* OriginalPage()
	{
		return reinterpret_cast<UINT8*>(PAGE_ALIGN(
			mOriginalAddress));
	}

	__forceinline UINT8* OriginalPageEnd()
	{
		return reinterpret_cast<UINT8*>(PAGE_ALIGN(mOriginalAddress)) + PAGE_SIZE;
	}

	__forceinline UINT8* OriginalPageInstructions()
	{
		return OriginalPage() - BOUNDARY_INSTRUCTION_LENGTH;
	}

	// Might require further changes or an additional function/parameter
	// for small relative instructions converted to a larger one.
	__forceinline UINT8* OriginalToNew(void* originalAddress, bool useTranslations = false)
	{
		if (useTranslations)
			return mNewPages + GetTranslationOffset(reinterpret_cast<UINT8*>(originalAddress));
		else
			return mNewPages + (reinterpret_cast<UINT8*>(originalAddress) - OriginalPageInstructions());
	}

	// This might need changes for top instruction support
	__forceinline UINT8* NewToOriginal(void* newAddress)
	{
		return OriginalPageInstructions() + (reinterpret_cast<UINT8*>(newAddress) - mNewPages);
	}
};