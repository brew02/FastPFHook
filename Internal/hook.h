#pragma once
#include <Windows.h>
#include <intrin.h>

#include <Zydis/Zydis.h>

#include "util.h"
#include "common.h"
#include "lock.h"

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

	struct Thread
	{
		LIST_ENTRY listEntry;
		void* threadID;
		UINT8* newPages;
	};
	LIST_ENTRY mThreadList;

	Lock mWriteLock;
	ULONG mPageProtection;

public:
	LIST_ENTRY listEntry;
	UINT8* mNewPages;
	UINT8* mOriginalAddress;
	UINT8* mRelocCursor;
	UINT64 mNewPagesSize;

	void NewTranslation(UINT8* originalAddress, UINT32 newOffset);
	UINT32 GetTranslationOffset(UINT8* originalAddress);

	bool Relocate(const void* buffer, size_t length);

	bool PlaceRelativeJump(INT32 offset);
	bool PlaceAbsoluteJump(UINT64 address);
	bool PlaceAbsoluteJumpAndBreak(UINT64 address);
	bool PlaceManualReturnAddress(UINT64 returnAddress);

	void NewThread();

	PFHook(void* newPages, void* originalAddress, UINT64 newPageSize) :
		mWriteLock{}, mNewPages{ reinterpret_cast<UINT8*>(newPages) },
		mOriginalAddress{ reinterpret_cast<UINT8*>(originalAddress) }, mNewPagesSize{ newPageSize },
		listEntry{ nullptr, nullptr }, mPageProtection{ 0 }
	{
		mRelocCursor = mNewPages + PAGE_SIZE + BOUNDARY_INSTRUCTION_LENGTH * 2 + JMP_SIZE_ABS;
		mRelocCursor = mNewPages + mNewPagesSize - BOUNDARY_INSTRUCTION_LENGTH;
		InitializeListHead(&mTranslationList);
		InitializeListHead(&mThreadList);
	}

	inline void LockWrites()
	{
		mWriteLock.Acquire();
		VirtualProtect(mNewPages, mNewPagesSize, PAGE_READWRITE, &mPageProtection);
	}

	inline void AllowWrites()
	{
		VirtualProtect(mNewPages, mNewPagesSize, mPageProtection, &mPageProtection);
		mWriteLock.Release();
	}

	// Remove some of these function, they are pointless
	// Add destructor definitions
	// Add another list that keeps track of all of the originalAddresses for function hooking purposes (i.e. multiple function hooks on the same page)

	__forceinline UINT8* NewPagesEnd()
	{
		return mNewPages + mNewPagesSize;
	}

	__forceinline UINT8* NewPagesInstructionsEnd()
	{
		return mNewPages + BOUNDARY_INSTRUCTION_LENGTH + PAGE_SIZE;
	}

	__forceinline UINT8* OriginalPage()
	{
		return reinterpret_cast<UINT8*>(
			PAGE_ALIGN(mOriginalAddress));
	}

	__forceinline UINT8* OriginalPageEnd()
	{
		return reinterpret_cast<UINT8*>(
			PAGE_ALIGN(mOriginalAddress)) + PAGE_SIZE;
	}

	__forceinline UINT8* OriginalPageInstructions()
	{
		return OriginalPage() - BOUNDARY_INSTRUCTION_LENGTH;
	}

	__forceinline UINT8* OriginalToNew(void* originalAddress, bool useTranslations = false)
	{
		if (useTranslations)
		{
			return mNewPages + GetTranslationOffset(
				reinterpret_cast<UINT8*>(originalAddress));
		}
		else
		{
			return mNewPages + (reinterpret_cast<UINT8*>(
				originalAddress) - OriginalPageInstructions());
		}
	}

	__forceinline UINT8* NewToOriginal(void* newAddress)
	{
		return OriginalPageInstructions() + (reinterpret_cast<UINT8*>(newAddress) - mNewPages);
	}
};