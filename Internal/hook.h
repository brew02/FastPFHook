#pragma once
#include <Windows.h>
#include <intrin.h>
#include <vector>
#include <mutex>

#include <Zydis/Zydis.h>

#include "util.h"
#include "common.h"

#define BOUNDARY_INSTRUCTION_LENGTH (ZYDIS_MAX_INSTRUCTION_LENGTH - 1)

class PFHook
{
public:
	struct Thread
	{
		UINT64 threadID;
		UINT8* newPages;
	};

	struct Translation
	{
		UINT8* originalAddress;
		UINT32 newOffset;
	};

private:
	std::vector<Translation> mTranslations;
	std::mutex mTranslationMutex;

	std::vector<Thread> mThreads;
	std::mutex mThreadMutex;

	bool mWritingLocked;
	std::mutex mWriteMutex;
	ULONG mPageProtection;

public:

	UINT8* mNewPages;
	UINT8* mOriginalAddress;
	UINT8* mRelocCursor;
	UINT64 mNewPagesSize;

	void InsertTranslation(const Translation& translation);
	uint32_t FindTranslationOffset(uint8_t* originalAddress);

	bool Relocate(const void* buffer, size_t length);

	bool PlaceRelativeJump(INT32 offset);
	bool PlaceAbsoluteJump(UINT64 address);
	bool PlaceAbsoluteJumpAndBreak(UINT64 address);
	bool PlaceManualReturnAddress(UINT64 returnAddress);

	void InsertCurrentThread();
	uint8_t* FindThreadNewPages();
	void SetThreadNewPages(uint8_t* newPages);

	PFHook(void* newPages, void* originalAddress) :
		mWritingLocked{ false }, mOriginalAddress{ reinterpret_cast<UINT8*>(originalAddress) },
		mNewPagesSize{ INITIAL_HOOK_SIZE }, mPageProtection{ 0 }, mNewPages{ reinterpret_cast<uint8_t*>(newPages) }
	{
		memset(mNewPages, 0xCC, mNewPagesSize);
		mRelocCursor = mNewPages + PAGE_SIZE + BOUNDARY_INSTRUCTION_LENGTH * 2 + JMP_SIZE_ABS;
	}

	~PFHook()
	{

	}

	// Place these in parseandtranslatesafe
	inline void LockWrites()
	{
		mWritingLocked = true;
		mWriteMutex.lock();
		VirtualProtect(mNewPages, mNewPagesSize, PAGE_READWRITE, &mPageProtection);
	}

	inline void UnlockWrites()
	{
		VirtualProtect(mNewPages, mNewPagesSize, mPageProtection, &mPageProtection);
		mWriteMutex.unlock();
		mWritingLocked = false;
	}

	__forceinline volatile long PeakWriteLock()
	{
		return mWritingLocked;
	}

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
			return mNewPages + FindTranslationOffset(
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

void InsertHook(PFHook* hook);
PFHook* FindHook(void* address);