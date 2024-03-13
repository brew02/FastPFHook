#pragma once
#include <intrin.h>
#include <Windows.h>

class Lock
{
private:
	volatile long mLock;

	inline bool TryLock()
	{
		return !mLock && !_interlockedbittestandset(&mLock, 0);
	}

public:
	inline volatile long Peak()
	{
		return mLock;
	}

	inline void Acquire()
	{
		while (!TryLock()) Sleep(10);
	}

	inline void Release()
	{
		_interlockedbittestandreset(&mLock, 0);
	}
};