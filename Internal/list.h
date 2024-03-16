#pragma once
#include <intrin.h>
#include <Windows.h>

class List
{
private:
	LIST_ENTRY mListHead;
	UINT64 mStructSize;

	inline void InitializeListHead(LIST_ENTRY* listHead)
	{
		listHead->Flink = listHead;
		listHead->Blink = listHead;
	}

	inline void InsertListHead(LIST_ENTRY* listHead, LIST_ENTRY* entry)
	{
		LIST_ENTRY* oldFlink = listHead->Flink;
		listHead->Flink = entry;
		entry->Flink = oldFlink;
		entry->Blink = listHead;
		oldFlink->Blink = entry;
	}

public:
	List(UINT64 structSize) : mStructSize{ structSize }
	{
		InitializeListHead(&mListHead);
	}

	void* NewEntry(void* entry)
	{
		InsertListHead(&mListHead, reinterpret_cast<LIST_ENTRY*>(
			reinterpret_cast<UINT64>(entry) + mStructSize));

		return entry;
	}

	void ForEachEntry(bool(*function)(void* entry))
	{
		for (LIST_ENTRY* entry = mListHead.Flink; entry != &mListHead; entry = entry->Flink)
		{
			if (function(reinterpret_cast<UINT8*>(entry) - mStructSize))
				return;
		}
	}

// do-while? (Explanation: https://stackoverflow.com/questions/8764733/can-a-c-macro-contain-temporary-variables)
#define NEW_ENTRY(inst, type, ...) \
do \
{ \
	type* t = reinterpret_cast<type*>(new unsigned char[sizeof(type) + sizeof(LIST_ENTRY)]); \
	*t  = type{__VA_ARGS__}; \
	inst->NewEntry(t); \
} while(0)

#define NEW_EMPTY_ENTRY(type) inst->NewEntry(new type)

};