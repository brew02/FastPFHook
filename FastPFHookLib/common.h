#pragma once
#include <Windows.h>

#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(address) (UINT_PTR)(address) & (~0xFFFllu)
#define INITIAL_HOOK_SIZE 2 * PAGE_SIZE

#define TRAP_FLAG 0b100000000llu
#define EXCEPTION_INFORMATION_EXECUTION 8

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