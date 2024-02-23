#pragma once
#include <Windows.h>

#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(address) (UINT_PTR)(address) & (~0xFFFllu)
#define INITIAL_HOOK_SIZE 2 * PAGE_SIZE
#define JMP_SIZE_32 5
#define JMP_SIZE_ABS 14
#define MANUAL_RET_SIZE 13

#define GP_REGISTER_COUNT (ZYDIS_REGISTER_R15 - ZYDIS_REGISTER_RAX) + 1

#define TRAP_FLAG 0b100000000llu

#define EXCEPTION_INFORMATION_EXECUTION 8

#define RVA(base, address) reinterpret_cast<UINT64>(base) - reinterpret_cast<UINT64>(address)

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