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