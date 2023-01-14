#include "StdAfx.h"
#include "LDasm.h"
_NT_BEGIN
#include <ntintsafe.h>
#include "trampoline.h"

class Z_DETOUR_REGION 
{
	friend Z_DETOUR_TRAMPOLINE;

	Z_DETOUR_REGION* next;
	Z_DETOUR_TRAMPOLINE* First;
	LONG dwRef;
	Z_DETOUR_TRAMPOLINE first[];

	static Z_DETOUR_REGION* spRegion;

	~Z_DETOUR_REGION();

	Z_DETOUR_REGION();

	Z_DETOUR_TRAMPOLINE* alloc();

	void free(Z_DETOUR_TRAMPOLINE* Next)
	{
		Next->Next = First, First = Next;

		Release();
	}

	void Release()
	{
		if (!--dwRef)
		{
			delete this;
		}
	}

	void operator delete(PVOID BaseAddress)
	{
		SIZE_T RegionSize = 0;
		NtFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, MEM_RELEASE);
	}

	void* operator new(size_t, ULONG_PTR min, ULONG_PTR max);

	static Z_DETOUR_TRAMPOLINE* _alloc(void* pvTarget);

	static void _free(Z_DETOUR_TRAMPOLINE* pTramp);

	static ULONG GetAllocationGranularity()
	{
		SYSTEM_BASIC_INFORMATION sbi;
		if (0 > NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), 0)) __debugbreak();
		return sbi.AllocationGranularity;
	}

public:
	static ULONG gAllocationGranularity;
};

Z_DETOUR_REGION* Z_DETOUR_REGION::spRegion = 0;
ULONG Z_DETOUR_REGION::gAllocationGranularity = Z_DETOUR_REGION::GetAllocationGranularity();

Z_DETOUR_REGION::~Z_DETOUR_REGION()
{
	Z_DETOUR_REGION** ppRegion = &spRegion, *pRegion;

	while ((pRegion = *ppRegion) != this)
	{
		ppRegion = &pRegion->next;
	}

	*ppRegion = next;
}

Z_DETOUR_REGION::Z_DETOUR_REGION() : first{}
{
	dwRef = 1;

	next = spRegion, spRegion = this;

	ULONG n = (gAllocationGranularity - sizeof(Z_DETOUR_REGION)) / sizeof(Z_DETOUR_TRAMPOLINE);

	Z_DETOUR_TRAMPOLINE* Next = first, *Prev = 0;
	do 
	{
		Next->Next = Prev, Prev = Next++;
	} while (--n);

	First = Prev;
}

Z_DETOUR_TRAMPOLINE* Z_DETOUR_REGION::alloc()
{
	if (Z_DETOUR_TRAMPOLINE* Next = First)
	{
		dwRef++;

		First = Next->Next;

		return Next;
	}

	return 0;
}

void* Z_DETOUR_REGION::operator new(size_t, ULONG_PTR min, ULONG_PTR max)
{
	ULONG_PTR addr, add = gAllocationGranularity - 1, mask = ~add;

	MEMORY_BASIC_INFORMATION mbi; 
	do 
	{
		if (0 > NtQueryVirtualMemory(NtCurrentProcess(),
			(void*)min, MemoryBasicInformation, &mbi, sizeof(mbi), 0)) return NULL;

		min = (UINT_PTR)mbi.BaseAddress + mbi.RegionSize;

		if (mbi.State == MEM_FREE)
		{
			addr = ((UINT_PTR)mbi.BaseAddress + add) & mask;

			if (addr < min && gAllocationGranularity <= (min - addr))
			{
				SIZE_T RegionSize = gAllocationGranularity;

				switch (NtAllocateVirtualMemory(NtCurrentProcess(), (void**)&addr, 0, 
					&RegionSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE))
				{
				case STATUS_CONFLICTING_ADDRESSES:
					min = (UINT_PTR)mbi.BaseAddress;
					break;
				case STATUS_SUCCESS:
					return (PVOID)addr;
				default: 
					return 0;
				}
			}
		}

	} while (min < max);

	return NULL;
}

void Z_DETOUR_REGION::_free(Z_DETOUR_TRAMPOLINE* pTramp)
{
	if (Z_DETOUR_REGION* pRegion = spRegion)
	{
		do 
		{
			if ((ULONG_PTR)pTramp - (ULONG_PTR)pRegion < gAllocationGranularity)
			{
				pRegion->free(pTramp);

				return ;
			}
		} while (pRegion = pRegion->next);
	}

	__debugbreak();
}

void ExpandRange(ULONG_PTR a, ULONG_PTR b, ULONG_PTR& min, ULONG_PTR& max)
{
	ULONG_PTR add = Z_DETOUR_REGION::gAllocationGranularity - 1, mask = ~add, _a, _b;
	
	_b = (a + 0x80000000) & mask;
	_a = (b + add - 0x80000000) & mask;

	min = b < _a ? 0 : _a;
	max = _b < a ? ULONG_PTR_MAX : _b;
}

BOOL GetRangeForAddress(PVOID pv, ULONG_PTR& min, ULONG_PTR& max)
{
	PVOID hmod;
	if (hmod = RtlPcToFileHeader(pv, &hmod))
	{
		if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(hmod))
		{
			ExpandRange((ULONG_PTR)hmod, (ULONG_PTR)hmod + pinth->OptionalHeader.SizeOfImage, min, max);
			return TRUE;
		}
		return FALSE;
	}

	MEMORY_BASIC_INFORMATION mbi;
	if (0 <= NtQueryVirtualMemory(NtCurrentProcess(), pv, MemoryBasicInformation, &mbi, sizeof(mbi), 0))
	{
		if (mbi.State == MEM_COMMIT)
		{
			PVOID AllocationBase = mbi.AllocationBase;

			do 
			{
				pv = (PBYTE)mbi.BaseAddress + mbi.RegionSize;

				if (0 > NtQueryVirtualMemory(NtCurrentProcess(), pv, MemoryBasicInformation, &mbi, sizeof(mbi), 0))
				{
					return FALSE;
				}

			} while (mbi.State == MEM_COMMIT && mbi.AllocationBase == AllocationBase);

			ExpandRange((ULONG_PTR)AllocationBase, (ULONG_PTR)pv, min, max);

			return TRUE;
		}
	}

	return FALSE;
}

Z_DETOUR_TRAMPOLINE* Z_DETOUR_REGION::_alloc(void* pvTarget)
{
	ULONG_PTR min, max, cb;

	if (!GetRangeForAddress(pvTarget, min, max))
	{
		return 0;
	}

	cb = max - min;

	Z_DETOUR_TRAMPOLINE* pTramp;

	Z_DETOUR_REGION* pRegion = spRegion;

	if (pRegion)
	{

		do 
		{
			if ((ULONG_PTR)pRegion - min < cb)
			{
				if (pTramp = pRegion->alloc())
				{
					return pTramp;
				}
			}

		} while (pRegion = pRegion->next);
	}

	if (pRegion = new(min, max) Z_DETOUR_REGION)
	{
		pTramp = pRegion->alloc();
		pRegion->Release();
		return pTramp;
	}

	return 0;
}

//////////////////////////////////////////////////////////////////////////

void* Z_DETOUR_TRAMPOLINE::operator new(size_t, void* pvTarget)
{
	return Z_DETOUR_REGION::_alloc(pvTarget);
}

void Z_DETOUR_TRAMPOLINE::operator delete(PVOID pv)
{
	Z_DETOUR_REGION::_free((Z_DETOUR_TRAMPOLINE*)pv);
}

NTSTATUS Z_DETOUR_TRAMPOLINE::Set()
{
	struct {
		ULONG op;
		BYTE pad[3];
		BYTE jmp_e9;
		union {
			ULONG64 rel;

			struct {
				ULONG rel32;
				USHORT fbe9; // jmp $-7
			};
		};
	} j;

	// first try direct jmp -> pvDetour
	j.rel = (ULONG64)(ULONG_PTR)pvDetour - (ULONG64)((ULONG_PTR)pvJmp + 5);

	if (j.rel + 0x80000000 >= 0x100000000ULL)
	{
		// try jmp -> jmp [pvDetour] in Z_DETOUR_TRAMPOLINE

		j.rel = (ULONG64)(ULONG_PTR)&ff25 - (ULONG64)((ULONG_PTR)pvJmp + 5);

		if (j.rel + 0x80000000 >= 0x100000000ULL)
		{
			return STATUS_UNSUCCESSFUL;
		}
	}

	PVOID pv = pvJmp;

#ifdef _M_IX86
	j.fbe9 = 0xf9eb;
#endif//#ifdef _M_IX86

	SIZE_T size = cbRestore;
	NTSTATUS status = ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &size, PAGE_EXECUTE_READWRITE, &j.op);

	if (0 > status)
	{
		return status;
	}

	j.jmp_e9 = 0xe9;

	memcpy(pvJmp, &j.jmp_e9, cbRestore);

	if (j.op != PAGE_EXECUTE_READWRITE)
	{
		ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &size, j.op, &j.op);
	}

	return STATUS_SUCCESS;
}

NTSTATUS Z_DETOUR_TRAMPOLINE::Remove()
{
	ULONG op;
	PVOID pv = pvJmp;

	SIZE_T size = cbRestore;

	NTSTATUS status = ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &size, PAGE_EXECUTE_READWRITE, &op);

	if (0 > status)
	{
		return status;
	}

	memcpy(pvJmp, rbRestore, cbRestore);

	if (op != PAGE_EXECUTE_READWRITE)
	{
		ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &size, op, &op);
	}

	return STATUS_SUCCESS;
}

PVOID Z_DETOUR_TRAMPOLINE::Init(PVOID pvTarget)
{
	ldasm_data ld;
	PBYTE code = (PBYTE)pvTarget, pDst = rbCode;
	BYTE len, cb = 0;
	cbRestore = 5;

#ifdef _M_IX86
	if (code[0] == 0x8b && code[1] == 0xff && // mov edi,edi
		((code[-1] == 0x90 && code[-2] == 0x90 && code[-3] == 0x90 && code[-4] == 0x90 && code[-5] == 0x90) || // nop
		 (code[-1] == 0xcc && code[-2] == 0xcc && code[-3] == 0xcc && code[-4] == 0xcc && code[-5] == 0xcc))) // int 3
	{
		pvJmp = code - 5;
		pvRemain = 0;
		cbRestore = 7;
		memcpy(rbRestore, pvJmp, 7);
		return code + 2;
	}
#endif//_M_IX86

	do 
	{
__0:
		len = ldasm( code, &ld, is_x64 );

		if (ld.flags & F_INVALID)
		{
			return 0;
		}

		memcpy(pDst, code, len);

		if (ld.flags & F_RELATIVE)
		{
			LONG_PTR delta;

			if (ld.flags & F_DISP)
			{
				if (ld.disp_size != 4)
				{
					return 0;
				}

				delta = *(PLONG)(code + ld.disp_offset);
__1:
				delta += code - pDst;

				if ((ULONG64)delta + 0x80000000 >= 0x100000000ULL)
				{
					return 0;
				}

				*(PLONG)(pDst + ld.disp_offset) = (LONG)delta;
			}
			else if (ld.flags & F_IMM)
			{
				BYTE opcode = code[ld.opcd_offset];

				switch (ld.imm_size)
				{
				default:
					return 0;
				case 4:
					delta = *(PLONG)(code + ld.imm_offset);

					if (ld.opcd_size == 1 && opcode == 0xe9 && code == pvTarget) // jmp +imm32
					{
						memcpy(rbRestore, pvTarget, 5);

						pvJmp = pvTarget, pvRemain = 0;

						return code + len + delta;
					}
					ld.disp_offset = ld.imm_offset;
					goto __1;
				case 1:
					if (ld.opcd_size != 1)
					{
						return 0;
					}

					delta = *(PCHAR)(code+ld.imm_offset);

					if (opcode == 0xeb) // jmp +imm8
					{
						if (code == pvTarget)
						{
							pvTarget = code = code + len + delta, cb = 0;
							goto __0;
						}
						pDst[ld.opcd_offset]=0xe9;// -> jmp +imm32

						delta += code - pDst - 3;

						if ((ULONG64)delta + 0x80000000 >= 0x100000000ULL)
						{
							return 0;
						}

						*(PLONG)(pDst + ld.imm_offset) = (LONG)delta;

						pDst += 3;
						break;
					}

					if (opcode - 0x70 > 0xf) // jxx
					{
						return 0;
					}

					pDst[ld.opcd_offset]=0x0f;
					pDst[ld.opcd_offset+1]=0x10+opcode;

					delta += code - pDst - 4;

					if ((ULONG_PTR)delta + 0x80000000 >= 0x100000000UL)
					{
						return 0;
					}

					*(PLONG)(pDst + ld.imm_offset + 1) = (LONG)delta;

					pDst += 4;
					break;
				}
			}
		}

		pDst += len;

	} while (code += len, (cb += len) < 5);

	pvRemain = code;

	*pDst++ = 0xff, *pDst++ = 0x25; // jmp [pvRemain]

	ULONG delta;

#if defined(_M_X64)  
	delta = RtlPointerToOffset(pDst + 4, &pvRemain);
#elif defined (_M_IX86)
	delta = (ULONG)&pvRemain;
#else
#error ##
#endif
	memcpy(pDst, &delta, sizeof(ULONG));

	memcpy(rbRestore, pvTarget, 5);

	pvJmp = pvTarget;

	return rbCode;
}

_NT_END