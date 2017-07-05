#include <windows.h>
#include <iostream>
#include <ImageHlp.h>

enum arch
{
	notfound,
	invalid,
	x32,
	x64,
	dotnet
};

enum corValues
{
	anycpu,
	x86pref,
	x64bit
};

#define COMIMAGE_FLAGS_32BITPREFERRED 0x20000

static CHAR* paths[] = {
	{"AnyCPU\\DotNetCrap.exe"},
	{"AnyCPUPrefer32\\DotNetCrap.exe"},
	{"x64\\DotNetCrap.exe"},
	{"x86\\DotNetCrap.exe"}
};

static PBYTE GetMappedFileBase(HANDLE hFile);

BOOL isDotNetILOnly(PIMAGE_COR20_HEADER cor)
{
	if (cor)
	{
		return ((cor->Flags & COMIMAGE_FLAGS_ILONLY) == COMIMAGE_FLAGS_ILONLY);
	}
}

BOOL isDotNet32BitPref(PIMAGE_COR20_HEADER cor)
{
	if (cor)
	{
		return ((cor->Flags & COMIMAGE_FLAGS_32BITPREFERRED) == COMIMAGE_FLAGS_32BITPREFERRED);
	}
}

BOOL isDotNet32bitOnly(PIMAGE_COR20_HEADER cor)
{
	if (cor)
	{
		return ((cor->Flags & COMIMAGE_FLAGS_32BITREQUIRED) == COMIMAGE_FLAGS_32BITREQUIRED);
	}
}

static PVOID GetPtrToCorHeader(HANDLE hFileHandle)
{
	HANDLE hMapHandle = NULL;
	LPVOID hMapView = NULL;
	DWORD dwSizeToMap = NULL;
	dwSizeToMap = GetFileSize(hFileHandle, 0);

	hMapHandle = CreateFileMapping(hFileHandle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, 0);
	if (!hMapHandle)
		return 0;
	hMapView = MapViewOfFile(hMapHandle, FILE_MAP_READ, 0, 0, dwSizeToMap);
	if (!hMapView)
		return 0;
	
	PIMAGE_DOS_HEADER _dosHeader = (PIMAGE_DOS_HEADER)hMapView;
	PIMAGE_NT_HEADERS _ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hMapView + _dosHeader->e_lfanew);
	if (_ntHeader && _ntHeader->Signature == IMAGE_NT_SIGNATURE)
	{
		//get the CLR header
		IMAGE_DATA_DIRECTORY *entry = NULL;
		entry = &_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
		//make sure we have a proper COR header
		if (entry->VirtualAddress == 0 || entry->Size == 0 || entry->Size < sizeof(IMAGE_COR20_HEADER))
		{
			return 0;
		}
		IMAGE_COR20_HEADER* _corHeader = (IMAGE_COR20_HEADER*)ImageRvaToVa(_ntHeader, hMapView, entry->VirtualAddress, 0);
		return _corHeader;
	}

	return 0;
}

static arch GetFileArchitecture(const TCHAR* szFileName)
{
	arch retval = notfound;
	HANDLE hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		IMAGE_DOS_HEADER idh;
		DWORD read = 0;
		if (ReadFile(hFile, &idh, sizeof(idh), &read, nullptr))
		{
			if (idh.e_magic == IMAGE_DOS_SIGNATURE)
			{
				IMAGE_NT_HEADERS inth;
				memset(&inth, 0, sizeof(inth));
				PIMAGE_NT_HEADERS pnth = nullptr;
				if (SetFilePointer(hFile, idh.e_lfanew, nullptr, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
				{
					if (ReadFile(hFile, &inth, sizeof(inth), &read, nullptr))
						pnth = &inth;
					else if (ReadFile(hFile, &inth, sizeof(DWORD) + sizeof(WORD), &read, nullptr))
						pnth = &inth;
				}
				if (pnth && pnth->Signature == IMAGE_NT_SIGNATURE)
				{
					if (pnth->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
						retval = x64;
					else if (pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0 && pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0 && (pnth->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0)
						retval = dotnet;
					else if (pnth->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
						retval = x32;
				}
			}
		}
		CloseHandle(hFile);
	}
	return retval;
}

int main(int argc, char ** argv)
{
	if (argc != 2)
	{
		// Use hardcoded program
	}
}