#include <windows.h>
#include <iostream>
#include <ImageHlp.h>

enum arch
{
	notfound,
	invalid,
	x32,
	x64,
	dotnet32,
	dotnet64
};

typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

#define COMFLAG_32BITPREFERRED 0x20000

struct DotNetIdentifier
{
	TCHAR *hFile = NULL;
	DotNetIdentifier(TCHAR* pathFile) :hFile(pathFile) {}

};

static CHAR* paths[] = {
	{"AnyCPU\\DotNetCrap.exe"},
	{"AnyCPUPrefer32\\DotNetCrap.exe"},
	{"x64\\DotNetCrap.exe"},
	{"x86\\DotNetCrap.exe"}
};


static BOOL isWoW64()
{
	BOOL isWoW64 = FALSE;

	static auto fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(GetCurrentProcess(), &isWoW64))
		{
			return FALSE;
		}
	}
	return isWoW64;
}

static arch GetFileArchitecture(const TCHAR* szFileName)
{
	arch retval = notfound;
	HANDLE hMapHandle = NULL;
	LPVOID hMapView = NULL;
	HANDLE hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
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

					else if ((pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0 &&
						pnth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size != 0 &&
						(pnth->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0))
					{
						// find out which flavor of dotnet we're dealing with. Specifically,
						// ANYCPU can be compiled with two flavors, 32bit preferred or not.
						// Without the 32bit preferred flag, the loader will load the .NET
						// environment based on the current platforms bitness (x32 or x64)

						// we use a file map so the OS handled loading the exe and we only need
						// to perform an RVA to VA conversion. As opposed to RVA to file offset.
						DWORD dwSizeToMap = NULL;
						dwSizeToMap = GetFileSize(hFile, 0);

						hMapHandle = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, dwSizeToMap, 0);
						if (!hMapHandle)
						{
							return retval;
						}
						hMapView = MapViewOfFile(hMapHandle, FILE_MAP_READ, 0, 0, dwSizeToMap);
						if (!hMapView)
						{
							CloseHandle(hMapHandle);
							return retval;
						}

						PIMAGE_DOS_HEADER _dosHeader = (PIMAGE_DOS_HEADER)hMapView;
						PIMAGE_NT_HEADERS _ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hMapView + _dosHeader->e_lfanew);
						if (_ntHeader && _ntHeader->Signature == IMAGE_NT_SIGNATURE)
						{
							IMAGE_DATA_DIRECTORY *entry = NULL;
							entry = &_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
							//make sure we have a proper COR header
							if (!entry || entry->VirtualAddress == 0 || entry->Size == 0 || entry->Size < sizeof(IMAGE_COR20_HEADER))
							{
								UnmapViewOfFile(hMapView);
								CloseHandle(hFile);
								CloseHandle(hMapHandle);
								// It's a cockroach!
								return invalid;
							}

							PIMAGE_COR20_HEADER _corHeader = (PIMAGE_COR20_HEADER)ImageRvaToVa(_ntHeader, hMapView, entry->VirtualAddress, 0);

							// Here we check for our pertinent flags
							// First lets get the 32bits required out of the way, we know that requires x32dbg
							if ((_corHeader->Flags & COMIMAGE_FLAGS_32BITREQUIRED) == COMIMAGE_FLAGS_32BITREQUIRED)
								retval = dotnet32;
							// ILONLY, lets see if 32bit preferred is set
							if ((_corHeader->Flags & COMIMAGE_FLAGS_ILONLY) == COMIMAGE_FLAGS_ILONLY)
							{
								if ((_corHeader->Flags & COMFLAG_32BITPREFERRED) == COMFLAG_32BITPREFERRED)
									retval = dotnet32;
								else if ((_corHeader->Flags & COMIMAGE_FLAGS_32BITREQUIRED) == COMIMAGE_FLAGS_32BITREQUIRED)
									retval = dotnet32;
								else
								{
									// If IL_ONLY is set, then we must determine based on current platform which CLR will be loaded
									// If we're running under wow64, we're on a 64bit system
									if (isWoW64())
										retval = dotnet64;
									else
										retval = dotnet32;
								}
							}
						}
					}
					else if (pnth->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
						retval = x32;
				}
			}
		}
		UnmapViewOfFile(hMapView);
		CloseHandle(hMapHandle);
		CloseHandle(hFile);
	}
	return retval;
}

int main(int argc, char ** argv)
{
	if (argc != 2)
	{
		TCHAR curDir[1024];
		// Use hardcoded program
		size_t lengthEntries = sizeof(paths) / sizeof(paths[0]);
		GetCurrentDirectory(1024, curDir);

	}
}