/////////////////////////////////////////////
//                                         //
//    Copyright (C) 2021-2021 Julian Uy    //
//  https://sites.google.com/site/awertyb  //
//                                         //
//   See details of license at "LICENSE"   //
//                                         //
/////////////////////////////////////////////

#include <windows.h>
#include "tp_stub.h"

static HMODULE this_hmodule = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD Reason, LPVOID lpReserved)
{
	if (Reason == DLL_PROCESS_ATTACH)
	{
		this_hmodule = hModule;
		if (hModule != NULL)
		{
			DisableThreadLibraryCalls(hModule);
		}
	}
	return TRUE;
}

static bool RunPE(ttstr path)
{
	// PE headers
	PIMAGE_DOS_HEADER pidh;
	PIMAGE_NT_HEADERS pinh;
	PIMAGE_SECTION_HEADER pish;

	// process info
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	// pointer to virtually allocated memory
	LPVOID lpAddress = NULL;

	// context of suspended thread for setting address of entry point
	CONTEXT context;

	// read executable file from storage
	BYTE *data = nullptr;
	ULONG size = 0;
	{
		IStream *in = TVPCreateIStream(path, TJS_BS_READ);
		if (!in)
		{
			TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: could not open file: %1"), (tjs_int)GetLastError()));
			return false;
		}
		STATSTG stat;
		in->Stat(&stat, STATFLAG_NONAME);
		size = (ULONG)(stat.cbSize.QuadPart);
		data = new BYTE[size];
		HRESULT read_result = in->Read(data, size, &size);
		in->Release();
		if (read_result != S_OK)
		{
			TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: could not read file: %1"), (tjs_int)GetLastError()));
			delete[] data;
			return false;
		}
	}

	// check if valid DOS header
	pidh = (PIMAGE_DOS_HEADER)data;
	if (pidh->e_magic != IMAGE_DOS_SIGNATURE)
	{
		TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: DOS signature error: %1"), (tjs_int)GetLastError()));
		return false;
	}

	// check if valid pe file
	pinh = (PIMAGE_NT_HEADERS)((ULONG_PTR)data + pidh->e_lfanew);
	if (pinh->Signature != IMAGE_NT_SIGNATURE)
	{
		TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: PE signature error: %1"), (tjs_int)GetLastError()));
		return false;
	}

	// first create process as suspended
	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);
	if (CreateProcess(NULL, GetCommandLine(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi) == FALSE)
	{
		TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: Create process error: %1"), (tjs_int)GetLastError()));
		return false;
	}

	context.ContextFlags = CONTEXT_FULL;
	if (GetThreadContext(pi.hThread, &context) == FALSE)
	{
		TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: Could not get thread context: %1"), (tjs_int)GetLastError()));
		return false;
	}

	// unmap memory space for our process
	HMODULE dll = LoadLibrary(TEXT("ntdll.dll"));
	if (dll == NULL)
	{
		TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: Could not load ntdll.dll: %1"), (tjs_int)GetLastError()));
		return false;
	}
	typedef NTSTATUS (WINAPI* unmap_view_of_section_type)(HANDLE, PVOID);
	unmap_view_of_section_type unmap_view_of_section = (unmap_view_of_section_type)GetProcAddress(dll, "NtUnmapViewOfSection");
	if (unmap_view_of_section == NULL)
	{
		TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: Could not get NtUnmapViewOfSection: %1"), (tjs_int)GetLastError()));
		return false;
	}
	if (unmap_view_of_section(pi.hProcess, (PVOID)pinh->OptionalHeader.ImageBase))
	{
		TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: Could not unmap original executable: %1"), (tjs_int)GetLastError()));
		return false;
	}


	// allocate virtual space for process
	lpAddress = VirtualAllocEx(pi.hProcess, (PVOID)pinh->OptionalHeader.ImageBase, pinh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (lpAddress == NULL)
	{
		TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: Virtual alloc error: %1"), (tjs_int)GetLastError()));
		return false;
	}

	// write headers into memory
	if (WriteProcessMemory(pi.hProcess, (PVOID)pinh->OptionalHeader.ImageBase, data, pinh->OptionalHeader.SizeOfHeaders, NULL) == FALSE)
	{
		TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: Write headers error: %1"), (tjs_int)GetLastError()));
		return false;
	}

	// write each section into memory
	for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++)
	{
		// calculate section header of each section
		pish = (PIMAGE_SECTION_HEADER)((ULONG_PTR)data + pidh->e_lfanew + sizeof (IMAGE_NT_HEADERS) + sizeof (IMAGE_SECTION_HEADER) * i);
		// write section data into memory
		if (WriteProcessMemory(pi.hProcess, (PVOID)(pinh->OptionalHeader.ImageBase + pish->VirtualAddress), (LPVOID)((ULONG_PTR)data + pish->PointerToRawData), pish->SizeOfRawData, NULL) == FALSE)
		{
			tjs_int last_error = GetLastError();
			if (last_error == 87)
			{
				TVPAddImportantLog(TJS_W("krselfload: Got ERROR_INVALID_PARAMETER while writing section; continuing anyway."));
			}
			else
			{
				TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: Write section error: %1"), last_error));
				return false;
			}
		}
	}

	// set starting address at virtual address: address of entry point
#ifdef _WIN64
	context.Rcx = pinh->OptionalHeader.ImageBase + pinh->OptionalHeader.AddressOfEntryPoint;
#else
	context.Eax = pinh->OptionalHeader.ImageBase + pinh->OptionalHeader.AddressOfEntryPoint;
#endif
	
	if (SetThreadContext(pi.hThread, &context) == FALSE)
	{
		TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: Set thread context error: %1"), (tjs_int)GetLastError()));
		return false;
	}

	// Get Kirikiri to unlock the log file
	TVPExecuteScript("if(typeof(global.Debug.logLocation) === 'String'){var arcdelim = System.getArgument('-arcdelim'); if (!arcdelim) {arcdelim = '>';}global.Debug.logLocation = '__this_path_should_be_fake__' + arcdelim;}");

	// delete the executable data to free some RAM
	delete[] data;

	// resume our suspended processes
	if (ResumeThread(pi.hThread) == (DWORD) -1)
	{
		TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: Resume thread error: %1"), (tjs_int)GetLastError()));
		return false;
	}

    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitcode;
    GetExitCodeProcess(pi.hProcess, &exitcode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    TerminateProcess(GetCurrentProcess(), exitcode);
	return true;
}


// Modified TVPGetXP3ArchiveOffset from XP3Archive.cpp
static bool IsXP3File(IStream *st)
{
	st->Seek({0}, STREAM_SEEK_SET, NULL);
	tjs_uint8 mark[11+1];
	static tjs_uint8 XP3Mark1[] =
		{ 0x58/*'X'*/, 0x50/*'P'*/, 0x33/*'3'*/, 0x0d/*'\r'*/,
		  0x0a/*'\n'*/, 0x20/*' '*/, 0x0a/*'\n'*/, 0x1a/*EOF*/,
		  0xff /* sentinel */, 
		// Extra junk data to break it up a bit (in case of compiler optimization)
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
		};
	static tjs_uint8 XP3Mark2[] =
		{ 0x8b, 0x67, 0x01, 0xff/* sentinel */ };

	// XP3 header mark contains:
	// 1. line feed and carriage return to detect corruption by unnecessary
	//    line-feeds convertion
	// 2. 1A EOF mark which indicates file's text readable header ending.
	// 3. 8B67 KANJI-CODE to detect curruption by unnecessary code convertion
	// 4. 01 file structure version and character coding
	//    higher 4 bits are file structure version, currently 0.
	//    lower 4 bits are character coding, currently 1, is BMP 16bit Unicode.

	static tjs_uint8 XP3Mark[11+1];
		// +1: I was warned by CodeGuard that the code will do
		// access overrun... because a number of 11 is not aligned by DWORD, 
		// and the processor may read the value of DWORD at last of this array
		// from offset 8. Then the last 1 byte would cause a fail.
#if 0
	static bool DoInit = true;
	if(DoInit)
	{
		// the XP3 header above is splitted into two part; to avoid
		// mis-finding of the header in the program's initialized data area.
		DoInit = false;
		memcpy(XP3Mark, XP3Mark1, 8);
		memcpy(XP3Mark + 8, XP3Mark2, 3);
		// here joins it.
	}
#else
	if (memcmp(XP3Mark, XP3Mark1, 8))
	{
		memcpy(XP3Mark, XP3Mark1, 8);
		memcpy(XP3Mark + 8, XP3Mark2, 3);
	}
#endif

	mark[0] = 0; // sentinel
	st->Read(mark, 11, NULL);
	if(mark[0] == 0x4d/*'M'*/ && mark[1] == 0x5a/*'Z'*/)
	{
		// "MZ" is a mark of Win32/DOS executables,
		// TVP searches the first mark of XP3 archive
		// in the executeble file.
		bool found = false;

		st->Seek({16}, STREAM_SEEK_SET, NULL);

		// XP3 mark must be aligned by a paragraph ( 16 bytes )
		const tjs_uint one_read_size = 256*1024;
		ULONG read;
		tjs_uint8 buffer[one_read_size]; // read 256kbytes at once

		while(st->Read(buffer, one_read_size, &read) == S_OK && read != 0)
		{
			tjs_uint p = 0;
			while(p<read)
			{
				if(!memcmp(XP3Mark, buffer + p, 11))
				{
					// found the mark
					found = true;
					break;
				}
				p+=16;
			}
			if(found) break;
		}

		if(!found)
		{
			return false;
		}
	}
	else if(!memcmp(XP3Mark, mark, 11))
	{
	}
	else
	{
		return false;
	}

	return true;
}

// Overridable function, in case you want to set up your own storage (e.g. minizip or libsquashfs)
// Return false to skip the XP3 file locator and current directory setting.
extern "C" bool __attribute__((weak)) prepare_storage(void)
{
	return true;
}

extern "C" __declspec(dllexport) HRESULT __stdcall V2Link(iTVPFunctionExporter *exporter)
{
	TVPInitImportStub(exporter);

	if (prepare_storage())
	{
		WCHAR* modnamebuf = new WCHAR[32768];
		if (modnamebuf)
		{
			if (this_hmodule)
			{
				DWORD ret_len = GetModuleFileNameW(this_hmodule, modnamebuf, 32768);
				if (ret_len)
				{
					ttstr arcname = modnamebuf;
					ttstr normmodname = TVPNormalizeStorageName(modnamebuf);
					arcname += TJS_W(">");
					ttstr normarcname = TVPNormalizeStorageName(arcname);
					IStream *in = TVPCreateIStream(normmodname, TJS_BS_READ);
					if (in)
					{
						if (IsXP3File(in))
						{
							TVPSetCurrentDirectory(normarcname);
							TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: TVP current directory has been set to %1."), normarcname));
						}
						else
						{
							TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: Self module is not XP3 file."), normarcname));
						}
						in->Release();
					}
					else
					{
						TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: could not open self module for reading: %1"), (tjs_int)GetLastError()));
					}
				}
			}
			delete[] modnamebuf;
		}
	}

	MEMORY_BASIC_INFORMATION meminfo;
	VirtualQuery((LPCVOID)GetModuleHandle(NULL), &meminfo, sizeof(meminfo));
	if (meminfo.AllocationProtect & ~PAGE_EXECUTE_WRITECOPY)
	{
		TVPAddImportantLog(TJS_W("krselfload: Not going to load tvpwin32.exe because current process is not memory mapped."));
	}
	else
	{
		tTJSVariant has_storage;
		TVPExecuteExpression("global.Storages.isExistentStorage('tvpwin32.exe')", &has_storage);
		if ((tTVInteger)has_storage != 0)
		{
			TVPAddImportantLog(TJS_W("krselfload: Found tvpwin32.exe in TVP storage."));
			if (RunPE("tvpwin32.exe") == false)
			{
				TVPExecuteExpression("global.System.inform('There was an error while executing tvpwin32.exe.')");
				TerminateProcess(GetCurrentProcess(), 1);
			}
			// Should be unreachable here.
			return S_OK;
		}
		else
		{
			TVPAddImportantLog(TJS_W("krselfload: Did not find tvpwin32.exe in TVP storage."));
		}
	}

	return S_OK;
}

extern "C" __declspec(dllexport) HRESULT __stdcall V2Unlink()
{
	TVPUninitImportStub();
	return S_OK;
}
