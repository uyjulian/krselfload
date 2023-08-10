/////////////////////////////////////////////
//                                         //
//    Copyright (C) 2021-2023 Julian Uy    //
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
							TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: TVP current directory has been set: %1"), normarcname));
						}
						else
						{
							TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: Self module is not XP3 file: %1"), normarcname));
						}
						in->Release();
					}
					else
					{
						TVPAddImportantLog(TVPFormatMessage(TJS_W("krselfload: could not open self module for reading: %1"), normarcname));
					}
				}
			}
			delete[] modnamebuf;
		}
	}

	return S_OK;
}

extern "C" __declspec(dllexport) HRESULT __stdcall V2Unlink()
{
	TVPUninitImportStub();
	return S_OK;
}
