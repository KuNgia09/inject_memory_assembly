// Copyright (c) 2015, Dan Staples

//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "LoadLibraryR.h"
#include"resource1.h"


#pragma comment(lib,"Advapi32.lib")

#define MYFUNCTION_HASH		0x6654bba6  // hash of "MyFunction"
#define LOADASSEMBLYHASH    0x83cd796f  //hash of "LoadAssembly"

#define LOADASSEMBLY2HASH    0xcb7c1e9d  //hash of "LoadAssembly2"
// Simple app to inject a reflective DLL into a process vis its process ID.
int main(int argc, char* argv[])
{
	HANDLE hFile = NULL;
	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	LPVOID lpBuffer = NULL;
	DWORD dwLength = 0;
	DWORD dwBytesRead = 0;
	DWORD dwProcessId = 0;
	DWORD dwExitCode = 1;
	TOKEN_PRIVILEGES priv = { 0 };
	HGLOBAL hResLoad;
	HRSRC hrsrc;
	LPVOID lpResLock;
	DWORD assembleArgSize = 0;
	LPWSTR commandLine = NULL;

	hrsrc=FindResource(NULL, MAKEINTRESOURCE(IDR_BIN_RES1), "BIN_RES");
	if (hrsrc == NULL) {
		printf("Failed to Find Resource:%d\n", GetLastError());
		return 0;
	}
		
	hResLoad = LoadResource(NULL,hrsrc);
	if (hResLoad == NULL) {
		printf("Failed to Load Resource:%d\n", GetLastError());
		return 0;
	}
	lpResLock = LockResource(hResLoad);
	if (lpResLock == NULL)
	{
		printf(TEXT("Could not lock dialog box."));
		return 0;
	}
	DWORD resSize=SizeofResource(NULL, hrsrc);
	lpBuffer = lpResLock;
	dwLength = resSize;



	do
	{

		
		// Usage: inject.exe [pid] [assembly_dll_file] [arg1] [arg2] [arg3]
		if (argc < 3) {
			printf("usage:inject.exe [pid] [assembly_dll_file] [arg1] [arg2] [arg3]");
			return 0;
		}

		dwProcessId = atoi(argv[1]);

		if (argc > 3) {
			commandLine = GetCommandLineW();
			assembleArgSize = (wcslen(commandLine) + 1) * sizeof(wchar_t);

		}



		

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			priv.PrivilegeCount = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
				AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

			CloseHandle(hToken);
		}

		hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
		if (!hProcess)
			BREAK_WITH_ERROR("Failed to open the target process");


		//读取assembly file
		char* assemblyPath = argv[2];
		printf("assemblyPath:%s\n", assemblyPath);
		HANDLE assemblyFile = CreateFileA(assemblyPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (assemblyFile == INVALID_HANDLE_VALUE) {
			BREAK_WITH_ERROR("Failed to open assembly file");
		}
		DWORD dwAssembleLength = GetFileSize(assemblyFile, NULL);
		if (dwAssembleLength == INVALID_FILE_SIZE || dwAssembleLength == 0)
			BREAK_WITH_ERROR("Failed to get the DLL file size");

		//按如下顺序写入数据
		//payload地址
		// payload大小
		//参数大小
		//参数数据
		PVOID assemblyBuffer = HeapAlloc(GetProcessHeap(), 0, dwAssembleLength);
		if (!assemblyBuffer)
			BREAK_WITH_ERROR("Failed to get the DLL file size");

		if (ReadFile(assemblyFile, (char*)assemblyBuffer, dwAssembleLength, &dwBytesRead, NULL) == FALSE)
			BREAK_WITH_ERROR("Failed to alloc a buffer!");

		LPVOID allocBuffer = VirtualAllocEx(hProcess, NULL, dwAssembleLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (allocBuffer == NULL) {
			BREAK_WITH_ERROR("Failed to call VirtualAllocEx");
		}
		printf("assembly payload address:0x%p\n", allocBuffer);

		SIZE_T dwWrittenNumber;
		//写入assembly bin数据
		if (WriteProcessMemory(hProcess, (char*)allocBuffer, assemblyBuffer, dwAssembleLength, &dwWrittenNumber) == NULL) {
			BREAK_WITH_ERROR("Failed to write assembly data in remote memory Failed");
		}

		//传递assembly参数
		char* passArgBuffer = (char*)malloc(sizeof(PVOID) + 8 + assembleArgSize);
		if (passArgBuffer == NULL) {
			BREAK_WITH_ERROR("Failed to malloc memory Failed");
		}
		*(SIZE_T*)passArgBuffer = (SIZE_T)allocBuffer;
		*(DWORD*)(passArgBuffer + sizeof(SIZE_T)) = dwAssembleLength;

		*(DWORD*)(passArgBuffer + sizeof(SIZE_T) + 4) = assembleArgSize;
		if (assembleArgSize) {
			//拷贝assembly参数
			memcpy(passArgBuffer + sizeof(SIZE_T) + 8, commandLine, assembleArgSize);
		}
		


		CloseHandle(assemblyFile);
		hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL, LOADASSEMBLY2HASH, passArgBuffer, sizeof(PVOID) + 8 + assembleArgSize);
		if (!hModule)
			BREAK_WITH_ERROR("Failed to inject the DLL");
		free(passArgBuffer);

		

		WaitForSingleObject(hModule, INFINITE);

		if (!GetExitCodeThread(hModule, &dwExitCode))
			BREAK_WITH_ERROR("Failed to get exit code of thread");

		printf("[+] Created thread exited with code %d.\n", dwExitCode);

	} while (0);

	

	if (hProcess)
		CloseHandle(hProcess);

	return dwExitCode;
}