// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include <stdio.h>
#include <tchar.h>
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

#import <mscorlib.tlb>  raw_interfaces_only			\
    	high_property_prefixes("_get","_put","_putref")		\
    	rename("ReportEvent", "InteropServices_ReportEvent")	\
	rename("or", "InteropServices_or")

using namespace mscorlib;





char sig_40[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };
char sig_20[] = { 0x76,0x32,0x2E,0x30,0x2E,0x35,0x30,0x37,0x32,0x37 };


BOOL FindVersion(void* assembly, int length)
{
	char* assembly_c;
	assembly_c = (char*)assembly;

	for (int i = 0; i < length; i++)
	{
		for (int j = 0; j < 10; j++)
		{
			if (sig_40[j] != assembly_c[i + j])
			{
				break;
			}
			else
			{
				if (j == (9))
				{
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}

BOOL ClrIsLoaded(LPCWSTR version, IEnumUnknown* pEnumerator, LPVOID* pRuntimeInfo) {
	HRESULT hr;
	ULONG fetched = 0;
	DWORD vbSize;
	BOOL retval = FALSE;
	wchar_t currentversion[260];

	while (SUCCEEDED(pEnumerator->Next(1, (IUnknown**)&pRuntimeInfo, &fetched)) && fetched > 0)
	{
		//已经加载的Runtime version
		hr = ((ICLRRuntimeInfo*)pRuntimeInfo)->GetVersionString(currentversion, &vbSize);


		if (!FAILED(hr))
		{
			if (wcscmp(currentversion, version) == 0)
			{
				retval = TRUE;
				break;
			}
		}
	}

	return retval;
}


extern "C" __declspec(dllexport) int LoadAssembly2(LPVOID payloadInfo, DWORD payloadInfoLen) {
	ICLRMetaHost* iMetaHost = NULL;
	ICLRRuntimeInfo* iRuntimeInfo = NULL;
	ICorRuntimeHost* iRuntimeHost = NULL;
	IUnknownPtr pAppDomain = NULL;
	_AppDomainPtr pDefaultAppDomain = NULL;
	_AssemblyPtr pAssembly = NULL;
	_MethodInfoPtr pMethodInfo = NULL;
	SAFEARRAYBOUND saBound[1];
	void* pData = NULL;
	VARIANT vRet;
	VARIANT vObj;
	VARIANT vPsa;
	SAFEARRAY* args = NULL;
	BOOL isloaded;
	BOOL bLoadable;
	LPCWSTR clrVersion;


	LPVOID payloadBuffer = (LPVOID) * (SIZE_T*)payloadInfo;
	DWORD payloadLen = *(DWORD*)((char*)payloadInfo + sizeof(SIZE_T));
	DWORD assembleArgSize = *(DWORD*)((char*)payloadInfo + sizeof(SIZE_T) + 4);



	char message[0x100] = { 0 };

	sprintf_s(message, 0x100, "assemble payload addr:%p!", payloadBuffer);
	OutputDebugStringA(message);

	sprintf_s(message, 0x100, "assemble payload len:%d!", payloadLen);
	OutputDebugStringA(message);

	sprintf_s(message, 0x100, "assembly argument size:%d!", assembleArgSize);
	OutputDebugStringA(message);


	if (FindVersion(payloadBuffer, payloadLen)) {
		clrVersion = L"v4.0.30319";
	}
	else {
		clrVersion = L"v2.0.50727";
	}

	CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (VOID**)&iMetaHost);

	IEnumUnknown* pEnumerator;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
	HRESULT hr = iMetaHost->EnumerateLoadedRuntimes(hProcess, &pEnumerator);

	if (FAILED(hr))
	{
		printf("Cannot enumerate loaded runtime w/hr 0x%08lx\n", hr);
		return 0;
	}
	hr = iMetaHost->GetRuntime(clrVersion, IID_ICLRRuntimeInfo, (VOID**)&iRuntimeInfo);

	if (FAILED(hr))
	{
		wprintf(L"Cannot get the required CLR version (%s) w/hr 0x%08lx\n", clrVersion, hr);
		return 0;
	}
	hr = iRuntimeInfo->IsLoadable(&bLoadable);

	if (FAILED(hr) || !bLoadable)
	{
		wprintf(L"Cannot load the required CLR version (%s) w/hr 0x%08lx\n", clrVersion, hr);
		return 0;
	}

	iRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&iRuntimeHost);
	hr = iRuntimeHost->Start();




	iRuntimeHost->GetDefaultDomain(&pAppDomain);
	pAppDomain->QueryInterface(__uuidof(_AppDomain), (VOID**)&pDefaultAppDomain);

	saBound[0].cElements = payloadLen;
	saBound[0].lLbound = 0;
	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, saBound);

	SafeArrayAccessData(pSafeArray, &pData);
	memcpy(pData, payloadBuffer, payloadLen);
	SafeArrayUnaccessData(pSafeArray);

	pDefaultAppDomain->Load_3(pSafeArray, &pAssembly);
	pAssembly->get_EntryPoint(&pMethodInfo);

	ZeroMemory(&vRet, sizeof(VARIANT));
	ZeroMemory(&vObj, sizeof(VARIANT));
	vObj.vt = VT_NULL;
	vPsa.vt = (VT_ARRAY | VT_BSTR);
	args = SafeArrayCreateVector(VT_VARIANT, 0, 1);

	wchar_t* argBuffer = NULL;


	//表示assembley有参数
	if (assembleArgSize > 0) {
		argBuffer = (wchar_t*)malloc(assembleArgSize);
		memcpy(argBuffer, (char*)payloadInfo + sizeof(SIZE_T) + 8, assembleArgSize);


		LPWSTR* szArglist;
		int nArgs;



		szArglist = CommandLineToArgvW(argBuffer, &nArgs);



		sprintf_s(message, 0x100, "参数个数为:%d", nArgs - 3);
		OutputDebugStringA(message);

		vPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, nArgs - 3);

		//去除前3个参数 前3个参数不是assembly的参数
		for (long i = 3; i < nArgs; i++)
		{
			OutputDebugStringW(szArglist[i]);
			size_t converted;
			/*size_t strlength = wcslen(szArglist[i]) + 1;
			OLECHAR* sOleText1 = new OLECHAR[strlength];
			char* buffer = (char*)malloc(strlength * sizeof(char));

			wcstombs_s(&converted,buffer,strlength, szArglist[i], strlength);
			mbstowcs_s(&converted, sOleText1, strlength, buffer, strlength);*/
			BSTR strParam1 = SysAllocString(szArglist[i]);
			long temp = i - 3;
			SafeArrayPutElement(vPsa.parray, &temp, strParam1);
			/*free(buffer);*/
		}

		long idx[1] = { 0 };
		SafeArrayPutElement(args, idx, &vPsa);



	}
	hr = pMethodInfo->Invoke_3(vObj, args, &vRet);
	pMethodInfo->Release();
	pAssembly->Release();
	pDefaultAppDomain->Release();
	iRuntimeInfo->Release();
	iMetaHost->Release();
	CoUninitialize();
}









BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

