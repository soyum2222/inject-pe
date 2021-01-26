#include <windows.h>

typedef long long QWORD;

QWORD findDll(QWORD pebAddr ,char *name);
DWORD getFuncAddress(char *funcName , QWORD k32Address);

QWORD WINAPI entry(QWORD pebAddr ,QWORD baseAddress,QWORD offset) {

	QWORD k32Address = 0 ;
	char kernelStr[]="KERNEL32.DLL";
	k32Address = findDll(pebAddr,kernelStr);

	char loadLibStr[]="LoadLibraryA";
	QWORD llibAddr = getFuncAddress(loadLibStr,k32Address);
	llibAddr+=k32Address;

	char getProcStr []="GetProcAddress";
	QWORD gpAddr= getFuncAddress(getProcStr,k32Address);
	gpAddr+=k32Address;

	//DWORD(*LoadLibraryA)(char*);
	typedef WINBASEAPI _Ret_maybenull_ HMODULE (WINAPI *LoadLibraryA)(_In_ LPCSTR );
    LoadLibraryA loadLibraryA= (LoadLibraryA)(llibAddr);

    typedef WINBASEAPI FARPROC (WINAPI *GetProcAddress)(_In_ HMODULE hModule,_In_ LPCSTR lpProcName);
    GetProcAddress getProcAddress = (GetProcAddress)(gpAddr);

    char userStr[]="User32.dll";
    HMODULE u32dll = loadLibraryA(userStr);

    char boxStr[]="MessageBoxW";
    QWORD box = getProcAddress(u32dll,boxStr);

    typedef WINUSERAPI int (WINAPI *MessageBoxW)(_In_opt_ HWND hWnd,_In_opt_ LPCWSTR lpText,_In_opt_ LPCWSTR lpCaption,_In_ UINT uType);
    MessageBoxW messageBoxW = (MessageBoxW)(box);

    char lpText[]="inject";
    messageBoxW(0,lpText,lpText,0x00000002L);

    return 0;
}

QWORD findDll(QWORD pebAddr ,char *name) {

	int nameLen=0;

	for (int i = 0; name[i] != '\0'; i++) {
		nameLen++;
	}

	QWORD ldr;

	ldr = *(QWORD*)(pebAddr + 0x18);

	QWORD InMemoryOrderModuleList;

	InMemoryOrderModuleList = *(QWORD*)(ldr + 0x30);

	QWORD flink;
	flink = *(QWORD*)(InMemoryOrderModuleList);

	for (;1;) {

		short length;
		length = *(short*)(flink + 0x38);

		char *dllName;

		dllName = *(char**)(flink + 0x38 + 0x08);

		if (dllName == 0) {
			break;
		}

		int index = 0;
		for (int i = 0; i < length; i++) {

			if (dllName[i] == 0){
				continue;
			}

			if (name[index] == dllName[i] ||
			    name[index] == (dllName[i] - ('a'-'A')) ||
		        name[index] == (dllName[i] - ('a'+'A'))
			   ) {
				index++;

				if (index == nameLen) {
					// find dll
					QWORD dllAddr = 0;
					dllAddr = *(QWORD*)(flink + 0x10);
					return dllAddr;
				}
			} else {
				break;
			}
		}

		InMemoryOrderModuleList = *(QWORD*)(flink);
		flink = *(QWORD*)(InMemoryOrderModuleList);
	}

	return 0;
}


/*
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
};
*/



DWORD getNTHead(QWORD k32Address){
	return *(DWORD *)(k32Address+0x3c);
}

DWORD getOptHead64(QWORD k32Address){
	return getNTHead(k32Address)+0x18;
}

DWORD getDataDir(QWORD k32Address){
	return getOptHead64(k32Address)+0x70;
}

struct _IMAGE_EXPORT_DIRECTORY * getExportDir(QWORD k32Address){

	QWORD addr = getDataDir(k32Address);

	addr += k32Address;

	addr = *(DWORD *)(addr);

	addr += k32Address;

	struct _IMAGE_EXPORT_DIRECTORY *export;

	export = (struct _IMAGE_EXPORT_DIRECTORY *)addr;

	return export;
}

DWORD getFuncAddress(char *funcName , QWORD k32Address){


    struct _IMAGE_EXPORT_DIRECTORY *export  = getExportDir(k32Address);

    for (int i=0;i<export->NumberOfFunctions;i++){

        QWORD offset = i*4;
        offset += export->AddressOfNames;
        offset += k32Address;

        QWORD entOffset = *(DWORD *)offset;
        entOffset += k32Address;

        char *ent = (char *)(entOffset);

        for (int j=0;;j++){

            if (funcName[j] != ent[j]){
                break;
            }

            if (ent[j]=='\0'){
                QWORD orderOffset =i*2;
                orderOffset += export->AddressOfNameOrdinals;
                orderOffset += k32Address;

                WORD num = *(WORD *)orderOffset;

                QWORD funcAddr = num;
                funcAddr *= 4;
                funcAddr +=export->AddressOfFunctions;
                funcAddr += k32Address;
                funcAddr = *(DWORD *)funcAddr;
                return funcAddr;
            }
        }
    }
    return 0;
}