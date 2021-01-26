#include "peb.h"
typedef unsigned long       DWORD;
typedef unsigned short      WORD;

DWORD getFuncAddress(char *funcName , DWORD k32Address);
DWORD findDll(DWORD pebAddr, char *name);

DWORD entry(DWORD pebAddr ,DWORD baseAddress,DWORD offset){

    DWORD k32Address = 0 ;
	char kernelStr[]="KERNEL32.DLL";
	k32Address = findDll(pebAddr,kernelStr);

	if (k32Address == 0 ){
		char kernelBaseStr[]="KERNELBASE.DLL";
    	k32Address = findDll(pebAddr,kernelBaseStr);

    	if (k32Address == 0 ){
 		   	return 0 ;
    	}
	}

	char loadLibStr[]="LoadLibraryA";
	DWORD llibAddr = getFuncAddress(loadLibStr,k32Address);
	llibAddr+=k32Address;

	char getProcStr []="GetProcAddress";
	DWORD gpAddr= getFuncAddress(getProcStr,k32Address);
	gpAddr+=k32Address;

	//DWORD(*LoadLibraryA)(char*);
	typedef WINBASEAPI _Ret_maybenull_ HMODULE (WINAPI *LoadLibraryA)(_In_ LPCSTR );
    LoadLibraryA loadLibraryA= (LoadLibraryA)(llibAddr);

    typedef WINBASEAPI FARPROC (WINAPI *GetProcAddress)(_In_ HMODULE hModule,_In_ LPCSTR lpProcName);
    GetProcAddress getProcAddress = (GetProcAddress)(gpAddr);

    char userStr[]="User32.dll";
    HMODULE u32dll = loadLibraryA(userStr);

    char boxStr[]="MessageBoxA";
    DWORD box = getProcAddress(u32dll,boxStr);
    typedef WINUSERAPI int (WINAPI *MessageBoxA)(_In_opt_ HWND hWnd,_In_opt_ LPCSTR lpText,_In_opt_ LPCSTR lpCaption,_In_ UINT uType);
//    typedef WINUSERAPI int (WINAPI *MessageBoxA)(_In_opt_ HWND hWnd,_In_opt_ LPCWSTR lpText,_In_opt_ LPCWSTR lpCaption,_In_ UINT uType);
    MessageBoxA messageBoxA = (MessageBoxA)(box);

    char lpText[]="inject";
    messageBoxA(0,lpText,lpText,0x00000002L);

    return 0;
}

DWORD findDll(DWORD pebAddr, char *name) {

    int nameLen = 0;

    for (int i = 0; name[i] != '\0'; i++) {
        nameLen++;
    }

    PPEB peb;
    peb = (PPEB) pebAddr;

    PPEB_LDR_DATA pldr;

    pldr = (peb->Ldr);

    LIST_ENTRY inMemoryOrderModuleList;

    inMemoryOrderModuleList = pldr->InMemoryOrderModuleList;

    PLIST_ENTRY flink;
    flink = inMemoryOrderModuleList.Flink;

    for (int loop = 0; loop < 10; loop++) {

        PLDR_DATA_TABLE_ENTRY table;
        table = (PLDR_DATA_TABLE_ENTRY) flink;

        short length;
        length = (short) (table->FullDllName.Length);

        char *dllName;

        dllName = (char *) (table->FullDllName.Buffer);

        if (dllName == 0) {
            break;
        }

        int index = 0;
        for (int i = 0; i < length; i++) {

            if (dllName[i] == 0) {
                continue;
            }

            if (name[index] == dllName[i] ||
                name[index] == (dllName[i] - ('a' - 'A')) ||
                name[index] == (dllName[i] + ('a' - 'A'))
                    ) {
                index++;

                if (index == nameLen) {
                    // find dll
                    DWORD dllAddr = 0;

                    dllAddr = (DWORD ) (table->Reserved2[0]);
                    return dllAddr;
                }
            } else {
                break;
            }
        }

        inMemoryOrderModuleList = *(LIST_ENTRY *) (flink->Flink);
        flink = (inMemoryOrderModuleList.Flink);
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


DWORD getNTHead(DWORD k32Address){
	return *(DWORD *)(k32Address+0x3c);
}

DWORD getOptHead32(DWORD k32Address){
	return getNTHead(k32Address)+0x18;
}

DWORD getDataDir(DWORD k32Address){
	return getOptHead32(k32Address)+0x60;
}

struct _IMAGE_EXPORT_DIRECTORY * getExportDir(DWORD k32Address){

	DWORD addr = getDataDir(k32Address);

	addr += k32Address;

	addr = *(DWORD *)(addr);

	addr += k32Address;

	struct _IMAGE_EXPORT_DIRECTORY *export;

	export = (struct _IMAGE_EXPORT_DIRECTORY *)addr;

	return export;
}

DWORD getFuncAddress(char *funcName , DWORD k32Address){


    struct _IMAGE_EXPORT_DIRECTORY *export  = getExportDir(k32Address);

    for (int i=0;i<export->NumberOfFunctions;i++){

        DWORD offset = i*4;
        offset += export->AddressOfNames;
        offset += k32Address;
        offset = *(DWORD *)offset;
        offset += k32Address;

        char *ent = (char *)(offset);

        for (int j=0;;j++){

            if (funcName[j] != ent[j]){
                break;
            }

            if (ent[j]=='\0'){
                DWORD orderOffset =i*2;
                orderOffset += export->AddressOfNameOrdinals;
                orderOffset += k32Address;

                WORD num = *(WORD *)orderOffset;

                DWORD funcAddr = num;
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