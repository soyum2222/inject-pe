typedef unsigned long       DWORD;
typedef unsigned short      WORD;
typedef long long           QWORD;




QWORD findDll(QWORD pebAddr ,char *name);
DWORD getFuncAddress(char *funcName , DWORD k32Address);


QWORD entry(QWORD pebAddr ,QWORD baseAddress,QWORD offset) {

	QWORD k32Address = 0 ;
	char name[]="KERNEL32.DLL";
	k32Address = findDll(pebAddr,name);
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