typedef unsigned long       DWORD;
typedef unsigned short      WORD;

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
	return k32Address+0x3c;
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
        offset += export->AddressOfFunctions;
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

                WORD num = (WORD *)orderOffset;

                DWORD funcAddr = num;
                funcAddr *= 4;
                funcAddr +=export->AddressOfFunctions;
                funcAddr += k32Address;
                funcAddr = (DWORD *)funcAddr;
                return funcAddr;
            }
        }
    }
    return 0;
}


DWORD entry(DWORD k32Address,DWORD baseAddress){
	char *funcName="CreateDirectoryA";
	return getFuncAddress(funcName,k32Address);
	//return 0x00;
}


