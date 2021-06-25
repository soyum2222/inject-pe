ifdef OS
	GCC =gcc.exe
	LD =ld.exe
	NASM =nasm.exe
	OBJCOPY =objcopy.exe
	OBJDUMP =objdump.exe
	BOOTSIZE =0
	RDATA =.rdata
	LDM = i386pe
else
	GCC =i686-w64-mingw32-gcc
	LD =i686-w64-mingw32-ld
	NASM =nasm
	OBJCOPY =i686-w64-mingw32-objcopy
	OBJDUMP =i686-w64-mingw32-objdump
	BOOTSIZE =0
	RDATA =.rdata
	LDM = i386pe

endif

ifndef ORIGIN_ENTER
ORIGIN_ENTER=0
endif

ifndef SIZE
SIZE=0
endif

build:boot func link

boot:init
	$(NASM) -dORIGIN_ENTER=$(ORIGIN_ENTER) -dSIZE=$(SIZE) -dORIGIN_CODE=$(ORIGIN_CODE) -f bin -o boot.bin boot.asm

init:boot.bin func.o
	$(eval TEXESIZE=$(shell $(OBJDUMP) -h func.o|grep .text |awk '{print $$3}'))
	$(eval RODATASIZE =$(shell $(OBJDUMP) -h func.o|grep $(RDATA) |awk '{print $$3}'))
	$(eval SIZE = $(shell ls -l|grep boot.bin |awk '{print $$5}'))
	$(eval HEXTEXESIZE = $(shell  printf %d 0x$(TEXESIZE)))
	$(eval RODATABEGIN =$(shell expr $(HEXTEXESIZE) + 32))
	$(eval HEXRODATABEGIN = 0x$(shell  printf %x $(RODATABEGIN)))
	$(eval LDFLAG = $(if $(RODATASIZE), -m$(LDM) --section-start=.text=0x00 --section-start=$(RDATA)=$(HEXRODATABEGIN) -e _entry -o func.bin func.o , -m$(LDM)  --section-start=.text=0x00 -e _entry -o func.bin func.o))
	$(eval OBJCOPYFLAG = $(if $(RODATASIZE), -O binary -j .text -j $(RDATA) func.bin , -O binary -j .text func.bin))

boot.bin:
	$(NASM) -dORIGIN_ENTER=0xff -dSIZE=0xff -dORIGIN_CODE=0xff,0xff,0xff,0xff,0xff -f bin -o boot.bin boot.asm

func.o:
	$(GCC) -Qn -fno-pie  -m32 -c -o func.o func.c

func:boot
	$(GCC) -Qn -fno-pie  -m32 -c -o func.o func.c
	$(LD)  $(LDFLAG)
	$(OBJCOPY) $(OBJCOPYFLAG)

link:func
	cat boot.bin > inject.bin
	cat func.bin >> inject.bin
