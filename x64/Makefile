ifdef OS
	GCC =gcc.exe
	LD =ld.exe
	NASM =nasm.exe
	OBJCOPY =objcopy.exe
	OBJDUMP =objdump.exe
	BOOTSIZE =0
	RDATA =.rdata
else
	GCC =x86_64-w64-mingw32-gcc
	LD =x86_64-w64-mingw32-ld
	NASM =nasm
	OBJCOPY =x86_64-w64-mingw32-objcopy
	OBJDUMP =x86_64-w64-mingw32-objdump
	BOOTSIZE =0
	RDATA =.rdata
endif

ifndef NEW_ENTER
NEW_ENTER=0
endif

ifndef ORIGIN_ENTER
ORIGIN_ENTER=0
endif

ifndef SIZE
SIZE=0
endif

build:boot func link

boot: init
	$(NASM) -dNEW_ENTER=$(NEW_ENTER) -dORIGIN_ENTER=$(ORIGIN_ENTER) -dSIZE=$(SIZE) -f bin -o boot.bin boot.asm

init:boot.bin func.o
	$(eval TEXESIZE=$(shell $(OBJDUMP) -h func.o|grep .text |awk '{print $$3}'))
	$(eval RODATASIZE =$(shell $(OBJDUMP) -h func.o|grep $(RDATA) |awk '{print $$3}'))
	$(eval SIZE = $(shell ls -l|grep boot.bin |awk '{print $$5}'))
	$(eval HEXTEXESIZE = $(shell  printf %d 0x$(TEXESIZE)))
	$(eval RODATABEGIN =$(shell expr $(HEXTEXESIZE) + 32))
	$(eval HEXRODATABEGIN = 0x$(shell  printf %x $(RODATABEGIN)))
	$(eval LDFLAG = $(if $(RODATASIZE), --section-start=.text=0x00 --section-start=$(RDATA)=$(HEXRODATABEGIN) -e entry -o func.bin func.o , --section-start=.text=0x00 -e entry -o func.bin func.o))
	$(eval OBJCOPYFLAG = $(if $(RODATASIZE), -O binary -j .text -j $(RDATA) func.bin , -O binary -j .text func.bin))


boot.bin:
	$(NASM) -dNEW_ENTER=0xff -dORIGIN_ENTER=0xff -dSIZE=0xff -f bin -o boot.bin boot.asm

func.o:
	$(GCC) -fno-pie -m32 -c -o func.o func.c

func:boot.bin
	$(GCC) -fno-stack-protector -fno-pie -m64 -c -o func.o func.c
	$(LD)  $(LDFLAG)
	$(OBJCOPY) $(OBJCOPYFLAG)

link:func.bin
	cat boot.bin > inject.bin
	cat func.bin >> inject.bin
