ifdef OS
	GCC =gcc.exe
	LD =ld.exe
	NASM =nasm.exe
	OBJCOPY =objcopy.exe
	BOOTSIZE =0

#	LDFLAG =-melf_386 -Ttext 0x00 -Trodata 0x100 -e entry -o func.bin func.o
else
	GCC =gcc
	LD =ld
	NASM =nasm
	OBJCOPY =objcopy
	a=$(shell nasm -dNEW_ENTER=0xff -dORIGIN_ENTER=0xff -dSIZE=0xff -f bin -o boot.bin boot.asm)
	b=$(shell gcc -fno-pie -m32 -c -o func.o func.c)

	ifeq ($(a),)
		ifeq ($(b),)
			TEXESIZE =$(shell objdump -h func.o|grep .text |awk '{print $$3}')
			RODATASIZE =$(shell objdump -h func.o|grep .rodata |awk '{print $$3}')
			SIZE = $(shell ls -l|grep boot.bin |awk '{print $$5}')
		endif
	endif


	ifeq ($(RODATASIZE),)
		LDFLAG =-melf_i386 -Ttext 0x00 -e entry -o func.bin func.o
		OBJCOPYFLAG =-O binary -j .text func.bin
	else
		HEXTEXESIZE = $(shell  printf %d 0x$(TEXESIZE))
		RODATABEGIN =$(shell expr $(HEXTEXESIZE) + 16)
		HEXRODATABEGIN = 0x$(shell  printf %x $(RODATABEGIN))
		LDFLAG =-melf_i386 -Ttext 0x00 -Trodata $(HEXRODATABEGIN) -e entry -o func.bin func.o
		OBJCOPYFLAG =-O binary -j .text -j .rodata func.bin
	endif

endif

build:boot func link


boot:
ifeq ($(NEW_ENTER), )
	$(NASM) -dNEW_ENTER=0 -dORIGIN_ENTER=0 -dSIZE=$(SIZE) -f bin -o boot.bin boot.asm
else
	$(NASM) -dNEW_ENTER=$(NEW_ENTER) -dORIGIN_ENTER=$(ORIGIN_ENTER) -dSIZE=$(SIZE) -f bin -o boot.bin boot.asm
endif

func:boot.bin
	$(GCC) -fno-pie -m32 -c -o func.o func.c
	$(LD)  $(LDFLAG)
	$(OBJCOPY) $(OBJCOPYFLAG)

link:func.bin
	cat boot.bin > inject.bin
	cat func.bin >> inject.bin

clean:
	rm func.o inject.bin func.bin boot.bin

