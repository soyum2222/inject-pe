GCC=gcc
LD =ld
NASM =nasm

boot:
ifeq ($(NEW_ENTER), )
		$(NASM) -dNEW_ENTER=0 -dORIGIN_ENTER=0 -dSIZE=392 -f bin -o boot.bin boot.asm
else
		$(NASM) -dNEW_ENTER=$(NEW_ENTER) -dORIGIN_ENTER=$(ORIGIN_ENTER) -dSIZE=392 -f bin -o boot.bin boot.asm
endif

func:
	$(GCC) -c func.c -o func.o
	$(LD) -Ttext 0x00 -e entry -o func.bin --oformat binary func.o

link:func boot
	cat boot.bin > inject.bin
	cat func.bin >> inject.bin
