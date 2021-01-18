GCC =gcc
LD =ld
NASM =nasm
OBJCOPY =objcopy

boot:
ifeq ($(NEW_ENTER), )
		$(NASM) -dNEW_ENTER=0 -dORIGIN_ENTER=0 -dSIZE=398 -f bin -o boot.bin boot.asm
else
		$(NASM) -dNEW_ENTER=$(NEW_ENTER) -dORIGIN_ENTER=$(ORIGIN_ENTER) -dSIZE=398 -f bin -o boot.bin boot.asm
endif

func:
	$(GCC) -fno-pie -m32 -c -o func.o func.c
	$(LD)  -melf_386 -Ttext 0x00 -Trodata 0x100 -e entry -o func.bin func.o
	$(OBJCOPY) -O binary -j .text -j .rodata func.bin

link:func boot
	cat boot.bin > inject.bin
	cat func.bin >> inject.bin

clean:
	rm func.o | rm inject.bin |rm func.bin |rm boot.bin