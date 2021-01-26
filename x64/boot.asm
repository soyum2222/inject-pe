BITS 64


%macro OFFSET 0
	push $
	call getOffsetAddr
%endmacro

%macro BaseAddr 0
	push $
	call getBaseAddr
%endmacro


	jmp ENTRY

ENTRY:

	push        rbp
	mov         rbp , rsp
	sub         rsp , 0x40

	BaseAddr
	mov         [rbp - 0x08] , rax

	OFFSET
	mov         [rbp - 0x10] , rax

	; get PEB address
	mov         rax , [gs:0x60]
	mov         [rbp - 0x18] , rax

    ; do any thing
    ; for abi
	mov         r8  , qword[rbp - 0x10]
	mov         rdx , qword[rbp - 0x08]
	mov         rcx , qword[rbp - 0x18]
	mov         rax , SIZE
	add         rax , [rbp - 0x10]
	call        rax

	mov         rax , [rbp - 0x08]
	add         rax , ORIGIN_ENTER
	leave
	jmp         rax

; Get memory offset
getOffsetAddr:
    mov         rax , [rsp]
    sub         rax , [rsp + 0x08]
    sub         rax , 0x0A
    ret         8

; get the PE base address on runtime
; base address value store in eax
getBaseAddr:
	mov         rax , [rsp]
	sub         rax , [rsp + 0x08]
	sub         rax , NEW_ENTER+0x0A;new entry point +10
	ret         8
