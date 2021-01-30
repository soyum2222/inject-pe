BITS 32

%macro OFFSET 0
	push $
	call getOffsetAddr
%endmacro

%macro BaseAddr 0
	push $
	call getBaseAddr
%endmacro

	jmp Enter

OC:
	db ORIGIN_CODE
	db 0x00

Enter:
	push        ebp
	mov         ebp , esp
	sub         esp , 0x20

	BaseAddr
	mov         [ebp - 0x04] , eax

	OFFSET
	mov         [ebp - 0x08] , eax

;	call        GetKernel32Addr
;	mov         [ebp - 0x0c] , eax
	;PEB
	mov         eax , [fs:0x30]
	mov         [ebp - 0x0c] , eax

    ; do any thing
    mov         eax , OC
    add         eax , [ebp - 0x08]
    push        eax
    push        ORIGIN_ENTER
	mov         ebx , [ebp - 0x08]
	add         ebx , SIZE
	push        ebx
	push 		dword[ebp - 0x04]
	push        dword[ebp - 0x0c]
	mov         eax , SIZE
	add         eax , [ebp - 0x08]
	call        eax


;	push        .name
;	push        dword[ebp - 0x08]
;	push        dword[ebp - 0x0c]
;	call        GetFuncAddress
;	leave
;	ret

    

	mov         eax , [ebp - 0x04]
	add         eax , ORIGIN_ENTER
	leave
	jmp         eax

.name:
    db "CreateDirectoryA"
    db 0x00

; Get memory offset
getOffsetAddr:
    mov         eax , [esp]
    sub         eax , [esp + 0x04]
    sub         eax , 0x0A
    ret         4

; get the PE base address on runtime
; base address value store in eax
getBaseAddr:
	mov         eax , [esp]
	sub         eax , [esp + 0x04]
	sub         eax , NEW_ENTER+0x0A;new entry point +5
	ret         4

; get kernal32 address
; address store in eax
;GetKernel32Addr:
;    mov         eax , [fs:0x030]
;    test        eax , eax
;    js          finished
;    mov         eax , [eax + 0x0c]
;    mov         eax , [eax + 0x14]
;    mov         eax , [eax]
;    mov         eax , [eax]
;    mov         eax , [eax + 0x10]
;    finished:
;    ret

; get NT header
; NT header address store in eax
; arg:    seq     size                offset          des
;           1        4                ebp+0x08        kernel32 base address
GetNTHead:
    push        ebp
    mov         ebp , esp

    mov         eax , [ebp + 0x08]
    mov         eax , [eax + 0x3c]

    leave
    ret         4

;get optionHeader32
;optionHeader32 address store in eax
; arg:      seq        size                offset             des
;              1          4                ebp+0x08           kernel32 base address
GetOptHeater32:
    push ebp
    mov         ebp , esp

    push         dword[ebp + 0x08]
    call         GetNTHead
    add         eax , 0x18

    leave
    ret         4

; get data dir address
; address store in eax
; arg:      seq        size                offset             des
;              1          4                ebp+0x08           kernel32 base address
GetDataDir:
    push        ebp
    mov         ebp , esp

    push         dword[ebp + 0x08]
    call         GetOptHeater32
    add         eax , 0x60

    leave
    ret         4

; get export dir
; export dir address store in eax
; arg:      seq        size                offset             des
;              1          4                ebp+0x08           kernel32 base address
GetExportDir:
    push         ebp
    mov          ebp , esp

    push         dword[ebp + 0x08]
    call         GetDataDir
    mov          ebx , eax
    add          ebx , [ebp + 0x08]
    mov          ebx , [ebx]
    add          ebx , [ebp + 0x08]
    mov          eax , ebx

    leave
    ret          4


; get function address width kernel32 export dir
; return value store in eax
; arg:    seq        size            offset            des
;           1        4               ebp+0x08          kernel32 base address
;           2        4               ebp+0x0c          base offset
;           3        4               ebp+0x10          function name
GetFuncAddress:
    push         ebp
    mov          ebp , esp
    sub          esp , 0x20


    push         dword[ebp+0x08]
    call         GetExportDir

    mov          ebx , [eax + 0x24]
    mov          [ebp - 0x04] , ebx                ; push function order
    mov          ebx , [eax + 0x18]
    mov          [ebp - 0x08] , ebx                ; push number of functions in esp
    mov          ebx , [eax + 0x20]
    mov          [ebp - 0x0c] , ebx                ; push address of names in esp
    mov          ebx , [eax + 0x1c]
    mov          [ebp - 0x10] , ebx                ; push address of functions in esp

    mov          ecx , 0x00
    mov          [ebp - 0x14] , ecx                ; a loop counter
.loop1:

    mov          eax , [ebp - 0x14]
    cmp          eax , [ebp - 0x08]
    jnb          .break1

    mov          eax , [ebp - 0x14]                ; mov loop counter to eax
    imul         eax , 0x04
    add          eax , [ebp - 0x0c]                ; get ENT offset
    add          eax , [ebp + 0x08]                ; add kernel32 base address
    mov          eax , [eax]                       ; get ENT offset

    mov          [ebp - 0x18] , eax                ; push ENT offset

    mov          eax , 0x00
    mov          [ebp - 0x1c] , eax                ; push loop2 counter
.loop2:

    mov          eax , [ebp - 0x18]                ; add ENT offset
    add          eax , [ebp + 0x08]                ; add kernel32 base address
    add          eax , [ebp - 0x1c]
    mov          bl, byte[eax]                     ; get a char

    mov          ecx , [ebp + 0x10]                ; function name
    add          ecx , [ebp + 0x0c]
    add          ecx , [ebp - 0x1c]
    mov          cl  , byte[ecx]

    cmp          bl  , cl
    jne          .break2

    cmp          bl  , 0x00
    je           .addr

    mov          eax , [ebp - 0x1c]
    inc          eax
    mov          [ebp - 0x1c] , eax
    jmp          .loop2

.break2:
    mov          eax , [ebp - 0x14]
    inc          eax
    mov          [ebp - 0x14] , eax
    jmp          .loop1

.break1:
    jmp          .ret

.addr:
    mov          eax , [ebp - 0x14]
    imul         eax , 0x02

    add          eax , [ebp - 0x04]         ; add offset push function order
    add          eax , [ebp + 0x08]         ; add kernel base
    mov          bx  , word[eax]
    mov          eax , 0x00000000
    mov          ax  , bx

    imul         eax , 0x04
    add          eax , [ebp - 0x10]
    add          eax , [ebp + 0x08]
    mov          eax , [eax]
    jmp          .ret

.ret:
    leave
    ret 12


