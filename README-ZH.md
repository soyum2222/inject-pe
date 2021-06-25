# inject-pe

# 介绍
	一个利用GCC生成windows平台的shellcode的工程.

	在windows PE 文件中,植入自定义代码,就像shellcode一样.
	
	工具会根据目标PE文件的arch类型,去编译x86/x64文件夹中的boot.asm 和 func.c文件,成为位置无关的shellcode.
	
	并植入到目标PE文件中,然后修改目标文件的entry point.指向到shellcode位置.执行完成后,跳转回PE源文件的位子.
	
# 使用
	首先请确认已经安装以下工具
	
	
* Mingw-w64
* MAKE
* NASM
* GOLANG


   	如果你是在 windows 上使用这套工具,那么需要使用 `bash cmd` , 比如 `git bash` 因为makefile中会使用到一些shell指令.


   在终端输入:
```
    FILE=./PE.exe make
```
    ./PE.exe 是被注入的PE文件.
    完成注入后得到a.exe.

# 编辑func.c
如果想要加入你自定义的逻辑,可以通过编写func.c文件.入口方法为

`DWORD entry(DWORD pebAddr ,DWORD baseAddress,DWORD offset ,DWORD originEntry,char * originCode)`

	pebAddr: windows peb 的首地址
	baseAddress: 程序运行时的基地址
	offset: 与基地址的偏移量
	originEntry: 原始程序的入口地址
	originCode: 原始入口点指令

注意:编写的代码内存必须在栈上分配.
