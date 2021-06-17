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
