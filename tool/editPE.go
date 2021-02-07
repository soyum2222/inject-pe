package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/soyum2222/editPE"
	"io/ioutil"
	"os"
)

func main() {
	var (
		f      string
		arch   bool
		inject bool
		o      string
		i      string
		e      bool
		hex    bool
		ne     bool
		code   bool
	)

	flag.StringVar(&f, "f", "", "PE file path")
	flag.BoolVar(&arch, "arch", false, "check pe file arch")
	flag.BoolVar(&inject, "inject", false, "inject a file")
	flag.StringVar(&o, "o", "", "out put file path")
	flag.StringVar(&i, "i", "", "binary file path")
	flag.BoolVar(&e, "e", false, "entry point")
	flag.BoolVar(&code, "c", false, "entry point")
	flag.BoolVar(&hex, "hex", false, "print hexadecimal")
	flag.BoolVar(&ne, "ne", false, "new entry point")
	flag.Parse()

	if ne {
		desFile, err := ioutil.ReadFile(f)
		if err != nil {
			panic(err)
		}

		pe := editPE.PE{}
		pe.Parse(desFile)

		tail := len(pe.ImageSectionHeaders) - 1

		pe.ImageSectionHeaders[tail].SizeOfRawData = uint32(len(pe.Raw)) - pe.ImageSectionHeaders[tail].PointerToRawData
		pe.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize = pe.ImageSectionHeaders[tail].SizeOfRawData
		pe.ImageSectionHeaders[tail].Characteristics = pe.ImageSectionHeaders[tail].Characteristics | (1 << 29)

		jmpOffset := pe.ImageSectionHeaders[tail].VirtualAddress + pe.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize

		if hex {
			fmt.Printf("%x\n", jmpOffset)
		} else {
			fmt.Println(jmpOffset)
		}
	}

	if e {
		desFile, err := ioutil.ReadFile(f)
		if err != nil {
			panic(err)
		}
		pe := editPE.PE{}
		pe.Parse(desFile)
		var origin uint32
		switch pe.ImageNTHeaders.FileHeader.SizeOfOptionalHeader {
		case editPE.SIZE_OF_OPTIONAL_HEADER_32:
			origin = pe.ImageOptionalHeader32.AddressOfEntryPoint

		case editPE.SIZE_OF_OPTIONAL_HEADER_64:
			origin = pe.ImageOptionalHeader64.AddressOfEntryPoint
		}

		if hex {
			fmt.Printf("%x\n", origin)
		} else {
			fmt.Println(origin)
		}
		return
	}

	if code {
		desFile, err := ioutil.ReadFile(f)
		if err != nil {
			panic(err)
		}
		pe := editPE.PE{}
		pe.Parse(desFile)
		var origin uint32
		switch pe.ImageNTHeaders.FileHeader.SizeOfOptionalHeader {
		case editPE.SIZE_OF_OPTIONAL_HEADER_32:
			origin = pe.ImageOptionalHeader32.AddressOfEntryPoint

		case editPE.SIZE_OF_OPTIONAL_HEADER_64:
			origin = pe.ImageOptionalHeader64.AddressOfEntryPoint
		}

		originCode := make([]byte, 5)
		origin = editPE.RVAToOffset(origin, pe.Raw)
		for i := origin; i < origin+5; i++ {
			originCode[i-origin] = pe.Raw[i]
		}

		if hex {
			for _, v := range originCode {
				fmt.Printf("0x%x,", v)
			}
		} else {
			for _, v := range originCode {
				fmt.Printf("0x%d,", v)
			}
		}
	}

	if inject {
		desFile, err := ioutil.ReadFile(f)
		if err != nil {
			panic(err)
		}

		injectFile, err := ioutil.ReadFile(i)
		if err != nil {
			panic(err)
		}

		of, err := os.Create(o)
		if err != nil {
			panic(err)
		}

		pe := editPE.PE{}
		pe.Parse(desFile)

		tail := len(pe.ImageSectionHeaders) - 1
		pe.Raw = append(pe.Raw, injectFile...)
		pe.Parse(pe.Raw)

		var origin uint32
		switch pe.ImageNTHeaders.FileHeader.SizeOfOptionalHeader {
		case editPE.SIZE_OF_OPTIONAL_HEADER_32:
			origin = pe.ImageOptionalHeader32.AddressOfEntryPoint
		case editPE.SIZE_OF_OPTIONAL_HEADER_64:
			origin = pe.ImageOptionalHeader64.AddressOfEntryPoint
		}

		//originSize := pe.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize
		pe.ImageSectionHeaders[tail].SizeOfRawData = uint32(len(pe.Raw)) - pe.ImageSectionHeaders[tail].PointerToRawData
		pe.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize = pe.ImageSectionHeaders[tail].SizeOfRawData
		pe.ImageSectionHeaders[tail].Characteristics = pe.ImageSectionHeaders[tail].Characteristics | (1 << 29)

		if pe.ImageOptionalHeader32 != nil {
			pe.ImageOptionalHeader32.SizeOfImage += 0x2000
		} else {
			pe.ImageOptionalHeader64.SizeOfImage += 0x2000
		}

		//jmpOffset := entry - (origin + 0x05)
		//jmpOffset := uint32(editPE.Offset2VA(uint32(len(pe.Raw)-len(injectFile)), pe.Raw))
		jmpOffset := (pe.ImageSectionHeaders[tail].VirtualAddress + pe.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize) - uint32(len(injectFile))
		jmpOffset = jmpOffset - (origin + 0x05)
		code := make([]byte, 4)
		binary.LittleEndian.PutUint32(code, jmpOffset)

		code = append([]byte{0xe9}, code...)
		originCode := make([]byte, 5)
		origin = editPE.RVAToOffset(origin, pe.Raw)
		for i := origin; i < origin+5; i++ {
			originCode[i-origin] = pe.Raw[i]
			pe.Raw[i] = code[i-origin]
		}

		if hex {
			for _, v := range code {
				fmt.Printf("0x%x,", v)
			}
		} else {
			for _, v := range code {
				fmt.Printf("0x%d,", v)
			}
		}

		_, err = of.Write(pe.Raw)
		if err != nil {
			panic(err)
		}
		return
	}

	if arch {
		file, err := ioutil.ReadFile(f)
		if err != nil {
			panic(err)
		}
		pe := editPE.PE{}
		pe.Parse(file)
		switch pe.ImageNTHeaders.FileHeader.SizeOfOptionalHeader {
		case editPE.SIZE_OF_OPTIONAL_HEADER_32:
			fmt.Print("x86\n")
			return
		case editPE.SIZE_OF_OPTIONAL_HEADER_64:
			fmt.Print("x64\n")
			return
		}
	}
}
