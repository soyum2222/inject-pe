ifdef OS
	GO=go.exe
else
	GO=go
endif

inject:init
ifeq ($(ARCH),x86)
	cd x86 && NEW_ENTER=0x$(NEW_ENTER) ORIGIN_ENTER=0x$(ORIGIN_ENTER) make
	./editPE.exe -inject -i ./x86/inject.bin -f $(FILE) -o ./a.exe
else
	cd x64 && NEW_ENTER=0x$(NEW_ENTER) ORIGIN_ENTER=0x$(ORIGIN_ENTER) make
	./editPE.exe -inject -i ./x64/inject.bin -f $(FILE) -o ./a.exe
endif



init:editPE.exe
	$(eval NEW_ENTER=$(shell ./editPE.exe -ne -hex -f $(FILE)))
	$(eval ORIGIN_ENTER=$(shell ./editPE.exe -e -hex -f $(FILE)))
	$(eval ARCH=$(shell ./editPE.exe -arch -f $(FILE)))

editPE.exe:
	cd tool && $(GO) build -o ../editPE.exe editPE.go

clean:
	rm -r ./x64/*.bin
	rm -r ./x64/*.o
	rm -r ./x86/*.bin
	rm -r ./x86/*.o
