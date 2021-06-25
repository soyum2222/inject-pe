ifdef OS
	GO=go.exe
else
	GO=go
endif

inject:init
	cd $(ARCH) && ORIGIN_ENTER=0x$(ORIGIN_ENTER) ORIGIN_CODE=$(ORIGIN_CODE) make
	./editPE.exe -inject -i ./$(ARCH)/inject.bin -f $(FILE) -o ./a.exe

init:editPE.exe
	#$(eval NEW_ENTER=$(shell ./editPE.exe -ne -hex -f $(FILE)))
	$(eval ORIGIN_ENTER=$(shell ./editPE.exe -e -hex -f $(FILE)))
	$(eval ORIGIN_CODE=$(shell ./editPE.exe -c -hex -f $(FILE)))
	$(eval ARCH=$(shell ./editPE.exe -arch -f $(FILE)))
	echo $(ORIGIN_CODE)

editPE.exe:
	cd tool && $(GO) build -o ../editPE.exe editPE.go

clean:
	-rm -r ./x64/*.bin
	-rm -r ./x64/*.o
	-rm -r ./x86/*.bin
	-rm -r ./x86/*.o
