ifdef OS
	GO=go.exe
else
	GO=go
endif

inject:editPE.exe
	$(eval NEW_ENTER=$(shell ./editPE.exe -ne -hex -f $(FILE)))
	$(eval ORIGIN_ENTER=$(shell ./editPE.exe -e -hex -f $(FILE)))
	$(eval ARCH=$(shell ./editPE.exe -arch -f $(FILE)))



	#echo $(NEW_ENTER)
	#echo $(ORIGIN_ENTER)
	#echo $(ARCH)

editPE.exe:
	cd tool && $(GO) build -o ../editPE.exe editPE.go