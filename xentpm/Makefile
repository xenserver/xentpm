VERSION = $(PRODUCT_VERSION)
RELEASE = 1

RPMROOT := $(shell pwd)

NAME := xentpm
COMPONENT_VERSION := 1.0.0
XENTPM_DIR := $(shell pwd)
SPEC := $(NAME).spec
SRC_TAR :=  $(NAME).tar.gz
SRC := $(NAME).tar.gz
SRCV := $(NAME)-$(COMPONENT_VERSION)

.PHONY: build
build: 
	[ -d $(RPMROOT)/BUILD ] || mkdir -p $(RPMROOT)/BUILD
	[ -d $(RPMROOT)/SOURCES ] || mkdir -p $(RPMROOT)/SOURCES
	cp -r $(NAME) $(SRCV) 
	tar -czf $(XENTPM_DIR)/SOURCES/$(SRC) $(SRCV) 	
	cp $(SPEC) SOURCES/

.PHONY: clean
clean:
	rm -rf BUILD
	rm -rf SOURCES
	rm -rf $(SRCV)

.PHONY: sources
sources:
