include ../common/env.mk
include ../common/rpmenv.mk
include ../common/versioning.mk

VERSION = $(PRODUCT_VERSION)
RELEASE = 1

RPMROOT := $(shell pwd)
RPMS_DIR = $(RPMROOT)/output/RPMS
SRPMS_DIR = $(RPMROOT)/output/SRPMS

NAME := xentpm
COMPONENT_VERSION := 1.0.0
SPEC := $(NAME).spec
SRC := $(NAME)-$(COMPONENT_VERSION).tar.gz
SRPM := $(NAME)-$(COMPONENT_VERSION)-$(RELEASE).src.rpm
RPM := $(NAME)-$(COMPONENT_VERSION)-$(RELEASE).rpm
SRCV := $(NAME)-$(COMPONENT_VERSION)

RPM_BUILT_COOKIE = $(RPMROOT)/BUILD/.rpm_built_cookie

.PHONY: build
build: $(RPM_BUILT_COOKIE)
 @ :

$(RPM_BUILT_COOKIE):
	[ -d $(RPMS_DIR) ] || mkdir -p $(RPMS_DIR)
	[ -d $(SRPMS_DIR) ] || mkdir -p $(SRPMS_DIR)
	[ -d $(RPMROOT)/BUILD ] || mkdir -p $(RPMROOT)/BUILD
	[ -d $(RPMROOT)/SOURCES ] || mkdir -p $(RPMROOT)/SOURCES
	cp -r $(NAME) $(SRCV)
	tar -czf SOURCES/$(SRC) $(SRCV)
	cp $(SPEC) SOURCES
	$(RPMBUILD) -ba --define "version $(COMPONENT_VERSION)"  --define "release $(RELEASE)" --define "_rpmdir $(RPMS_DIR)" --define "_sourcedir $(RPMROOT)/SOURCES" --define "_srcrpmdir $(SRPMS_DIR)" --define "_builddir $(RPMROOT)/BUILD" --define "trousers_dir $(RPMROOT)/trousers" SOURCES/$(SPEC)

.PHONY: clean
clean:
	rm -rf BUILD
	rm -rf SOURCES
	rm -rf $(SRCV)
	rm -rf output
	rm -rf obj

.PHONY: sources
sources:
