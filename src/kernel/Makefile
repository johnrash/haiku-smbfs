# Makefile for the smbfs kernel file system add-on. Build natively on Haiku.
NAME := smbfs
OBJDIR ?= objects
HEADERS := /boot/system/develop/headers

CORE_SRCS := Crypto.cpp Platform.cpp Utf.cpp NtStatus.cpp Ntlm.cpp \
	Connection.cpp
FS_SRCS := kernel_interface.cpp Volume.cpp Inode.cpp MimeTypes.cpp

OBJS := $(patsubst %.cpp,$(OBJDIR)/%.o,$(FS_SRCS)) \
	$(patsubst %.cpp,$(OBJDIR)/core_%.o,$(CORE_SRCS))

CXX := g++
CXXFLAGS := -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-multichar \
	-D_KERNEL_MODE=1 -ffreestanding -finline -fno-semantic-interposition \
	-fno-tree-vectorize -fno-exceptions -fno-use-cxa-atexit -fpic \
	-mno-red-zone -fno-omit-frame-pointer \
	-Iinclude -I$(HEADERS)/private -I$(HEADERS)/private/kernel \
	-I$(HEADERS)/private/kernel/arch/x86 -I$(HEADERS)/private/shared \
	-I$(HEADERS)/private/system -I$(HEADERS)/private/system/arch/x86_64
LDFLAGS := -shared -nostdlib -Xlinker --no-undefined \
	-Xlinker -soname=$(NAME) -z max-page-size=0x1000
KERNEL_LIB := /boot/system/develop/lib/_KERNEL_

INSTALL_DIR ?= /boot/system/non-packaged/add-ons/kernel/file_systems

all: $(OBJDIR)/$(NAME)

$(OBJDIR)/$(NAME): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(KERNEL_LIB)

$(OBJDIR)/%.o: %.cpp *.h ../smb2/*.h include/*.h
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OBJDIR)/core_%.o: ../smb2/%.cpp ../smb2/*.h include/*.h
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

install: $(OBJDIR)/$(NAME)
	mkdir -p $(INSTALL_DIR)
	cp $(OBJDIR)/$(NAME) $(INSTALL_DIR)/$(NAME)

clean:
	rm -rf $(OBJDIR)

.PHONY: all install clean
