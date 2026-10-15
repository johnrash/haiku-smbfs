# Builds the userland host for the smbfs kernel add-on (Linux/Haiku userland).
CXX ?= g++
SAN ?= -fsanitize=address,undefined
CXXFLAGS ?= -O1 -g -Wall -Wno-unused-parameter -fno-omit-frame-pointer $(SAN) \
	-D_FILE_OFFSET_BITS=64 -include include/haiku_compat.h -Iinclude
OBJDIR ?= objects
CORE := Crypto Platform Utf NtStatus Ntlm Connection
FS := kernel_interface Volume Inode MimeTypes
OBJS := $(patsubst %,$(OBJDIR)/core_%.o,$(CORE)) $(patsubst %,$(OBJDIR)/fs_%.o,$(FS)) $(OBJDIR)/fshost.o

all: $(OBJDIR)/fshost

$(OBJDIR)/fshost: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) -lpthread

$(OBJDIR)/core_%.o: ../../smb2/%.cpp ../../smb2/*.h
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OBJDIR)/fs_%.o: ../../kernel/%.cpp ../../kernel/*.h ../../smb2/*.h include/*.h
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OBJDIR)/fshost.o: fshost.cpp include/*.h ../../kernel/*.h
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -rf $(OBJDIR)

.PHONY: all clean
