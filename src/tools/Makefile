# Builds the userland test tools (Linux or Haiku).
CXX ?= g++
CXXFLAGS ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
CORE := ../smb2/Crypto.cpp ../smb2/Platform.cpp ../smb2/Utf.cpp \
	../smb2/NtStatus.cpp ../smb2/Ntlm.cpp ../smb2/Connection.cpp
OBJDIR ?= objects
CORE_OBJS := $(patsubst ../smb2/%.cpp,$(OBJDIR)/%.o,$(CORE))

UNAME := $(shell uname -s)
ifeq ($(UNAME),Haiku)
LIBS := -lnetwork
else
LIBS := -lpthread
endif

all: $(OBJDIR)/smbtest $(OBJDIR)/crypto_test

$(OBJDIR)/%.o: ../smb2/%.cpp ../smb2/*.h
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(OBJDIR)/smbtest: smbtest.cpp $(CORE_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ smbtest.cpp $(CORE_OBJS) $(LIBS)

$(OBJDIR)/crypto_test: crypto_test.cpp $(OBJDIR)/Crypto.o
	$(CXX) $(CXXFLAGS) -o $@ crypto_test.cpp $(OBJDIR)/Crypto.o

clean:
	rm -rf $(OBJDIR)

.PHONY: all clean
