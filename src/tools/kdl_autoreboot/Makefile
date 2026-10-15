# Kernel debugger add-on: reboots automatically after a kernel panic (for
# unattended test machines). Build natively on Haiku.
NAME := kdl_autoreboot
OBJDIR ?= objects
HEADERS := /boot/system/develop/headers
CXX := g++
CXXFLAGS := -O2 -Wall -Wextra -Wno-unused-parameter -Wno-multichar \
	-D_KERNEL_MODE=1 -ffreestanding -finline -fno-semantic-interposition \
	-fno-tree-vectorize -fno-exceptions -fno-use-cxa-atexit -fpic \
	-mno-red-zone -fno-omit-frame-pointer \
	-I../../kernel/include -I$(HEADERS)/private -I$(HEADERS)/private/kernel \
	-I$(HEADERS)/private/kernel/arch/x86 -I$(HEADERS)/private/shared \
	-I$(HEADERS)/private/system -I$(HEADERS)/private/system/arch/x86_64
LDFLAGS := -shared -nostdlib -Xlinker --no-undefined \
	-Xlinker -soname=$(NAME) -z max-page-size=0x1000
KERNEL_LIB := /boot/system/develop/lib/_KERNEL_
INSTALL_DIR ?= /boot/home/config/non-packaged/add-ons/kernel/debugger

all: $(OBJDIR)/$(NAME)

$(OBJDIR)/$(NAME): $(NAME).cpp
	@mkdir -p $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c -o $(OBJDIR)/$(NAME).o $(NAME).cpp
	$(CXX) $(LDFLAGS) -o $@ $(OBJDIR)/$(NAME).o $(KERNEL_LIB)

install: $(OBJDIR)/$(NAME)
	mkdir -p $(INSTALL_DIR)
	cp $(OBJDIR)/$(NAME) $(INSTALL_DIR)/$(NAME)

uninstall:
	rm -f $(INSTALL_DIR)/$(NAME)

clean:
	rm -rf $(OBJDIR)

.PHONY: all install uninstall clean
