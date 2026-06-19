CC = /opt/amiga/bin/m68k-amigaos-gcc
AR ?= /opt/amiga/bin/m68k-amigaos-ar
RANLIB ?= /opt/amiga/bin/m68k-amigaos-ranlib

CFLAGS = -Iinclude -Isrc -Os -Wall -Wextra -fomit-frame-pointer -mcrt=nix13 -m68020 -fno-builtin
LDFLAGS = -mcrt=nix13 -m68020

BUILD = build
LIBOBJS = $(BUILD)/amitls13.o $(BUILD)/socket_os13.o $(BUILD)/http_url.o
TOOLOBJS = $(BUILD)/amitls13_get.o

.PHONY: all clean

all: $(BUILD)/libamitls13.a $(BUILD)/amitls13_get

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/amitls13_get.o: tools/amitls13_get.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/libamitls13.a: $(LIBOBJS)
	/opt/amiga/bin/m68k-amigaos-ar rcs $@ $(LIBOBJS)
	/opt/amiga/bin/m68k-amigaos-ranlib $@

$(BUILD)/amitls13_get: $(TOOLOBJS) $(BUILD)/libamitls13.a
	$(CC) $(LDFLAGS) $(TOOLOBJS) $(BUILD)/libamitls13.a -o $@

clean:
	rm -rf $(BUILD)
