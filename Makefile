CC = /opt/amiga/bin/m68k-amigaos-gcc

CFLAGS = -Iinclude -Isrc -Ithird_party/bearssl/inc -Ithird_party/bearssl/src -Os -Wall -Wextra -fomit-frame-pointer -mcrt=nix13 -m68020 -fno-builtin -DBR_LOMUL=1
LDFLAGS = -mcrt=nix13 -m68020

BUILD = build
LIBOBJS = $(BUILD)/amitls13.o $(BUILD)/socket_os13.o $(BUILD)/http_url.o $(BUILD)/x509_insecure.o $(BUILD)/os13_seed.o
TOOLOBJS = $(BUILD)/amitls13_get.o

BRSRCS = $(shell find third_party/bearssl/src -name '*.c' \
	! -path '*/ssl/ssl_server*' \
	! -path '*/symcipher/*x86ni*' \
	! -path '*/symcipher/*sse2*' \
	! -path '*/symcipher/*pwr8*' \
	! -path '*/rand/sysrng.c' \
	! -path '*/int/i62_*')
BROBJS = $(patsubst third_party/bearssl/src/%.c,$(BUILD)/bearssl/%.o,$(BRSRCS))

.PHONY: all clean

all: $(BUILD)/libamitls13.a $(BUILD)/amitls13_get

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/bearssl/%.o: third_party/bearssl/src/%.c | $(BUILD)
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/amitls13_get.o: tools/amitls13_get.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/libamitls13.a: $(LIBOBJS) $(BROBJS)
	/opt/amiga/bin/m68k-amigaos-ar rcs $@ $(LIBOBJS) $(BROBJS)
	/opt/amiga/bin/m68k-amigaos-ranlib $@

$(BUILD)/amitls13_get: $(TOOLOBJS) $(BUILD)/libamitls13.a
	$(CC) $(LDFLAGS) $(TOOLOBJS) $(BUILD)/libamitls13.a -o $@

clean:
	rm -rf $(BUILD)
