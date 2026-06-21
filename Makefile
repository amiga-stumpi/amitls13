CC = /opt/amiga/bin/m68k-amigaos-gcc
AR = /opt/amiga/bin/m68k-amigaos-ar
RANLIB = /opt/amiga/bin/m68k-amigaos-ranlib

TRACE ?= 0
DEBUG ?= 0

CFLAGS = -Iinclude -Isrc -Ithird_party/bearssl/inc -Ithird_party/bearssl/src -Os -Wall -Wextra -fomit-frame-pointer -mcrt=nix13 -m68020 -fno-builtin -DBR_LOMUL=1
SDKCFLAGS = -Isdk/include -Os -Wall -Wextra -fomit-frame-pointer -mcrt=nix13 -m68020 -fno-builtin
ifeq ($(TRACE),1)
CFLAGS += -DAMITLS13_TRACE=1
endif
ifeq ($(DEBUG),1)
CFLAGS += -DAMITLS13_DEBUG=1
endif
LDFLAGS = -mcrt=nix13 -m68020
LIBLDFLAGS = -mcrt=nix13 -m68020 -nostartfiles

BUILD = build
COREOBJS = $(BUILD)/amitls13.o $(BUILD)/socket_os13.o $(BUILD)/socket_os13_stubs.o $(BUILD)/http_url.o $(BUILD)/x509_insecure.o $(BUILD)/os13_seed.o
LIBRARYOBJS = $(COREOBJS) $(BUILD)/amitls13_library.o $(BUILD)/amitls13_library_stubs.o
TOOLOBJS = $(BUILD)/amitls13_get.o
LIBTOOLOBJS = $(BUILD)/amitls13_get_lib.o $(BUILD)/amitls13_client_stubs.o
OPENCLOSEOBJS = $(BUILD)/amitls13_openclose.o
REPEATTOOLOBJS = $(BUILD)/amitls13_repeat_get_lib.o $(BUILD)/amitls13_client_stubs.o
SDKEXAMPLEOBJS = $(BUILD)/amitls13_example_get.o $(BUILD)/sdk_amitls13_client_stubs.o

BRSRCS = $(shell find third_party/bearssl/src -name '*.c' \
	! -path '*/ssl/ssl_server*' \
	! -path '*/symcipher/*x86ni*' \
	! -path '*/symcipher/*sse2*' \
	! -path '*/symcipher/*pwr8*' \
	! -path '*/rand/sysrng.c' \
	! -path '*/int/i62_*')
BROBJS = $(patsubst third_party/bearssl/src/%.c,$(BUILD)/bearssl/%.o,$(BRSRCS))

.PHONY: all clean trace debug

all: $(BUILD)/libamitls13.a $(BUILD)/amitls13.library $(BUILD)/amitls13_get $(BUILD)/amitls13_get_lib $(BUILD)/amitls13_openclose $(BUILD)/amitls13_repeat_get_lib $(BUILD)/amitls13_example_get

trace:
	$(MAKE) clean
	$(MAKE) TRACE=1 all

debug:
	$(MAKE) clean
	$(MAKE) TRACE=1 DEBUG=1 all

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: src/%.S | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/bearssl/%.o: third_party/bearssl/src/%.c | $(BUILD)
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/amitls13_get.o: tools/amitls13_get.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/amitls13_get_lib.o: tools/amitls13_get_lib.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/amitls13_openclose.o: tools/amitls13_openclose.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/amitls13_repeat_get_lib.o: tools/amitls13_repeat_get_lib.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/amitls13_example_get.o: sdk/examples/amitls13_example_get.c | $(BUILD)
	$(CC) $(SDKCFLAGS) -c $< -o $@

$(BUILD)/sdk_amitls13_client_stubs.o: sdk/amitls13_client_stubs.S | $(BUILD)
	$(CC) $(SDKCFLAGS) -c $< -o $@

$(BUILD)/libamitls13.a: $(COREOBJS) $(BROBJS)
	$(AR) rcs $@ $(COREOBJS) $(BROBJS)
	$(RANLIB) $@

$(BUILD)/amitls13.library: $(LIBRARYOBJS) $(BROBJS)
	$(CC) $(LIBLDFLAGS) $(LIBRARYOBJS) $(BROBJS) -o $@

$(BUILD)/amitls13_get: $(TOOLOBJS) $(BUILD)/libamitls13.a
	$(CC) $(LDFLAGS) $(TOOLOBJS) $(BUILD)/libamitls13.a -o $@

$(BUILD)/amitls13_get_lib: $(LIBTOOLOBJS)
	$(CC) $(LDFLAGS) $(LIBTOOLOBJS) -o $@

$(BUILD)/amitls13_openclose: $(OPENCLOSEOBJS)
	$(CC) $(LDFLAGS) $(OPENCLOSEOBJS) -o $@

$(BUILD)/amitls13_repeat_get_lib: $(REPEATTOOLOBJS)
	$(CC) $(LDFLAGS) $(REPEATTOOLOBJS) -o $@

$(BUILD)/amitls13_example_get: $(SDKEXAMPLEOBJS)
	$(CC) $(LDFLAGS) $(SDKEXAMPLEOBJS) -o $@

clean:
	rm -rf $(BUILD)
