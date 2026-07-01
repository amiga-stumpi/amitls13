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
PINFAILTOOLOBJS = $(BUILD)/amitls13_pin_fail_lib.o $(BUILD)/amitls13_client_stubs.o
PINPRINTTOOLOBJS = $(BUILD)/amitls13_pin_print_lib.o $(BUILD)/amitls13_client_stubs.o
STREAMTESTOBJS = $(BUILD)/amitls13_stream_test_lib.o $(BUILD)/amitls13_client_stubs.o

BRSRCS = \
	third_party/bearssl/src/mac/hmac.c \
	third_party/bearssl/src/int/i15_montmul.c \
	third_party/bearssl/src/int/i15_iszero.c \
	third_party/bearssl/src/int/i15_modpow2.c \
	third_party/bearssl/src/int/i15_tmont.c \
	third_party/bearssl/src/int/i15_ninv15.c \
	third_party/bearssl/src/int/i15_add.c \
	third_party/bearssl/src/int/i15_sub.c \
	third_party/bearssl/src/int/i15_fmont.c \
	third_party/bearssl/src/int/i15_modpow.c \
	third_party/bearssl/src/int/i15_decmod.c \
	third_party/bearssl/src/int/i15_muladd.c \
	third_party/bearssl/src/int/i15_encode.c \
	third_party/bearssl/src/int/i15_decode.c \
	third_party/bearssl/src/int/i15_bitlen.c \
	third_party/bearssl/src/ssl/ssl_rec_gcm.c \
	third_party/bearssl/src/ssl/ssl_engine.c \
	third_party/bearssl/src/ssl/ssl_client.c \
	third_party/bearssl/src/ssl/ssl_hs_client.c \
	third_party/bearssl/src/ssl/prf_sha256.c \
	third_party/bearssl/src/ssl/ssl_io.c \
	third_party/bearssl/src/ssl/prf.c \
	third_party/bearssl/src/symcipher/aes_ct_ctr.c \
	third_party/bearssl/src/symcipher/aes_ct_enc.c \
	third_party/bearssl/src/symcipher/aes_ct.c \
	third_party/bearssl/src/codec/ccopy.c \
	third_party/bearssl/src/codec/dec32be.c \
	third_party/bearssl/src/codec/enc32be.c \
	third_party/bearssl/src/rand/hmac_drbg.c \
	third_party/bearssl/src/rsa/rsa_i15_pub.c \
	third_party/bearssl/src/rsa/rsa_i15_pkcs1_vrfy.c \
	third_party/bearssl/src/rsa/rsa_pkcs1_sig_unpad.c \
	third_party/bearssl/src/x509/x509_decoder.c \
	third_party/bearssl/src/ec/ec_p256_m15.c \
	third_party/bearssl/src/hash/ghash_ctmul32.c \
	third_party/bearssl/src/hash/sha2small.c \
	third_party/bearssl/src/hash/multihash.c \
	third_party/bearssl/src/hash/sha1.c
BROBJS = $(patsubst third_party/bearssl/src/%.c,$(BUILD)/bearssl/%.o,$(BRSRCS))

.PHONY: all clean trace debug

all: $(BUILD)/libamitls13.a $(BUILD)/amitls13.library $(BUILD)/amitls13_get $(BUILD)/amitls13_get_lib $(BUILD)/amitls13_openclose $(BUILD)/amitls13_repeat_get_lib $(BUILD)/amitls13_example_get $(BUILD)/amitls13_pin_fail_lib $(BUILD)/amitls13_pin_print_lib $(BUILD)/amitls13_stream_test_lib

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

$(BUILD)/amitls13_pin_fail_lib.o: tools/amitls13_pin_fail_lib.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/amitls13_pin_print_lib.o: tools/amitls13_pin_print_lib.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/amitls13_stream_test_lib.o: tools/amitls13_stream_test_lib.c | $(BUILD)
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

$(BUILD)/amitls13_pin_fail_lib: $(PINFAILTOOLOBJS)
	$(CC) $(LDFLAGS) $(PINFAILTOOLOBJS) -o $@

$(BUILD)/amitls13_pin_print_lib: $(PINPRINTTOOLOBJS)
	$(CC) $(LDFLAGS) $(PINPRINTTOOLOBJS) -o $@

$(BUILD)/amitls13_stream_test_lib: $(STREAMTESTOBJS)
	$(CC) $(LDFLAGS) $(STREAMTESTOBJS) -o $@

clean:
	rm -rf $(BUILD)
