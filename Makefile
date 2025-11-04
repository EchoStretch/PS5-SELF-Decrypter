PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := ps5-self-decrypter.elf
SOCK_ELF := ps5-self-decrypter-sock-log.elf
SYSTEM_COMMON_LIB_ELF := ps5-self-decrypter-system-common-lib.elf
FULL_SYSTEM_ELF := ps5-self-decrypter-full-system.elf
SHELLCORE_ELF := ps5-self-decrypter-shellcore.elf
GAME_ELF := ps5-self-decrypter-game.elf

CFLAGS := -Wall -O2 -Iinclude

all: $(ELF)
sock: $(SOCK_ELF)
dist: $(SYSTEM_COMMON_LIB_ELF) $(FULL_SYSTEM_ELF) $(SHELLCORE_ELF) $(GAME_ELF)

CFILES := $(wildcard source/*.c)

$(ELF): $(CFILES)
	$(CC) $(CFLAGS) -o bin/$@ $^

$(SOCK_ELF): $(CFILES)
	$(CC) $(CFLAGS) -DLOG_TO_SOCKET -o bin/$@ $^

$(SYSTEM_COMMON_LIB_ELF): $(CFILES)
	$(CC) $(CFLAGS) -DDUMP_SYSTEM_COMMON_LIB -o bin/$@ $^

$(FULL_SYSTEM_ELF): $(CFILES)
	$(CC) $(CFLAGS) -DDUMP_ALL_SYSTEM -o bin/$@ $^

$(SHELLCORE_ELF): $(CFILES)
	$(CC) $(CFLAGS) -DDUMP_SHELLCORE -o bin/$@ $^

$(GAME_ELF): $(CFILES)
	$(CC) $(CFLAGS) -DDUMP_GAME -o bin/$@ $^

clean:
	rm -f bin/*.elf

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) bin/$(ELF)

send: test