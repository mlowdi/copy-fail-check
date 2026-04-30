CC ?= gcc
MUSL_CC ?= musl-gcc

CFLAGS = -O2 -Wall -Wextra
TARGET = af_alg_check
SRC = af_alg_splice_check.c

# Default: static build with gcc (large but works everywhere)
static: $(SRC)
	$(CC) -static $(CFLAGS) -o $(TARGET) $(SRC)

# Smaller static binary via musl (if musl-tools installed)
musl: $(SRC)
	$(MUSL_CC) -static $(CFLAGS) -o $(TARGET) $(SRC)

# Dynamic build (for testing on a dev box)
dynamic: $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: static musl dynamic clean
