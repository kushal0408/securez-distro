# SecureZ+ OS — CrypticEngine Makefile
#
# Builds: libcryptic.so, libcryptic.a, crypticd daemon
# Requires: libsodium-dev

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11 \
          -fstack-protector-strong -fPIC \
          -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE \
          -Iinclude
LDFLAGS = -lsodium -lpthread

# Source files
LIB_SRCS = src/cryptic_engine.c \
           src/crypto_core.c \
           src/secure_memory.c \
           src/secure_session.c \
           src/hidden_container.c \
           src/key_storage.c \
           src/nxe_loader.c \
           src/nxe_builder.c \
           src/integrity.c

DAEMON_SRC = daemon/crypticd.c

# Object files
LIB_OBJS = $(LIB_SRCS:.c=.o)
DAEMON_OBJ = $(DAEMON_SRC:.c=.o)

# Outputs
LIB_SHARED = libcryptic.so
LIB_STATIC = libcryptic.a
DAEMON     = crypticd

# Install paths
PREFIX     = /usr
LIBDIR     = $(PREFIX)/lib
INCLUDEDIR = $(PREFIX)/include/cryptic
SBINDIR    = $(PREFIX)/sbin
UNITDIR    = /etc/systemd/system

.PHONY: all clean install uninstall test

all: $(LIB_SHARED) $(LIB_STATIC) $(DAEMON)

# Shared library
$(LIB_SHARED): $(LIB_OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Static library
$(LIB_STATIC): $(LIB_OBJS)
	ar rcs $@ $^

# Daemon
$(DAEMON): $(DAEMON_OBJ) $(LIB_STATIC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Compile C to object
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Install
install: all
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -d $(DESTDIR)$(SBINDIR)
	install -d $(DESTDIR)$(UNITDIR)
	install -d $(DESTDIR)/etc/securez
	install -d $(DESTDIR)/var/lib/securez
	install -m 755 $(LIB_SHARED) $(DESTDIR)$(LIBDIR)/
	install -m 644 $(LIB_STATIC) $(DESTDIR)$(LIBDIR)/
	install -m 644 include/*.h $(DESTDIR)$(INCLUDEDIR)/
	install -m 755 $(DAEMON) $(DESTDIR)$(SBINDIR)/
	install -m 644 daemon/crypticd.service $(DESTDIR)$(UNITDIR)/
	ldconfig 2>/dev/null || true

# Uninstall
uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(LIB_SHARED)
	rm -f $(DESTDIR)$(LIBDIR)/$(LIB_STATIC)
	rm -rf $(DESTDIR)$(INCLUDEDIR)
	rm -f $(DESTDIR)$(SBINDIR)/$(DAEMON)
	rm -f $(DESTDIR)$(UNITDIR)/crypticd.service

# Run tests
test: $(LIB_STATIC)
	$(CC) $(CFLAGS) -o tests/test_crypto tests/test_crypto.c $(LIB_STATIC) $(LDFLAGS)
	./tests/test_crypto

# Clean
clean:
	rm -f $(LIB_OBJS) $(DAEMON_OBJ)
	rm -f $(LIB_SHARED) $(LIB_STATIC) $(DAEMON)
	rm -f tests/test_crypto
