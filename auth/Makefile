# SecureZ+ OS — Auth System Makefile

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -fstack-protector-strong -fPIC -D_GNU_SOURCE
LDFLAGS_PAM  = -lsodium -lpam
LDFLAGS_MK   = -lsodium

.PHONY: all clean install

all: pam_securez.so securez-master-key

# PAM module (shared library)
pam_securez.so: src/pam_securez.c
	$(CC) $(CFLAGS) -shared -o $@ $< $(LDFLAGS_PAM)

# Master key utility
securez-master-key: src/master_key.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS_MK)

install: all
	install -m 644 pam_securez.so $(DESTDIR)/lib/x86_64-linux-gnu/security/
	install -m 755 securez-master-key $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/etc/pam.d/
	install -m 644 pam.d/securez-auth $(DESTDIR)/etc/pam.d/ 2>/dev/null || true

clean:
	rm -f pam_securez.so securez-master-key
