# SecureZ+ OS — SecureZ Shell Makefile

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11 \
          -fstack-protector-strong -D_GNU_SOURCE \
          -Iinclude -I../crypticengine/include
LDFLAGS = -lreadline -lsodium -lpthread

SRCS    = src/szshell.c \
          src/parser.c \
          src/prompt.c \
          src/builtins.c \
          src/crypto_cmds.c \
          src/session_cmds.c \
          src/system_cmds.c

OBJS    = $(SRCS:.c=.o)
TARGET  = szshell

PREFIX  = /usr

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install: $(TARGET)
	install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/szshell
	@# Register as a valid login shell
	@grep -q szshell /etc/shells 2>/dev/null || echo "/usr/bin/szshell" >> /etc/shells

clean:
	rm -f $(OBJS) $(TARGET)
