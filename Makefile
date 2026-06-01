CC = gcc
CFLAGS = -Wall -Wextra -O2 -I/opt/homebrew/include
LDFLAGS = -L/opt/homebrew/lib -lgmp

BINARY = ssss
SOURCES = main.c ssss.c
HEADERS = ssss.h

.PHONY: all clean install

all: $(BINARY)

$(BINARY): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

install: $(BINARY)
	cp $(BINARY) /usr/local/bin/ssss-split
	ln -sf /usr/local/bin/ssss-split /usr/local/bin/ssss-combine

clean:
	rm -f $(BINARY) ssss-split ssss-combine

# Create local symlinks for testing
test-links: $(BINARY)
	ln -sf $(BINARY) ssss-split
	ln -sf $(BINARY) ssss-combine
