
LIBS = -lcrypto
CFLAGS = -O2 -g -Wall -Wextra -Werror=format-security

all: certwatch certwatch.1

certwatch: certwatch.o
	$(CC) $(LDFLAGS) -o certwatch $< $(LIBS)

certwatch.1: certwatch.xml
	xmlto man $<

check: certwatch
	cd t && prove -v .
