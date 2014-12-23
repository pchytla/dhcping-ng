CC = gcc 
POD2MAN = pod2man
GZIP = gzip
CFLAGS = -g -Wall 

ifndef OS
  OS := $(shell uname)
endif


ifeq "$(OS)" "FreeBSD"
        INCDIR    := -I/usr/local/include/libnet11
        LIBDIR    := -L/usr/local/lib/libnet11
endif

LDFLAGS = -lpcap -lnet

all:
	$(CC) $(CFLAGS) -c dhcping-ng.c $(INCDIR)
	$(CC) $(CFLAGS) -o dhcping-ng dhcping-ng.o $(LDFLAGS) $(INCDIR) $(LIBDIR)
	$(POD2MAN) dhcping-ng.pod >dhcping-ng.8
	$(GZIP) -f dhcping-ng.8

all-static:
	$(CC) $(CFLAGS) -c dhcping-ng.c $(INCDIR)
	$(CC) $(CFLAGS) -static -o dhcping-ng-static dhcping-ng.c $(LDFLAGS) $(INCDIR) $(LIBDIR)
	$(POD2MAN) dhcping-ng.pod >dhcping-ng.8
	$(GZIP) -f dhcping-ng.8
        
clean:
	@rm -f core dhcping-ng-static dhcping-ng *.o *.8 *.8.gz
