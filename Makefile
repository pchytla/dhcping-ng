CC = gcc 
POD2MAN = pod2man
GZIP = gzip
CFLAGS = -g -Wall 
#For FreeBSD uncomment this
INCDIR    = -I/usr/local/include
LIBDIR    = -I/usr/local/lib/libnet11
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
