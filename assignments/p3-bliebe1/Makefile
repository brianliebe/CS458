LINKS = -lssl -lcrypto -Wno-write-strings -lresolv -lnsl

all: gen-pass sslcli sslserv

gen-pass: gen-pass.cpp sha1.cpp sha1.h
	g++ gen-pass.cpp sha1.cpp -o gen-pass -Wall -Wextra

sslserv: sslserv.cpp sha1.cpp sha1.h
	g++ sslserv.cpp sha1.cpp -o sslserv -L/usr/lib $(LINKS)

sslcli: sslcli.cpp
	g++ sslcli.cpp -o sslcli -L/usr/lib $(LINKS)

clean:
	rm -f gen-pass sslserv sslcli
