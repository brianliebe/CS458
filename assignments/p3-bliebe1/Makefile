LINKS = -lssl -lcrypto -lresolv -lnsl -L/usr/lib

all: gen-pass sslcli sslserv

gen-pass: gen-pass.cpp sha1.cpp sha1.h
	g++ gen-pass.cpp sha1.cpp -o gen-pass -Wall -Wextra

sslserv: sslserv.cpp sha1.cpp sha1.h
	g++ sslserv.cpp sha1.cpp -o sslserv $(LINKS)

sslcli: sslcli.cpp
	g++ sslcli.cpp -o sslcli $(LINKS)

clean:
	rm -f gen-pass sslserv sslcli
