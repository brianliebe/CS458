all: gen-pass sslserv sslcli

gen-pass: gen-pass.cpp sha1.cpp sha1.h
	g++ gen-pass.cpp sha1.cpp -o gen-pass -Wall -Wextra

sslserv: sslserv.cpp
	g++ sslserv.cpp -o sslserv -L/usr/lib -lssl -lcrypto -Wno-write-strings

sslcli: sslcli.cpp
	g++ sslcli.cpp -o sslcli -L/usr/lib -lssl -lcrypto -Wno-write-strings

clean:
	rm -f gen-pass sslserv sslcli
