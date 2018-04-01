LINKS = -lssl -lcrypto -Wno-write-strings -lresolv -lnsl

all: voter-cli vf

vf: vf.cpp sha1.cpp sha1.h shared.h
	g++ vf.cpp sha1.cpp -o vf -L/usr/lib $(LINKS)

voter-cli: voter-cli.cpp shared.h
	g++ voter-cli.cpp -o voter-cli -L/usr/lib $(LINKS)

clean:
	rm -f vf voter-cli
