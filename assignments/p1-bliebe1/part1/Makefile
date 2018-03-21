all: client server

client: telnetcli.c
	gcc telnetcli.c -o telnetcli -lresolv -lsocket -lnsl

server: telnetserv.c
	gcc telnetserv.c -o telnetserv -lresolv -lsocket -lnsl

clean:
	rm -f telnetserv telnetcli
