#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <strings.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

int main(int argc, char **argv) {
        int  sockfd, n; 
        char recvline[100];
        struct sockaddr_in servaddr;
	char message[2000];
	char command[1000];
	char argument[999];
	char reply[2000];

        if(argc!=3){
                printf("Usage : gettime <IP address>\n");
                exit(1); 
        }
        if((sockfd = socket(AF_INET,SOCK_STREAM, 0)) < 0) {
                perror("socket"); 
                exit(2);
        }
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons((unsigned short)atoi(argv[2]));

	struct hostent *h = gethostbyname(argv[1]);
	struct in_addr **addr_list = (struct in_addr **) h->h_addr_list;
	char ip[100];
	strcpy(ip, inet_ntoa(*addr_list[0]));

        if (inet_pton(AF_INET, ip, &servaddr.sin_addr) <= 0) {
                perror("inet_pton"); 
                exit(3);
        }
        if (connect(sockfd,  (struct sockaddr *) &servaddr,sizeof(servaddr)) < 0 ) {
                perror("connect"); 
                exit(4); 
        }


	while (1) {
		message[0] = '\0';
		printf("telnet > ");
		scanf("%s", command);
		if (strcmp(command, "cd") == 0 || strcmp(command, "mkdir") == 0 || strcmp(command, "rmdir") == 0) {
			scanf("%s", argument);
			strcpy(message, command);
			strcat(message, " ");
			strcat(message, argument);
		}
		else {
			strcpy(message, command);
		}

		if (send(sockfd, message, strlen(message), 0) < 0) {
			printf("Error sending message\n");
			return 0;
		}
		if (strcmp(message, "exit") == 0) {
			close(sockfd);
			return 0;
		}
		int message_len;
		if ((message_len = recv(sockfd, reply, 2000, 0)) < 0) {
			printf("Error receiving message\n");
			return 0;
		}
		reply[message_len] = '\0';
		if (strcmp(reply, "okay") != 0) {
			printf("%s\n", reply);
		}
	}
        close(sockfd);
} 

