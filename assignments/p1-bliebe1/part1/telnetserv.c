#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>

int findLastChar(char *str) {
	int index = -1, i = 0;
	while (str[i] != '\0') {
		if (str[i] == '/') index = i;
		i++;
	}
	return index;
}

int main(int argc, char **argv) {
        int   listenfd, connfd, clilen;
        struct sockaddr_in servaddr, cliaddr;
        char buff[100];
        time_t ticks;
	char *std_rep = "okay";

        listenfd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family      = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port        = htons(atoi(argv[1]));   /* daytime server */

        bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr));       
	listen(listenfd, 100); 
   

	while (1) {
		clilen = sizeof(cliaddr);
		connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);

		char cwd[2000];
		if (getcwd(cwd, sizeof(cwd)) == NULL) {
			printf("Error getting working directory\n");
		}
		
		int read_size;
		char message[2000];
		char reply[2000];
		while ((read_size = recv(connfd, message, 2000, 0)) > 0) {
			message[read_size] = '\0';
			reply[0] = '\0';
			// printf("%s\n", message);

			if (strcmp(message, "exit") == 0) break;
			else if (strcmp(message, "pwd") == 0) {
				write(connfd, cwd, strlen(cwd));
			}
			else if (strcmp(message, "ls") == 0) {
				int status;
				char path[200];
				char lspath[200];
				strcpy(lspath, "/bin/ls ");
				strcat(lspath, cwd);

				FILE *fp = popen(lspath, "r");
				while (fgets(path, 200, fp) != NULL) {
					strcat(reply, path);
				}
				status = pclose(fp);
				if (strcmp(reply, "") == 0) strcat(reply, std_rep);

				write(connfd, reply, strlen(reply));
			}
			else {
				char *context, *first, *second;
				first = strtok_r(message, " ", &context);
				second = context;
				if (strcmp(first, "cd") == 0) {
					if (strcmp(second, "..") == 0) {
						cwd[findLastChar(cwd)] = '\0';
						printf("Moved to: %s\n", cwd);
						write(connfd, std_rep, strlen(std_rep));
					}
					else {
						char cwdcopy[2000];
						strcpy(cwdcopy, cwd);

						strcat(cwd, "/");
						strcat(cwd, second);
						DIR *dir = opendir(cwd);
						if (ENOENT == errno) {
							char *error = "Directory does not exist.";
							strcpy(cwd, cwdcopy);
							write(connfd, error, strlen(error));
						}
						else {
							printf("Moved to: %s\n", cwd);
							write(connfd, std_rep, strlen(std_rep));
						}
					}
				}
				else if (strcmp(first, "mkdir") == 0) {
					char newdir[2000];
					strcpy(newdir, cwd);
					strcat(newdir, "/");
					strcat(newdir, second);
					DIR *dir = opendir(newdir);
					if (dir) {
						char *error = "Directory already exists.";
						write(connfd, error, strlen(error));
					}
					else {
						mkdir(newdir, 0700);
						printf("Created dir: %s\n", newdir);
						write(connfd, std_rep, strlen(std_rep));
					}
				}
				else if (strcmp(first, "rmdir") == 0) {
					char newdir[2000];
					strcpy(newdir, cwd);
					strcat(newdir, "/");
					strcat(newdir, second);
					DIR *dir = opendir(newdir);
					if (dir) {
						rmdir(newdir);
						printf("Removed dir: %s\n", newdir);
						write(connfd, std_rep, strlen(std_rep));
					}
					else {
						char *error = "Directory does not exist.";
						write(connfd, error, strlen(error));
					}
				}
				else {
					char *error = "Command not found";
					write(connfd, error, strlen(error));
				}
			}
		}
		printf("Closing conncection.\n");		
		close(connfd);
	}
}

