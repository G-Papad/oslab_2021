/*
 * socket-server.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

/* Convert a buffer to upercase */
void toupper_buf(char *buf, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		buf[i] = toupper(buf[i]);
}

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(void)
{
	char buf[100];
	char addrstr[INET_ADDRSTRLEN];
	int sd, newsd;
	ssize_t n;
	socklen_t len;
	struct sockaddr_in sa;
	
	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) { //creates a socket that has TCP/IPv4 connection
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa)); //fills the sizeof(sa) with 0
	sa.sin_family = AF_INET;	//IPv4
	sa.sin_port = htons(TCP_PORT);	//htons -> convert TCP_PORT to network byte order
	sa.sin_addr.s_addr = htonl(INADDR_ANY); //This is an IP address that is used when we don't want to bind a socket to any specific IP.
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { //αναθλετει διευθυνση στο socket
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) { //ετοιμασαζει το socket να δεχθει συνδεσεις
		perror("listen");
		exit(1);
	}

	/* Loop forever, accept()ing connections */
	//int termination_flag=0;
	for (;;) {
		fprintf(stderr, "Waiting for an incoming connection...\n");

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) { //newsd -> new connected socket
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));

		/* We break out of the loop when the remote peer goes away */
		fd_set readfds;
		int retval;
		for (;;) {
			FD_ZERO(&readfds);
			FD_SET(0, &readfds);
			FD_SET(newsd, &readfds);
			retval = select(newsd+1, &readfds, NULL, NULL, NULL);
			if(retval == -1){
				perror("select()");
				break;
			}
			if(FD_ISSET(0, &readfds)){
				n = read(0, buf, sizeof(buf));
				if(n < 0){
					perror("read from input failed");
					break;
				}
				
				if(n-1 >= 0)
					buf[n - 1] = '\0';
				if (insist_write(newsd, buf, strlen(buf)) != strlen(buf)) {
					perror("write");
					exit(1);
				}
				if(n==0) break;
			}
			if(FD_ISSET(newsd, &readfds)){
				n = read(newsd, buf, sizeof(buf));
				if(n<0){
					perror("read from remote peer failed");
					break;
				}
				if(n==0) break;
				
				if(insist_write(1, buf, n) != n){
					perror("write to stdin failed");
					break;
				}
				if (insist_write(1, "\n", 1) != 1){
					perror("write to remote peer failed");
					break;
				}
			}
		}
		
		/* Make sure we don't leak open files */
		if (close(newsd) < 0)
			perror("close");
	}

	/* This will never happen */
	return 1;
}

