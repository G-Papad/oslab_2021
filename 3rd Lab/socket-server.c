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
#include <sys/stat.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

#include "our_crypto.h"


//crypto
int encrypt(int cfd, struct session_op sess, unsigned char *iv, unsigned char *in, unsigned char *enc_msg){
	struct crypt_op cryp;
	memset(&cryp, 0, sizeof(cryp));

	cryp.ses = sess.ses;
	cryp.len = DATA_SIZE;
	cryp.src = in;
	cryp.dst = enc_msg;
	cryp.iv = iv;
	cryp.op = COP_ENCRYPT;

	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("encrypt_ioctl(CIOCCRYPT)");
		return 1;
	}
	return 0;
}


int decrypt(int cfd, struct session_op sess, unsigned char *iv, unsigned char *in, unsigned char *dec_msg){
	struct crypt_op cryp;
	memset(&cryp, 0, sizeof(cryp));

	cryp.ses = sess.ses;
	cryp.len = DATA_SIZE;
	cryp.src = in;
	cryp.dst = dec_msg;
	cryp.iv = iv;
	cryp.op = COP_DECRYPT;

	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("decrypt_ioctl(CIOCCRYPT)");
		return 1;
	}
	return 0;
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
	struct session_op sess;
	struct {
		unsigned char 	in[DATA_SIZE],
				encrypted[DATA_SIZE],
				decrypted[DATA_SIZE];
		unsigned char iv[BLOCK_SIZE];
		unsigned char key[KEY_SIZE];
				
	} data;

	char addrstr[INET_ADDRSTRLEN];
	int sd, newsd, i=0, nfd, cfd;
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
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) { //\u03b1\u03bd\u03b1\u03b8\u03bb\u03b5\u03c4\u03b5\u03b9 \u03b4\u03b9\u03b5\u03c5\u03b8\u03c5\u03bd\u03c3\u03b7 \u03c3\u03c4\u03bf socket
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) { //\u03b5\u03c4\u03bf\u03b9\u03bc\u03b1\u03c3\u03b1\u03b6\u03b5\u03b9 \u03c4\u03bf socket \u03bd\u03b1 \u03b4\u03b5\u03c7\u03b8\u03b5\u03b9 \u03c3\u03c5\u03bd\u03b4\u03b5\u03c3\u03b5\u03b9\u03c2
		perror("listen");
		exit(1);
	}


	cfd = open("/dev/cryptodev0", O_RDWR, 0);
	if(cfd < 0){
		perror("open");
		return 1;
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

		memset(&sess, 0, sizeof(sess));

		/*
		 * Get crypto session for AES128
		 */
		nfd = open("key.txt", O_RDONLY);
		read(nfd, data.key, KEY_SIZE);
		nfd = open("iv.txt", O_RDONLY);
		read(nfd, data.iv, BLOCK_SIZE);


		sess.cipher = CRYPTO_AES_CBC;
		sess.keylen = KEY_SIZE;
		sess.key = data.key;
	
		if (ioctl(cfd, CIOCGSESSION, &sess)){
			perror( "ioctl(CIOCGSESSION)");
			return 1;
		}

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
				n = read(0, data.in, sizeof(data.in));
				if(n < 0){
					perror("read from input failed");
					break;
				}
			


				if(n-1 >= 0)
					data.in[n - 1] = '\0';
				encrypt(cfd, sess, data.iv, data.in, data.encrypted);
				if (insist_write(newsd, data.encrypted, sizeof(data.in)) != sizeof(data.in)) {
					perror("write");
					exit(1);
				}
				if(n==0) break;
			}
			if(FD_ISSET(newsd, &readfds)){
				n = read(newsd, data.in, sizeof(data.in));
				if(n<0){
					perror("read from remote peer failed");
					break;
				}
				if(n==0) break;
				
				decrypt(cfd, sess, data.iv, data.in, data.decrypted);

				if(insist_write(1, data.decrypted, strlen(data.decrypted)) != strlen(data.decrypted)){
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
