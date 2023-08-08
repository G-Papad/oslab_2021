/*
 * socket-client.c
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

#include <sys/select.h>

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

int main(int argc, char *argv[])

{
	struct session_op sess;
	struct {
		unsigned char 	in[DATA_SIZE],
				encrypted[DATA_SIZE],
				decrypted[DATA_SIZE];
		unsigned char iv[BLOCK_SIZE];
		unsigned char key[KEY_SIZE];
				
	} data;
	int sd, port, i=0, nfd, cfd;
	ssize_t n;
	char socket_buf[100];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	/* Be careful with buffer overruns, ensure NUL-termination */
	// strncpy(buf, HELLO_THERE, sizeof(buf));
	// buf[sizeof(buf) - 1] = '\0';


	cfd = open("/dev/cryptodev0", O_RDWR, 0);
	if(cfd < 0){
		perror("open");
		return 1;
	}

	/* Say something... */
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

	for(;;){
		//fprintf(stderr, "FOR\n");	
		FD_ZERO(&readfds);
		FD_SET(0, &readfds);
		FD_SET(sd, &readfds);
		retval = select(sd+1, &readfds, NULL, NULL, NULL);
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
			if (insist_write(sd, data.encrypted, sizeof(data.in)) != sizeof(data.in)) {
				perror("write");
				exit(1);
			}
			if(n==0) break;
		}
		if(FD_ISSET(sd, &readfds)){
			n = read(sd, data.in, sizeof(data.in));
			if(n<0){
				perror("read from remote peer failed");
				break;
			}
			if(n==0){ 
				fprintf(stderr, "End Of Communication\n");				
				break;
			}
	
			decrypt(cfd, sess, data.iv, data.in, data.decrypted);
/*		for(i=0; i<DATA_SIZE; i++)
			printf("%c", data.decrypted[i]);
		printf("\n");
*/

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
	/*
	 * Let the remote know we're not going to write anything else.
	 * Try removing the shutdown() call and see what happens.
	  */
	if (shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}

	fprintf(stderr, "\nDone.\n");
	return 0;
}