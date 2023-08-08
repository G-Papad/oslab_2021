#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>

int main(){
	int fd;
	pid_t pid;
	char buffer[99999];
	fd = open("/dev/lunix0-batt", O_RDONLY);
	pid = fork();
	if(pid==0){
		while(1){
		read(fd, &buffer,6);
		printf("I'm the child\n");
		write(1, &buffer,6);
		}
	}
	else{
		while(1){
		read(fd, &buffer, 6);
		printf("I'm the parent\n");
		write(1, &buffer, 6);

		}
	}

	return 0;
}
