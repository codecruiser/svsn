/**
 * SVSN Ports checker and server
 * 
 * Version: 0.1 (Alpha version)
 * 
 * Description: This programm was created to check for given ports 
 * 			logging the state of each in a file
 * 			and to act as a server to let the checking be done 
 * 			remotely
 * 
 * Author: Zbigniew Szczepanski
 * 
 * TODO: there is a lot of issues which need to be addressed here,
 * 		e.g.: server security, logging, unclattering the code. 
 * 		Wait for next version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <regex.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct ports_check_return {
	short int success;
	char *ret;
} pcr;

struct s_address {
		char *ip;
		struct {
			int size;
			int *ports;
		} ports;
};

struct s_address readConf(char *filename);

struct s_address extractPorts(char *content);

regmatch_t *regExpProcessor(char *pattern, char *content);

void help();

void createDeamon(struct s_address sa);

void serverizeMe(struct s_address sa);

void serverConnection(struct s_address *sa, int *aconn);

void checkPorts(struct s_address sa);

pcr checkingPorts(struct s_address sa);


/**
 * This is main function, making this project executable
 */
int main(int argc, char **argv) {
	int *ports_to_b_checked;
	int i;
	struct s_address sa;
	
	/**
	 * It declares some default ports to be checked (example only)
	 */	
	int arr[6] = {25, 80, 90, 95, 125, 160};
	
	char *ip = "127.0.0.1\0";
	
	sa.ip = ip;
	sa.ports.size = 6;
	sa.ports.ports = arr;
	
	/**
	 * goes through arguments list and checks for options
	 */
	for(i = 1; i < argc; i++)
	{
		if(argv[i][0] == '-')
		{
			switch(argv[i][1])
			{
				case 'c':
					i++;
					if(i >= argc)
					{
						help();
					} 
					else 
					{
						sa = readConf(argv[i]);
					}
					break;
			}
		}
	}
	
	/**
	 * Turn the proccess to a daemon
	 */
	createDeamon(sa);
	
	//commented out debugging check
	//serverizeMe(sa);
	//checkPorts(sa);
	
	return 0;
}

/**
 * Function to read config file
 */
struct s_address readConf(char *filename)
{
	FILE *fp; //file pointer
	char *content;

	fp = fopen(filename, "r");
	
	if(fp)
	{
		int file_len;
		
		//cursor set to end of the file to determ length of the file
		fseek(fp, 0, SEEK_END);
		
		//current cursor position (here: file length)
		file_len = ftell(fp);
		
		//back to begining
		fseek(fp, 0, SEEK_SET );		
		
		content = malloc(file_len);

		if(content)
		{
			int j;
			
			for(j = 0; j < file_len; j++)
			{
				char *buff;
								
				buff = malloc(file_len);
								
				buff = fgets(buff, file_len, fp);
								
				if(feof(fp))
					break;
					
				strcat(content, buff);
				
				free(buff);
			}
		} 
		else
		{
			perror("Couldn't allocate memory for conf data");
			exit(EXIT_FAILURE);
		}
	}
	else
	{
		perror("Couldn't read the configuration file");
        exit(EXIT_FAILURE);
	}
	fflush(fp);
	
	fclose(fp);
	
	struct s_address sa = extractPorts(content);
	
	//we don't need the string so let memory be freed
	free(content);
	
	return sa;
}

/**
 * Extract ports
 */
struct s_address extractPorts(char *content) 
{
	regmatch_t *rm;
	regmatch_t *rm_ports;	
	int a;
	
	struct s_address sa;
	
	sa.ports.size = 0;
	sa.ports.ports = malloc(sizeof(int));
	
	//extract IP
	rm = regExpProcessor("^\\s*IPS{0,1}\\s+([0-9\\.]+)\\s*:\\s*([0-9,\\s]+).+$", content);
			
	//if found let's extract size and string matched for IPs
	int match_ip_size = rm[1].rm_eo - rm[1].rm_so;
	
	if(match_ip_size < 1) return;

	//copy IP to struct s_address
	sa.ip = malloc(match_ip_size+1);
	memcpy(sa.ip, &content[rm[1].rm_so], match_ip_size);
	sa.ip[match_ip_size] = '\0';
	
	printf("IP: %s\n", sa.ip);
	
	//if found let's extract size and string matched for IPs
	int match_ports_size = rm[2].rm_eo - rm[2].rm_so;
	
	if(match_ports_size < 1) return;

	//copy Ports to struct s_address
	char *ports;
	
	ports = malloc(match_ports_size+1);
	memcpy(ports, &content[rm[2].rm_so], match_ports_size);
	ports[match_ports_size] = '\0';
	
	printf("Ports: %s\n", ports);
		
	while((rm_ports = regExpProcessor("([0-9]+)", ports)) != 0)
	{
		//loop through the rest
		for(a = 0; a < 1; a++)
		{
			int match_port_size = rm_ports[a].rm_eo - rm_ports[a].rm_so;
			
			if(match_port_size > 0)
			{
				char *port;
				char *rest_of_ports;
				
				port = malloc(match_port_size+1);
				memcpy(port, &ports[rm_ports[a].rm_so], match_port_size);
				port[match_port_size] = '\0';
				
				//printf("[%d]\n", atoi(port));
				
				sa.ports.ports = realloc(sa.ports.ports, (sizeof(int)*sa.ports.size)+sizeof(int));
				*(sa.ports.ports+sa.ports.size) = atoi(port);
				
				//sa.ports
				sa.ports.size++;

				rest_of_ports = malloc(match_ports_size-rm_ports[a].rm_eo+1);
				memcpy(rest_of_ports, &ports[rm_ports[a].rm_eo], match_ports_size-rm_ports[a].rm_eo);
				rest_of_ports[match_ports_size-rm_ports[a].rm_eo] = '\0';
				
				//free memory of original ports string
				free(ports);
				
				//create new one with 
				ports = rest_of_ports;
				
				//printf("%s\n", ports);
			}
		}
	}
	
	return sa;
}

/**
 * regular expression machine
 */
regmatch_t *regExpProcessor(char *pattern, char *machedstr)
{
	regex_t regexp;
	int retre;
	regmatch_t *rm;
	
	//prepare regexp string for search of a pattern like: IPS 127.0.0.1:80,20
	if(regcomp(&regexp, pattern, REG_ICASE | REG_NEWLINE | REG_EXTENDED)) 
	{
		perror("Couldn't compile regex");
		
		exit(EXIT_FAILURE);
	}
	
	rm = calloc(sizeof(regmatch_t), 20);
	
	retre = regexec(&regexp, machedstr, 20, rm, 0);
	
	if(!retre)
	{
		//we don't need regexp no more
		regfree(&regexp);
		
		return rm;
	}
	else if(retre == REG_NOMATCH) 
	{
		rm = 0;
		
		return rm;
	}
	else 
	{
		perror("Regex match problem");
		
		exit(EXIT_FAILURE);
	}
}

/**
 * Show help message
 */
void help()
{
	printf("Use following options:\n");
	printf("\t-c filename - loads configuration file, where filename is name of configuration file\n");
	exit(EXIT_FAILURE);
}

/**
 * Changes the app to deamon
 */
 void createDeamon(struct s_address sa)
 {	
	pid_t process_id = 0;
	pid_t sid = 0;

	process_id = fork();

	if (process_id < 0)
	{
		perror("Couldn't fork proccess");
		exit(EXIT_FAILURE);
	}

	/**
	 * Murder in the family. Parent is being killed
	 */	
	if(process_id > 0)
	{
		printf("process id: %d \n", process_id);
		
		exit(EXIT_SUCCESS);
	}
	else
	{
		/**
		 * We for again to let server and port checker have 
		 * their own threads 
		 */
		pid_t subprocess_id = fork();

		if(subprocess_id < 0)
		{
			perror("Couldn't fork proccess");
			exit(EXIT_FAILURE);
		}
		
		if(subprocess_id > 0)
		{
			printf("process id: %d \n", subprocess_id);
			serverizeMe(sa);
			return;
		}
		else
		{
			checkPorts(sa);
			return;
		}
	}

	if (process_id > 0)
	{
		umask(0);

		/**
		 * New session starts
		 */
		sid = setsid();

		if(sid < 0)
		{
			perror("Couldn't start new session");
			exit(EXIT_FAILURE);
		}

		chdir("/");

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}
}

/**
 * Creates server to let ports checking infromation be available online
 */
void serverizeMe(struct s_address sa)
{
	int sn_socket;
	int aconn;
	struct sockaddr_in sn_int_address;
	int sn_binding;
	int port = 2026;
		
	/**
	 * socket is being created 
	 * and checks if socket is opened 
	 * and if not, throws an error message and exits
	 * we use internet namespace for address format: AF_INET 
	 * (other: PF_INET, AF_LOCAL, PF_LOCAL)
	 * and pipe-like style: SOCK_STREAM (other: SOCK_DGRAM, SOCK_RAW)
	 * and we set protocol as 0
	 */
	sn_socket = socket(AF_INET, SOCK_STREAM, 0);
	
	if(sn_socket < 0) 
	{
		perror("Couldn't open a socket");
        exit(EXIT_FAILURE);
    }

    /**
     *  fills sockaddr_in struct with data
     */
	sn_int_address.sin_family = AF_INET;
	sn_int_address.sin_port = htons(port);
	sn_int_address.sin_addr.s_addr = htonl(INADDR_ANY);
	
    /**
     * binds the socket with particular address
     * and checks if binding was successful
	 * and if not, throws an error message and exits
     */
    sn_binding = bind(sn_socket, (struct sockaddr *) &sn_int_address, 
						sizeof(sn_int_address));
    
    if(sn_binding < 0)
	{
		perror("Couldn't bind the socket with address");
		
		if(port <= IPPORT_RESERVED)
		{
			printf("It's most probably that you are not root"); 
			printf("and you use a port from within reserved range\n");
		}
		
        exit(EXIT_FAILURE);
    }
    
    listen(sn_socket, 10); 
    
    while(1)
    {
		printf("Waiting\n");
		aconn = accept(sn_socket, (struct sockaddr*)NULL, NULL); 

		printf("Connection\n");
        serverConnection(&sa, &aconn);
        
        printf("ServerNextLoop\n");
        
		sleep(1);
	}
    
    /**
     * shut down the socket, it is no longer needed
     * and we let whatever hasn't gone out to go with 0
     * (other: 1, 2)
     */
	if(shutdown(sn_socket, 0) < 0)
	{
		perror("Couldn't shutdown the socket");
        exit(EXIT_FAILURE);
	}
}

/**
 * Thread for single connection
 * 
 * TODO: security (e.g. handshake, hash-like), logging
 */
void serverConnection(struct s_address *sa, int *aconn)
{
	int conn_process_id = fork();
	
	if(conn_process_id < 0)
	{
		perror("Couldn't fork proccess");
		exit(EXIT_FAILURE);
	}
	
	//parent ends here;
	if(conn_process_id > 0) {
		return;
	}
	
	char send_buffer[1025];
    time_t now; 
	FILE *fp;
	
	now = time(NULL);
	
	pcr ports_return = checkingPorts(*sa);
	
	if(ports_return.success == 0)
		snprintf(send_buffer, sizeof(send_buffer), "%.24s: %s\r\n", ctime(&now), "Checking problem");
	else
		snprintf(send_buffer, sizeof(send_buffer), "%.24s: %s\r\n", ctime(&now), ports_return.ret);
	
	write(*aconn, send_buffer, strlen(send_buffer)); 
	
	fp = fopen("portstatus", "a");
	fputs("!", fp);
	fclose(fp);
	
	shutdown(*aconn, SHUT_RDWR);
	
	_exit(EXIT_SUCCESS);
}

/**
 * Ports checking
 */
void checkPorts(struct s_address sa)
{
	FILE *fp;
	time_t time_r;
	struct tm *ltime;
	char lbuf[50];
	char *buff;
	
	while(1)
	{
		fp = fopen("ports_status", "a");
				
		if(fp == NULL) 
		{
			perror("Status file write");
			exit(EXIT_FAILURE);
		}
		
		/**
		 * Gets current time
		 */
		time(&time_r);
		
		strftime(lbuf, 50, "%c", localtime(&time_r));
		
		fputs(lbuf, fp);
		fputs("-", fp);

		/**
		 * Actual ports checking
		 */
		pcr ports_return = checkingPorts(sa);
		
		if(ports_return.success == 0)
		{
			perror("Ports checking failed");
			
			fclose(fp);
			
			exit(EXIT_FAILURE);
		}
		
		fputs(ports_return.ret, fp);
		
		fputs("\n", fp);
		
		fclose(fp);
						
		sleep(60);
	}
}

/**
 * Goes through ports and check each of them
 */
pcr checkingPorts(struct s_address sa)
{
	int k = 0;
	char *ports_status;
	int chk_socket;
	pcr ports_return;
	
	ports_return.ret = calloc(sizeof(char), 100);
	ports_status = calloc(sizeof(char), 100);
	
	strcpy(ports_status, "");
	
	for(k=0; k < sa.ports.size; k++)
	{
		int chk_port = (int) *(sa.ports.ports+k);
		struct sockaddr_in chk_int_address;
		
		chk_int_address.sin_family = AF_INET;
		//chk_int_address.sin_addr.s_addr = htonl(INADDR_ANY);		
		chk_int_address.sin_addr.s_addr = inet_addr("127.0.0.1");		
		chk_int_address.sin_port = htons(chk_port);
		
		/**
		 * tries to open socket
		 */			
		chk_socket = socket(AF_INET, SOCK_STREAM, 0);
		
		if(chk_socket < 0) 
		{
			ports_return.success = 0;
			strcpy(ports_return.ret, "Couldn't open a socket");
			
			return ports_return;
		}
		
		/**
		 * tries to connect with particular address using the socket
		 */
		int chk_connection = connect(chk_socket, 
								(struct sockaddr *) &chk_int_address,
								sizeof(chk_int_address));
		
		strncat(ports_status, "[", 2);
		
		char chk_port_str[10];
		
		snprintf(chk_port_str, 10, "%d", chk_port);
		
		strncat(ports_status, chk_port_str, sizeof(chk_port_str));
		
		strncat(ports_status, ":", 1);
		
		if(chk_connection < 0)
		{
			strncat(ports_status, "0", 1);
		}
		else
		{
			strncat(ports_status, "1", 1);
		}
		
		strncat(ports_status, "]", 1);
	}
	
	/**
	 * close the socket, we have checked if ports are open
	 */
	if(close(chk_socket) < 0)
	{
		ports_return.success = 0;
		strcpy(ports_return.ret, "Couldn't shutdown the socket");
		
		return ports_return;
	}
	
	ports_return.success = 1;
	strcpy(ports_return.ret, ports_status);
	
	free(ports_status);
	
	return ports_return;
}
