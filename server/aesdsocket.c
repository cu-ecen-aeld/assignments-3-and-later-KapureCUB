#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <signal.h>

#define PORT                "9000"
#define BACKLOGS            5
#define OUTPUT_FILE_PATH    "/var/tmp/aesdsocketdata"
#define MAX_BUFFER_SIZE     256


int socket_fd;
int signal_caught = 0;
char host[NI_MAXHOST];     // for getting connection logs

static void signal_handler(int sig) {
    signal_caught = sig;
    shutdown(socket_fd, SHUT_RDWR); // shutdown socket
}


static int send_data_to_client(int socket, FILE * fd) {
    
    int ret = 0;
    int  bytes_read;
    char *packet_ptr;
    size_t sent_cnt;
    char read_buffer[MAX_BUFFER_SIZE];
    memset(read_buffer, 0, MAX_BUFFER_SIZE);
    while (!feof(fd))
    {
        bytes_read = fread(read_buffer, 1, MAX_BUFFER_SIZE, fd);
        packet_ptr = read_buffer;
        sent_cnt = send(socket, packet_ptr, bytes_read, 0);
        if (sent_cnt == -1) {
            syslog(LOG_ERR, "Unable to send data to client\n");
            ret = -1;
            break;
        }
        memset(read_buffer, 0, MAX_BUFFER_SIZE);
        syslog(LOG_INFO, "Sent %lu bytes to client\n", sent_cnt);
    }

    return ret;
}

static int read_packet(int socket, FILE * fd) {
    
    int result = 0;
    char read_buffer[MAX_BUFFER_SIZE];
    memset(read_buffer, 0, MAX_BUFFER_SIZE);
    int continue_read = 1;
    
    while(continue_read) {
        //read from socket
        ssize_t byte_read = recv(socket, read_buffer, (MAX_BUFFER_SIZE-1), 0);
        if(byte_read == -1) {
            continue_read = 0;
            result = -1;
            syslog(LOG_ERR, "Error reading data from socket\n");
        } else  if(byte_read == 0) {  
            continue_read = 0;
            result = -1;
        } else {
            syslog(LOG_ERR, "Received %lu bytes from client\n", byte_read);
            // check for \n
            char *nl_char = memchr(read_buffer, '\n', MAX_BUFFER_SIZE);
            continue_read = (nl_char == NULL) ? 1:0;

            // write data to file /var/tmp/aesdsocketdata
            fwrite(read_buffer, byte_read, 1, fd);
            // clear read_buffer
            memset(read_buffer, 0, MAX_BUFFER_SIZE);

            syslog(LOG_INFO, "Data written to file\n");
        }
    }

    return result;
}

static int aesd_socket_init(void) {
    // socket variables 
    int ret;
    int ret_val = -1;
    int reuse_val = 1;
    int socket_fd;
    struct addrinfo hints;
    struct addrinfo *servinfo; 
    
    memset(&hints,   0, sizeof(hints));

    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    // create socket 
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        syslog(LOG_ERR, "Error creating socket: \
                         Unable to create file describtor\n");
        return -1;
    } else {
        // setup SOCKOPTS for reusing the address SO_REUSEADDR
        ret = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, \
                         &reuse_val, sizeof(reuse_val));
        if (ret == 0) {
                syslog(LOG_INFO, "Socket created succesfully\n");
        } else {
            close(socket_fd);
            syslog(LOG_ERR, "Error creating socket: \
                             Failed to setsockopt SO_REUSEADDR\n");
            return -1;
        }
    }

    // get address info
    ret = getaddrinfo(NULL, PORT, &hints, &servinfo);
    if (ret != 0) {
        close(socket_fd);
        syslog(LOG_ERR, "Unable to get addr info \n");
        return -1;
    } else {
        // bind socket
        // iterate through the linked list returned from getaddrinfo
        for(struct addrinfo* itr = servinfo; itr != NULL; itr = itr->ai_next) { 
            ret = bind(socket_fd, itr->ai_addr, itr->ai_addrlen);
            if(ret == 0) { 
                syslog(LOG_INFO, "Socket bind completed succesfully\n");
                break;
            }
        }
        // free addrinfo before error checking
        freeaddrinfo(servinfo);

        if (ret == -1) {
            close(socket_fd);
            syslog(LOG_ERR, "ERROR binding socket\n");
            return -1;
        } 
    }

    // listen to created socket
    ret = listen(socket_fd, BACKLOGS);
    if (ret != -1) {
        ret_val = socket_fd;
    } else {
        close(socket_fd);
        syslog(LOG_ERR, "Error occurred during listening to socket\n");
        return -1;
    }

    return ret_val;
}

static int socket_accept(int socket_fd) {
    int ret;
    int new_socket_fd;
    struct sockaddr_storage    client_addr;
    socklen_t                  client_addr_size = sizeof client_addr;
    

    new_socket_fd = accept(socket_fd, (struct sockaddr*)&client_addr, \
                               &client_addr_size);
    if(new_socket_fd == -1){
        syslog(LOG_ERR, "Failed to execute socket accept\n");
        return -1;
    }
    // get client ip
    ret = getnameinfo((struct sockaddr*)&client_addr, client_addr_size, host,\
                       sizeof(host), NULL, 0, NI_NUMERICHOST);
    if(ret != 0) {
        syslog(LOG_ERR, "Failed to get hostname\n");
    }
    syslog(LOG_INFO, "Accepted connection from %s\n", host);

    return new_socket_fd;
}

int main(int argc, char *argv[])
{
    openlog("LOG for AESD Socket", 0, LOG_USER);

    int ret;
    int socket_stat = 1;
    bool daemon_enable  = false;

    // check arguments passed
    if(argc == 2) {
        if (strcmp(argv[1], "-d") == 0) {
            // argument for running as daemon process
            daemon_enable = true;
            syslog(LOG_INFO, "Running aesdsocket as a daemon");
        }    
    } else if(argc == 1) {
        // argument for running as a normal process
        syslog(LOG_INFO, "Running aesdsocket as a normal process");
    } else {
        // error
        fprintf(stderr, "ERROR, invalid arguments.\nUsage: aesdsocket\nOPTIONS:\n\t[-d] - run as daemon.\n");
        exit(-1);
    }

    // initialize socket if args check is successful
    if((socket_fd = aesd_socket_init()) == -1) {
        socket_stat = 0;
    }

    // signal handle variables
    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = signal_handler;

    // setting up signal handling for SIGTERM and SIGINT
    ret = sigaction(SIGTERM, &action, NULL);
    if (ret != 0) {
        fprintf(stderr, "Could not setup SIGTERM handler\n");
        exit(-1);
    }

    ret = sigaction(SIGINT, &action, NULL);
    if (ret != 0) {
        fprintf(stderr, "Could not setup SIGINT handler\n");
        exit(-1);
    }

    // start daemon process based on flag
    if (daemon_enable) {
        syslog(LOG_INFO,"Executing Daemonization\n");
        pid_t pid = fork();
        if(pid == -1){ 
            syslog(LOG_ERR,"Error forking during daemon creation\n");
            exit(-1);
        } else if(pid != 0) { 
            //exit in parent
            exit(0); 
        }
        //setsid 
        setsid();
        // change directory
        chdir("/"); 
        //redirect stdin/out/err to /dev/null
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);
    }

    // accept 
    int new_socket_fd;
    FILE *fd;

    while(socket_stat && !signal_caught) {
        new_socket_fd = socket_accept(socket_fd);
        if(new_socket_fd == -1) {
            // retry
            continue;
        }

        // create /var/tmp/aesdsocketdata in append mode
        fd = fopen(OUTPUT_FILE_PATH, "a+");

        //read full packet
        ret = read_packet(new_socket_fd, fd);
        if(ret == -1) { 
            syslog(LOG_ERR, "Error reading via socket.\n");
            socket_stat = 0;
            fclose(fd);
            continue;
        }
        // // connection stopped
        // if(ret == 0) { 
        //     fclose(fd);
        //     continue;
        // }
        // close file to reopen
        fclose(fd);

        // open file in read mode
        fd = fopen(OUTPUT_FILE_PATH, "r+");

        // retransmit the file
        ret = send_data_to_client(new_socket_fd, fd);
        if(ret == -1) {
            syslog(LOG_INFO, "Error sending data to client\n");
        }

        syslog(LOG_INFO, "Closed connection from %s\n", host);
        close(new_socket_fd); 
        fclose(fd);
    }

    // terminate routine
    syslog(LOG_INFO, "Caught signal, exiting\n"); 
    if(socket_stat) {
        close(new_socket_fd);           // close accepted socket
        close(socket_fd);               // close socket
        remove(OUTPUT_FILE_PATH);       // remove log file
    }
    closelog();                     // close log
    
    return 0;
}