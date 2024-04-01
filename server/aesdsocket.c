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

#include "queue.h"
#include <time.h>
#include <pthread.h>
#include <sys/time.h>

// additions for assignment 9
#include <sys/ioctl.h>
#include "../aesd-char-driver/aesd_ioctl.h"

#define PORT                     "9000"
#define BACKLOGS                 5
#define MAX_BUFFER_SIZE          256
#define IOCTL_CMD_STR            "AESDCHAR_IOCSEEKTO:"
#define IOCTL_STR_CMD_LEN        (sizeof(IOCTL_CMD_STR) - 1)      // escape /n
#define MINIMUM_IOCTL_CMD_LEN    22

#define USE_AESD_CHAR_DEVICE     1

#ifdef USE_AESD_CHAR_DEVICE
    #define OUTPUT_FILE_PATH    "/dev/aesdchar"
#else
    #define OUTPUT_FILE_PATH    "/var/tmp/aesdsocketdata"
#endif

int socket_fd;
int signal_caught = 0;
int signal_timer  = 0;
char host[NI_MAXHOST];     // for getting connection logs

int ioctl_found = 1;

/*************************** Thread data structure ****************************/ 
typedef struct {
    pthread_mutex_t* th_mutex;
    int new_socket_fd; 
    int log_file_fd;
    int complete_flag; // 0-not complete; 1-success; -1-failure
}thread_data_t;

/************************** Linked list data structure ************************/ 
typedef struct slist_thread_s slist_thread_t;
struct slist_thread_s {
    pthread_t thread;
    thread_data_t* td;
    SLIST_ENTRY(slist_thread_s) entries;
};

/**************************************************************************//**
 * Signal handler function. Called when a SIGINT or SIGTERM event is triggered.
 *
 * @param[in] sig - signal num caught
 *
 *****************************************************************************/
static void signal_handler(int sig) {
    signal_caught = sig;
    shutdown(socket_fd, SHUT_RDWR); // shutdown socket
}

/**************************************************************************//**
 * Timer handler function. Called when a SIGALRM event is triggered.
 *
 * @param[in] sig - signal num caught
 *
 *****************************************************************************/
static void timer_handler( int sn ) {
    if(sn == SIGALRM) {
        signal_timer = 1;
    }
}

/**************************************************************************//**
 * Send data to client. Reads data from OUTPUT_FILE_PATH and sends it over the 
 * socket connection.
 *
 * @param[in] socket - FD of socket file created
 * @param[in] fd     - FD of OUTPUT_FILE_PATH
 * 
 * @return    ret    - success(0) or failure(-1) 
 *
 *****************************************************************************/
static int send_data_to_client(int socket, int fd) {
    
    int ret = 0;
    ssize_t  bytes_read;
    off_t file_offset = 0;
    char eof_char = 0;
    ssize_t sent_cnt;
    char read_buffer[MAX_BUFFER_SIZE];
    memset(read_buffer, 0, MAX_BUFFER_SIZE);

    while(1) {

        if(ioctl_found == 0)
            bytes_read = read(fd, read_buffer, MAX_BUFFER_SIZE);
        else 
            bytes_read = pread(fd, read_buffer, MAX_BUFFER_SIZE, file_offset);

        syslog(LOG_INFO, "Read %lu bytes from file\n", bytes_read);
        if(bytes_read == -1) {
            syslog(LOG_ERR, "Error reading file in send data");
            ret = -1;
            break;
        }
        //end of file
        if(bytes_read == 0) { 
            // if no file data, sending \n 
            if(eof_char != '\n') {
                sent_cnt = send(socket, "\n", 1, 0);
                if(sent_cnt == -1) { 
                    syslog(LOG_ERR, "Error sending data to socket");
                }
            }
            ret = 0;
            break;
        }
        // valid data to send via socket
        sent_cnt = send(socket, read_buffer, bytes_read, 0);
        if(sent_cnt == -1) {
            syslog(LOG_ERR, "Error sending data to socket");
            ret = -1;
            break;
        }

        eof_char = read_buffer[bytes_read-1];
        // set offset for new read
        file_offset += bytes_read;

        memset(read_buffer, 0, MAX_BUFFER_SIZE);
        syslog(LOG_INFO, "Sent %lu bytes to client\n", sent_cnt);    
    }

    return ret;
}


/**************************************************************************//**
 * Read packet from socket connection and write it to OUTPUT_FILE_PATH.
 *
 * @param[in] socket - FD of socket file created
 * @param[in] fd     - FD of OUTPUT_FILE_PATH
 * 
 * @return    ret    - success(0) or failure(-1) 
 *
 *****************************************************************************/
static int read_packet(int socket, int fd, pthread_mutex_t *m) {
    
    int result        = 1;
    int continue_read = 1;
    //int ioctl_found   = 1;
    ssize_t ret; 

    char read_buffer[MAX_BUFFER_SIZE];
    memset(read_buffer, 0, MAX_BUFFER_SIZE);
    ssize_t byte_read, total_byte_read = 0;

    struct aesd_seekto seekto;

    char *buff = malloc(1);
    if(!buff) {
        syslog(LOG_ERR, "Failure allocating dynamic buffer while reading");
        result        = -1;
        continue_read = 0;
    }

    // allocate null character to buff
    *buff = '\0';

    while(continue_read) {
        //read from socket
        byte_read = recv(socket, read_buffer, (MAX_BUFFER_SIZE-1), 0);
        if(byte_read == -1) {
            continue_read = 0;
            result = -1;
            syslog(LOG_ERR, "Error reading data from socket\n");
        } else  if(byte_read == 0) {  
            continue_read = 0;
            result = 0;
        } else {
            syslog(LOG_ERR, "Received %lu bytes from client\n", byte_read);

            // Calculate the new buffer size
            int new_buff_len = strlen(buff) + strlen(read_buffer) + 1;
            char *ret_buff   = realloc(buff, new_buff_len);
            if (!ret_buff) {
                syslog(LOG_ERR, "Failure calling relloc while reading");
                continue_read = 0;
                result = -1;
                continue;
            }

            // assign the new relloc address to buff 
            buff = ret_buff;
            total_byte_read += byte_read;

            // copy data to new allocated buff
            strcpy(buff, read_buffer);

            // check for \n 
            char *nl_char = memchr(buff, '\n', MAX_BUFFER_SIZE);
            continue_read = (nl_char == NULL) ? 1:0; 
        }
    }

    #ifdef USE_AESD_CHAR_DEVICE
        // Check to see if we've gotten the ioctl command and the other arguments
        ioctl_found = strncmp(buff, IOCTL_CMD_STR, IOCTL_STR_CMD_LEN);
        if(ioctl_found == 0) {
            if(byte_read >= MINIMUM_IOCTL_CMD_LEN) {
                syslog(LOG_INFO, "IOCTL command received");
                
                // call the ioctl method and skip writting to file
                seekto.write_cmd        = (uint32_t)atoi(&buff[IOCTL_STR_CMD_LEN]);
                seekto.write_cmd_offset = (uint32_t)atoi(&buff[MINIMUM_IOCTL_CMD_LEN - 1]);
                syslog(LOG_INFO, "Write cmd %u and write cmd offset %u", seekto.write_cmd, seekto.write_cmd_offset);
                ioctl(fd, AESDCHAR_IOCSEEKTO, &seekto);
            }
        }
    #endif


    // write data to file /var/tmp/aesdsocketdata and check if ioclt command not found
    // acquire lock
    if((result != -1) && (ioctl_found != 0)) {
        if(pthread_mutex_lock(m) == 0) {
            ret = write(fd, buff, byte_read);
            pthread_mutex_unlock(m);
            if(ret == -1) {
                syslog(LOG_ERR, "Failure writing to file");
            } else {
                syslog(LOG_INFO, "Data written to file : %lu bytes\n", byte_read);
            }
        } else {
            syslog(LOG_ERR, "Failure acquiring lock for file write\n");
            result = -1;
        }
    }

    // perform cleanup
    free(buff);
    memset(read_buffer, 0, MAX_BUFFER_SIZE);
    return result;
}


/**************************************************************************//**
 * Function to initialize the socket. Creates a socket FD and start listening 
 * at the created connection.
 * 
 * @return    ret_val - returns FD of socket connection or failure(-1) 
 *
 *****************************************************************************/
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


/**************************************************************************//**
 * Accept socket connection and create a new FD for the transfer of data.
 *
 * @param[in] socket - FD of socket file created
 * 
 * @return    new_socket_fd - returns new FD of socket or failure(-1) 
 *
 *****************************************************************************/
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

/**************************************************************************//**
 * Accept socket connection and create a new FD for the transfer of data.
 *
 * @param[in] t_para - thread data structure for the thread
 * 
 * @return    new_socket_fd - returns new FD of socket or failure(-1) 
 *
 *****************************************************************************/
static void* socket_thread(void* t_para) {
    
    int result = 1;
    int ret;

    //setup threading info
    if(!t_para) {
        syslog(LOG_ERR, "Thread parameter is a null pointer");
        return NULL;
    }
    thread_data_t* t_data = (thread_data_t*) t_para;
    
    // continuously read
    while(1) {  
        //read full packet
        ret = read_packet(t_data->new_socket_fd, t_data->log_file_fd, \
                          t_data->th_mutex);
        if(ret == -1) { 
            syslog(LOG_ERR, "Error reading via socket");
            // failed
            result = -1;
            break;
        }
        if(ret == 0) { //connection ended
            break;
        }

        // retransmit the file
        syslog(LOG_INFO, "Sending data to client\n");
        ret = send_data_to_client(t_data->new_socket_fd, t_data->log_file_fd);
        if(ret == -1) {
            syslog(LOG_INFO, "Error sending data to client\n");
        }
        // reset the ioctl flag
        ioctl_found = 1;
    }

    // complete flag
    t_data->complete_flag = result;
    
    return t_para;
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
            syslog(LOG_INFO, "Running aesdsocket as a daemon for assignment 9");
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

    // register timer handler
    action.sa_handler = timer_handler; 
    ret = sigaction(SIGALRM, &action, NULL); 
    if(ret != 0) {
        syslog(LOG_ERR, "Could not setup SIGALRM handler\n");
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

    //create linked list
    SLIST_HEAD(slisthead, slist_thread_s) head;
    SLIST_INIT(&head);
    
    //create mutex
    pthread_mutex_t mutex;
    pthread_mutex_init(&mutex, NULL);
    
    //setup 10 second timer
    struct itimerval delay;

    delay.it_value.tv_sec     = 10;
    delay.it_value.tv_usec    = 0;
    delay.it_interval.tv_sec  = 10;
    delay.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &delay, NULL);
    
    char data[60];
    memset(&data, 0, sizeof(data));
    time_t rawNow;
    struct tm* now = (struct tm*)malloc(sizeof(struct tm));

    // accept 
    int new_socket_fd;
    int fd;

    // create /var/tmp/aesdsocketdata in append mode
    fd = open(OUTPUT_FILE_PATH, O_CREAT | O_RDWR | O_APPEND, S_IRUSR | S_IWUSR |
                                                             S_IRGRP | S_IWGRP | 
                                                             S_IROTH | S_IWOTH);
    
    while(socket_stat && !signal_caught) {
        new_socket_fd = socket_accept(socket_fd);
        if(new_socket_fd != -1) {
        
            // thread creation process
            pthread_t thread;
            thread_data_t* t_data = malloc(sizeof(thread_data_t));
            if(!t_data) {
                syslog(LOG_ERR, "Failed to allocate thread_data");
                socket_stat = 0;
                continue;
            }

            // fill in the thread data 
            t_data->th_mutex      = &mutex;
            t_data->new_socket_fd = new_socket_fd;
            t_data->log_file_fd   = fd;
            t_data->complete_flag = 0;
            
            //setup linked list element
            slist_thread_t* t_ptr = malloc(sizeof(slist_thread_t));
            if(t_ptr == NULL) { 
                syslog(LOG_ERR, "Failed to allocate linked list node");
                free(t_data);
                socket_stat = 0;
                continue;
            }

            ret = pthread_create(&thread, NULL, &socket_thread, t_data);
            if(ret != 0) {
                syslog(LOG_ERR, "Failed to create thread.\n");
                free(t_data);
                free(t_ptr);
                socket_stat = 0;
                continue;
            }
                
            // addend to linked list node
            t_ptr->thread = thread;
            t_ptr->td = t_data;
            SLIST_INSERT_HEAD(&head, t_ptr, entries);
        }

        #ifndef USE_AESD_CHAR_DEVICE
            // timer service routine
            if(signal_timer) {
                signal_timer = 0; 
                
                //get now
                time(&rawNow);
                now = localtime_r(&rawNow, now);
                
                //format timestamp
                memset(&data, 0, sizeof(data));
                strftime(data, sizeof(data), "timestamp: %Y, %m, %d, %H, %M, %S\n", now);

                ret = pthread_mutex_lock(&mutex);
                if(ret != 0) {
                    syslog(LOG_ERR, "Failed to lock timestamp");
                    socket_stat = 0;
                    ret = pthread_mutex_unlock(&mutex);
                    continue;
                }

                //write timestamp to file
                write(fd, data, strlen(data));
                ret = pthread_mutex_unlock(&mutex);
            }
        #endif

        // check for thread status and close if complete
        slist_thread_t* tp = NULL;
        slist_thread_t* next = NULL;
        SLIST_FOREACH_SAFE(tp, &head, entries, next) {
            //check complete flag
            if(tp->td->complete_flag == 1) {
                //remove from linked list
                SLIST_REMOVE(&head, tp, slist_thread_s, entries);
                
                //join 
                void* t_ret = NULL;
                ret = pthread_join(tp->thread, &t_ret);
                if(ret != 0) {
                    syslog(LOG_ERR, "Failed to end thread:%ld", tp->thread);
                    socket_stat = 0;
                }
                
                thread_data_t* tmp_ret = (thread_data_t *) t_ret;

                //close the socket
                syslog(LOG_DEBUG, "Closed connection from %s", host);
                close(tmp_ret->new_socket_fd);  
            
                //free thread data and thread struct
                free(tmp_ret);
                free(tp);
            }
            
        }
    }

    // terminate routine
    syslog(LOG_INFO, "Caught signal, exiting\n"); 
    if(socket_stat) {
        close(new_socket_fd);           // close accepted socket
        close(socket_fd);               // close socket
        #ifndef USE_AESD_CHAR_DEVICE
            remove(OUTPUT_FILE_PATH);       // remove log file
        #endif
        close(fd);
    }

    //free linked list
    void* t;
    while(!SLIST_EMPTY(&head)) {
        slist_thread_t* threadp = SLIST_FIRST(&head);
        SLIST_REMOVE_HEAD(&head, entries);
        pthread_join(threadp->thread, &t);
        free(t);
        free(threadp);
        threadp = NULL;
    }

    // free timer struct
    free(now);
    pthread_mutex_destroy(&mutex);
    closelog();                         // close log
    
    return 0;
}
