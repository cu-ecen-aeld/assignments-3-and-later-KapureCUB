#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define REQUIRED_ARGS      (3)
#define FILE_PERMISSIONS   (0644)

int fd, wret;
int arg_check    = 0;
int write_enable = 0;
char *file, *string;


void usage(void) {
    printf("Error occurred. Check /var/log/syslog for detailed error log.");
    printf("\n\nUSAGE: ./writer.sh writefile writestr\n");
    printf("    writefile  - file to overwrite\n");
    printf("    writestr   - string to write\n");
}

int main(int argc, char *argv[])
{
    // open syslog 
    openlog("writer.c ", 0, LOG_USER);
    
    // arguments check
    if(argc != REQUIRED_ARGS) {
        syslog(LOG_ERR, "Invalid number of arguments passed. Passed %d, required %d", argc, (REQUIRED_ARGS-1));
        usage();
        exit(1);
    } else { 
        file = argv[1];   
        string = argv[2];
        arg_check = 1;
    }
    
    if(arg_check == 1) {
        // opening file
        fd = open (file, O_WRONLY | O_CREAT | O_TRUNC, FILE_PERMISSIONS);
        if (fd == -1) {
            syslog(LOG_ERR, "Error opening file %s : %s\n", file, strerror(errno));
            usage();
            exit(1);
        }
        
        // writting to file
        syslog(LOG_DEBUG, "Writing %s to %s\n", string, file);
        int length = strlen(string);
        wret = write (fd, string, length);
        if (wret == -1) {
            syslog(LOG_ERR, "Error writing to file %s string %s : %s\n", file, string, strerror(errno));
            usage();
            exit(1);
        } else if (wret != length) {
            syslog(LOG_ERR, "All string contents not written to file. Written %d of %d characters. \
                            \n", wret, length);
        }

        // closing file
        if (close (fd) == -1) {
            syslog(LOG_ERR, "Error closing file %s : %s\n", file, strerror(errno));
            usage();
            exit(1);
        }
    }
}

