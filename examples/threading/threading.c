#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)


// convert msec to usec
#define MILLISECOND_TO_USEC    (1000)


void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    int ret;
    bool local_success = false;
    struct thread_data* args = (struct thread_data *) thread_param;

    // wait to start thread
    usleep((args->wait_to_obtain_ms)*MILLISECOND_TO_USEC);

    // call lock on mutex
    ret = pthread_mutex_lock(args->mutex);
    if(ret != 0) {
        ERROR_LOG("Error in acquiring lock in TID %lu. %s", pthread_self(), strerror(errno));
    }
    
    // wait for relaese
    usleep((args->wait_to_release_ms)*MILLISECOND_TO_USEC);
    
    // call unlock on mutex
    ret = pthread_mutex_unlock(args->mutex);
    if(ret != 0) {
        ERROR_LOG("Error in releasing lock in TID %lu. %s", pthread_self(), strerror(errno));
    } else {
        local_success = true;
    }
    
    // set success in return struct parameters
    if(local_success) {
        args->thread_complete_success = true;
    }

    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */
    // local variables
    bool ret = false;
    int ret_thread;

    // dynamically allocated memory for thread data
    struct thread_data *thread_param             = malloc(sizeof(struct thread_data));
    
    // filling in the thread data parameters
    thread_param->wait_to_obtain_ms       = wait_to_obtain_ms;
    thread_param->wait_to_release_ms      = wait_to_release_ms;
    thread_param->mutex                   = mutex;
    thread_param->thread_complete_success = false;

    // create thread
    ret_thread = pthread_create(thread, NULL, threadfunc, thread_param);
    if(ret_thread == 0) {
        DEBUG_LOG("Thread with TID %d started succesfully.", *thread);
        ret = true;
    } else {
        ERROR_LOG("Error creating thread with TID %lu. %s", *thread, strerror(errno));
    }

    return ret;
}

