/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"
//#include <stdio.h>    // added for printf
/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    bool failed_to_find = false;
    struct aesd_buffer_entry *ret = NULL; 
    // check for args validity
    if(buffer != NULL) {
        if(entry_offset_byte_rtn != NULL) {
            size_t local_char_offset              = char_offset+1;
            uint8_t local_out_offs                = buffer->out_offs;
            uint8_t local_in_offs                 = buffer->in_offs;
            struct aesd_buffer_entry *local_entry = &((buffer->entry)[local_out_offs]); 
            // iterate till desired entry reached
            while(local_char_offset > (local_entry->size)) {
                // check if out_offs is within in_offs
                if((buffer->full) && (buffer->in_offs == 0) && (buffer->out_offs == 0)) {
                    if(local_out_offs == (AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - 1)) {
                        failed_to_find = true;
                        break;
                    }
                } else {
                    if(local_out_offs == (local_in_offs -1)) {
                        failed_to_find = true;
                        break;
                    }
                }
                // shift to next entry and retry
                local_char_offset -= (local_entry->size);
                local_out_offs = (local_out_offs == (AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - 1)) ? \
                                  0:local_out_offs+1;
                local_entry = &((buffer->entry)[local_out_offs]);
            }
            // set return parameters
            if(!failed_to_find) {
                *entry_offset_byte_rtn = (local_char_offset-1);
                ret = local_entry;
            }
        } else {
            // invalid add_entry parameter. Report error
            //printf("Invalid buffer pointer passed to fops\n");
        }    
    } else {
        // invalid buffer parameter. Report error
        //printf("Invalid entry_offset_byte_rtn pointer passed to fops\n");
    }

    return ret;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
struct aesd_buffer_entry *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    // check for args validity
    if(buffer != NULL) {
        if(add_entry != NULL) {

            uint8_t local_in_offs   = buffer->in_offs;
            uint8_t local_out_offs  = buffer->out_offs;
            struct aesd_buffer_entry *ret_ptr = NULL;

            // return case
            if(buffer->full) {
                ret_ptr = buffer->entry[local_in_offs];
            }
            // adding element to buffer
            buffer->entry[local_in_offs] = *add_entry;
            // setting input and output buffer offsets
            if(buffer->full) {    
                local_out_offs = (local_out_offs == (AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - 1)) ? \
                                  0:local_out_offs+1;
            }
            local_in_offs = (local_in_offs == (AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - 1)) ? \
                             0:local_in_offs+1;

            buffer->in_offs  = local_in_offs;
            buffer->out_offs = local_out_offs;
            if(local_in_offs == local_out_offs) {
                // buffer full. Set flag
                buffer->full = true;
            }
        } else {
            // invalid add_entry parameter. Report error
            //printf("Invalid buffer pointer passed to add_entry\n");
        }    
    } else {
        // invalid buffer parameter. Report error
        //printf("Invalid entry pointer passed to add_entry\n");
    }
    
    return ret_ptr;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
