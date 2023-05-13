#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include "hole.h"


#define DEST_PORT 1500
#define DEST_IP "127.0.0.1" 
#define MAX_DATA 100000
 
#define HEAP_INFO -1
#define FREE 0

#define MSG_END "000"
#define MSG_DATA_NEED "111"
#define MSG_HOLES "222"
#define MSG_ERRO "EEE"
#if PTR_SIZE == 4
typedef uint32_t CHUNK_PTR;
#else
typedef uint64_t CHUNK_PTR;
#endif

void parse_holes(int sockfd)
{
    int data_buf[MAX_DATA];
    memset(data_buf, -2, sizeof(data_buf));
    send(sockfd, MSG_DATA_NEED, 3, 0); 

    // read data len
    char data_len_buf[4] = {0};
    uint8_t data_len_already_read = 0;
    while (data_len_already_read < 4) {
        ssize_t read_bytes  = recv(sockfd, &data_len_buf[data_len_already_read], 1, 0);
        if (read_bytes < 0) {
            printf("Failed to recieve date length!\n");
            exit(0);
        }
        data_len_already_read += read_bytes;
    }

    uint32_t data_len = *(uint32_t*)data_len_buf;

    uint32_t already_read = 0;
    while (already_read < data_len) {
        ssize_t cur_read = recv(sockfd, &data_buf[already_read], data_len - already_read, 0);
        if (cur_read < 0) {
            printf("Failed to receive data, err is %s\n", strerror(errno));
            exit(0);
        }

        already_read += cur_read;
    }


    //simulate                          

    uint64_t total_mallocs = 0;  // total malloc number
    void *malloc_sequence_addr[1024];
    memset(malloc_sequence_addr, 0, sizeof(malloc_sequence_addr));

    int malloc_primitive_number[1024]; // all primitive numbers
    int malloc_op_index[1024];         // all op indexes
    memset(malloc_primitive_number, -1, sizeof(malloc_primitive_number)); 
    memset(malloc_op_index, -1, sizeof(malloc_op_index)); 


    int *ptr = data_buf;
    int *dog = 0;

    while(*ptr != -2)
    {
        int buf[4];
        buf[0] = *ptr;      // flag
        buf[1] = *(ptr+1);  // argument
        buf[2] = *(ptr+2);  // primitive number
        buf[3] = *(ptr+3);  // op index
        int flag = buf[0];
        if(flag == -2)
            break;
        switch(flag)
        {
            case HEAP_INFO:
            {
                T_HOLE cur_hole;
                send(sockfd, MSG_HOLES, 3, 0);

                //malloc info
                for(int i = 0; i < total_mallocs; i++){
                    CHUNK_PTR *dog = malloc_sequence_addr[i];
                    if (dog == 0x0) {
                        continue;
                    }

                    int pnum = malloc_primitive_number[i];
                    int op_index = malloc_op_index[i];

                    cur_hole.addr = dog - 2;
                    cur_hole.size = *(dog-1);
                    cur_hole.pnum = pnum;
                    cur_hole.op_index = op_index;
                    cur_hole.type = ALLOCATED_CHUNK;
                    cur_hole.alloc_index = i;
                    send(sockfd, &cur_hole, sizeof(cur_hole), 0);                
                }

                // parse top chunk
                CHUNK_PTR *top_chunk_ptr = (CHUNK_PTR*)(MAIN_ARENA_BASE + FASTBIN_OFFSET + NB_FASTBINS * PTR_SIZE);
                cur_hole.addr = *top_chunk_ptr;
                cur_hole.size = *((CHUNK_PTR*)(*top_chunk_ptr) + 1);
                cur_hole.type = TOP_CHUNK;
                cur_hole.alloc_index = 0;
                cur_hole.alloc_index = total_mallocs;
                send(sockfd, &cur_hole, sizeof(cur_hole), 0);

                // last remainder
                CHUNK_PTR *last_remainder_ptr = (CHUNK_PTR*)(MAIN_ARENA_BASE + FASTBIN_OFFSET + (NB_FASTBINS + 1) * PTR_SIZE);
                if (*last_remainder_ptr != 0x0) {
                    cur_hole.addr = *last_remainder_ptr;
                    cur_hole.size = *((CHUNK_PTR*)(*last_remainder_ptr) + 1);
                    cur_hole.type = HOLE_LAST_REMAINDER;
                    cur_hole.alloc_index = 0;
                    send(sockfd, &cur_hole, sizeof(cur_hole), 0);
                }



#if HAS_TCACHE // parse tcache if needed
                for(int i = 0; i < TCACHE_MAX_BINS; i++) {                    
                    CHUNK_PTR *dog = HEAP_BASE + TCACHE_ENTRY_OFFSET + i * PTR_SIZE;
                    if(*dog==0)continue;
                    while(*dog != 0x00) {
                        dog = *dog;
                        cur_hole.addr = dog - 2; 
                        cur_hole.size = *(dog-1);
                        cur_hole.type = HOLE_TCACHE_BIN;
                        cur_hole.alloc_index = 0;
                        send(sockfd, &cur_hole, sizeof(cur_hole), 0);
                    }; 
                }

#endif

                //arena_fastbin
                for(int i=0; i < NB_FASTBINS; i++) {
                    CHUNK_PTR *dog = (CHUNK_PTR*)(MAIN_ARENA_BASE + FASTBIN_OFFSET + i * PTR_SIZE);
                    if (*dog == 0x0) {
                        continue;
                    }
                    cur_hole.addr = *dog;
                    cur_hole.size = *((CHUNK_PTR*)(*dog) + 1);
                    send(sockfd, &cur_hole, sizeof(cur_hole), 0);

                    CHUNK_PTR next = *((CHUNK_PTR*)(*dog) + 2);
                    while (next) {
                        cur_hole.addr = next;
                        cur_hole.size = *((CHUNK_PTR*)(next) + 1);
                        cur_hole.type = HOLE_FAST_BIN;
                        send(sockfd, &cur_hole, sizeof(cur_hole), 0);
                        cur_hole.alloc_index = 0;
                        next = *((CHUNK_PTR*)(next) + 2);
                    };
                }
               
                for(int i = 0; i < (NBINS * 2 - 2); i += 2) {
                    CHUNK_PTR *FD = (CHUNK_PTR*)(MAIN_ARENA_BASE + BINS_OFFSET + i * PTR_SIZE);
                    CHUNK_PTR loop_addr = MAIN_ARENA_BASE + BINS_OFFSET + (i-2) * PTR_SIZE;
                    if (*FD == loop_addr) {
                        continue;
                    }
                    

                    CHUNK_PTR *next = FD;
                    do {
                        if (*next == 0x0) {
                            break;
                        }
                        cur_hole.addr = *next;
                        cur_hole.size = *((CHUNK_PTR*)(*next) + 1);
                        if (i == 0) {
                            cur_hole.type = HOLE_UNSORTED_BIN;
                        } else {
                            cur_hole.type = HOLE_NORMAL_BIN;
                        }
                        cur_hole.alloc_index = 0;
                        send(sockfd, &cur_hole, sizeof(cur_hole), 0);
                        next = ((CHUNK_PTR*)(*next) + 2);
                    } while (*(next) != loop_addr);

                }
                
                cur_hole.addr = 0xdeadbeef;  // mark as end
                send(sockfd, &cur_hole, sizeof(cur_hole), 0);

                break;
            }
            
            
            case FREE:
            {
                void *ptr_tmp;
                ptr_tmp = malloc_sequence_addr[buf[1]];
                malloc_sequence_addr[buf[1]] = 0x0;
                free(ptr_tmp);
                break;  
            };
            default:
            {
                if(flag > 0 && malloc_sequence_addr[total_mallocs] == NULL )
                {
                    void *addr_tmp = malloc(buf[1]);
                    
                    malloc_sequence_addr[total_mallocs] = addr_tmp;
                    malloc_primitive_number[total_mallocs] = buf[2];
                    malloc_op_index[total_mallocs] = buf[3];

                    total_mallocs++;
                    break;
                }
                    else break;
            }

        }
        ptr += 4;
    };
                                                
    send(sockfd, MSG_END, 3, 0);
    exit(0);
}


 
int main()
{
    int sockfd,new_fd;
    struct sockaddr_in dest_addr;
    int int_time;

    // printf("size is %d\n", sizeof(T_HOLE));
    // return -1;

    sleep(2);
    //socket
    sockfd=socket(AF_INET,SOCK_STREAM,0);
    if(sockfd==-1) {
        return -1;
    }


    dest_addr.sin_family=AF_INET;
    dest_addr.sin_port=htons(DEST_PORT);
    dest_addr.sin_addr.s_addr=inet_addr(DEST_IP);
    bzero(&(dest_addr.sin_zero),8);
    

    if (connect(sockfd,(struct sockaddr*)&dest_addr,sizeof(struct sockaddr))==-1) { 
        return -1;
    } 

    brk(HEAP_BASE);  // adjust heap start so that python generated C code can has the same heap start address

    while (1) {
        char cmd[2] = {0};
        while (1) {
            ssize_t read_len = read(sockfd, cmd, sizeof(char));
            if (read_len < 0) {
                printf("Cannot read cmd!\n");
                return -1;
            }

            if (read_len == 0) {
                continue;
            }
            break;
        }

        // printf("CMD is %c\n", cmd[0]); DO NOT USE PRINTF

        if (cmd[0] == 'N') {  // new case
            pid_t work_pid = fork();
            if (work_pid == 0) {//child process
                parse_holes(sockfd);
            }
            else if (work_pid < 0) {//child process
                printf("Unable to fork work process!\n");
                return -1;
            } else {//parent process
                //printf("fork new process successfully!\n");
                int status;
                waitpid(work_pid, &status, 0);
                if (status!=0) {
                    send(sockfd, MSG_ERRO, 3, 0);
                }
            }
        } else if (cmd[0] == 'Q') {  // quit
            break;
        }
    }


    close(sockfd);
    return 0;   
} 
