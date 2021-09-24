#include <signal.h>

#include "sock_utils.h"
#include "string_utils.h"

static volatile int keep_running = 1;

// default interface name if no option selected
const char* itf_default_name = "eno1";

// get SIGINT to proper exit
static inline void int_handler(){

    keep_running = 0;
}

int main(int argc, char **argv){

    signal(SIGINT, int_handler);

    char itf_spec[IFNAMSIZ + 1];

    if (argc == 3 && (strcmp(argv[1], "-i") == 0 || strcmp(argv[1], "--interface") == 0)){
        safe_strcpy(itf_spec, IFNAMSIZ + 1, argv[2]);
        printf("Using interface %s interface...\n", itf_spec);
    }
    else if (argc == 2){
        printf("selecting interface from list TODO\n");
        return EXIT_SUCCESS;
    }
    else{
        printf("Using default eno 1 interface...\n");
        strcpy(itf_spec, itf_default_name);
    }

    int sock = init_sock(itf_spec);

    if (sock < 0){
        perror("fatal error : failed to init socket\n");
        close(sock);
        return EXIT_FAILURE;
    }

    // allocating big buffer for receive sock data
    unsigned char *buffer = (unsigned char *)malloc(BUFF_SIZE);

    if (buffer == NULL){
        perror("error : failed to allocate buffer\n");
        close(sock);
        return EXIT_FAILURE;
    }
     
    fd_set read_fds, temp;

    FD_ZERO(&read_fds);
    FD_ZERO(&temp);
    FD_SET(sock,&read_fds);

    while(keep_running) {

        temp = read_fds;

        int ret = select(sock + 1, &temp, NULL, NULL, NULL);
        
        if (ret == -1){
            perror("error : failed to select()\n");
            return EXIT_FAILURE;
        }

        if (FD_ISSET(sock, &temp)) {

            memset(buffer, 0x00, BUFF_SIZE);

            // receiving and  processing data
            ret = recv(sock, buffer, BUFF_SIZE-1, MSG_TRUNC);
            if (ret > 0){

                process_frame(buffer , ret);

                printf("\n\n\tRaw data:\n\n");

                // print raw data in hex
                for (int i = 0; i < ret; i++){
                    printf("%02X ", *(buffer+i));
                }
                printf("\n");
            }
        }
    }


    printf("Exit : ok\n");
    free(buffer);
    close(sock);

    return EXIT_SUCCESS;

}
