#include <signal.h>

#include "sock_utils.h"
#include "string_utils.h"

// default interface name if no option selected

const char* ITF_DEFAULT_NAME = "eno1";

// dynamic allocated array that will receive datas

static unsigned char* buffer = NULL;

// get SIGINT to proper exit freeing memory

static inline void int_handler(int signum){

    free(buffer);
    printf("Exiting program : ok\n");
    exit(EXIT_SUCCESS);
}

long get_user_input(int);
void free_double_pointer(void**, int); 

int main(int argc, char **argv){

    // set the signal handler to catch Ctrl + c interrupt
    signal(SIGINT, int_handler);

    char itf_spec[IFNAMSIZ];
    char **itf_list = NULL;

    // -i option : provide interface name to bind to
    if (argc == 3 && (strcmp(argv[1], "-i") == 0 || strcmp(argv[1], "--interface") == 0)){

        safe_strcpy(itf_spec, IFNAMSIZ, argv[2]);
        printf("Using interface %s interface...\n", itf_spec);
    }

    // -l option : select interface from list
    else if (argc == 2 && (strcmp(argv[1], "-l") == 0 || strcmp(argv[1], "--list") == 0)){

        itf_list = (char**)malloc(sizeof(char*) * ITF_MAX_NBR);

        if (itf_list == NULL){
            perror("error while allocating array\n");
            return EXIT_FAILURE;
        }

        int nbr_itf = get_itf_list(itf_list, ITF_MAX_NBR);

        if (nbr_itf <= 0){
            perror("error while getting interface list or no interface is available\n");
            return EXIT_FAILURE;
        }

        printf("DEBUG : get interfaces list ok\n");

        printf("\nList of available interfaces :\n");
        for(int i = 0; i < nbr_itf; i++){
            printf("\t | [%u] interface name : %s\n", i, itf_list[i]);
        }

        long itf_nbr = get_user_input(nbr_itf);
        printf("Using interface %s to bind with...\n", itf_list[itf_nbr]);
        safe_strcpy(itf_spec, IFNAMSIZ, itf_list[itf_nbr]);

        free_double_pointer((void**)itf_list, nbr_itf); 

    }
    // no option : default interface name eno1
    else{
        printf("Using default eno 1 interface...\n");
        safe_strcpy(itf_spec, strlen(ITF_DEFAULT_NAME), ITF_DEFAULT_NAME);
    }

    
    // create sock and initialize it with interface name

    int sock = init_sock(itf_spec);

    if (sock < 0){
        perror("fatal error : failed to init socket\n");
        close(sock);
        return EXIT_FAILURE;
    }

    // allocating a big buffer for receive sock data

    buffer = (unsigned char *)malloc(BUFF_SIZE);

    if (buffer == NULL){
        perror("error : failed to allocate buffer\n");
        close(sock);
        return EXIT_FAILURE;
    }
     
    // setting file descriptor here for the socket

    fd_set read_fds, temp;

    FD_ZERO(&read_fds);
    FD_ZERO(&temp);
    FD_SET(sock,&read_fds);

    while(1) {

        temp = read_fds;

        int ret = select(sock + 1, &temp, NULL, NULL, NULL);
        
        if (ret == -1){
            perror("error : failed to select()\n");
            return EXIT_FAILURE;
        }

        if (FD_ISSET(sock, &temp)) {

            memset(buffer, 0x00, BUFF_SIZE);

            // receiving and processing data
            // why MSG_TRUNC ? an experiment approch to test some things
            
            ret = recv(sock, buffer, BUFF_SIZE-1, MSG_TRUNC);
            
            if (ret > 0){

                // print current local time in hh:mm:ss
                print_current_time();
                
                // process parsing
                process_frame(buffer , ret);

                printf("\n\nRaw data:\n");

                // print raw data in hex
                for (int i = 0; i < ret; i++){
                    
                    if (i % 32 == 0) 
                        printf("\n");

                    printf("%02X ", *(buffer+i));
                }
                printf("\n");
            }
        }
    }


    close(sock);

    return EXIT_SUCCESS;

}

// get user input for interface number choice

long get_user_input(int max_itf_nbr){

    char* end = NULL;
    char buffer[255];
    long number = 0;

    printf("Choose an interface to bind to [number]: \n");

    while (fgets(buffer, sizeof(buffer), stdin) != NULL){

        number = strtol(buffer, &end, 10);

        if (end == buffer || *end !='\n' || number > max_itf_nbr || number < 0){
            printf("Not a valid input. Enter a number between 0 and %u\n", max_itf_nbr -1);
            exit(EXIT_FAILURE);
        } 
        else break;
    }

    return number;
}

// releases any double pointer dynamically allocated

void free_double_pointer(void** double_ptr, int size){

    for(int i = 0; i < size; i++)
        free(double_ptr[i]);
    free(double_ptr);

}
