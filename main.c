/* Libraries */ 

#include <signal.h>  

#include "sock_utils.h" 
#include "string_utils.h"

// main option fields structure

typedef struct opt_args_main {

    uint8_t is_filter   : 2;
    uint8_t is_file     : 2;
    uint8_t is_itf      : 2;
    uint8_t is_godmode  : 2;


} __attribute__((packed)) opt_args_main;

// get SIGINT to proper exit freeing memory
void int_handler(int);
void handle_packet(u_char*, const struct pcap_pkthdr*, const u_char*);                

static const char* default_filename = "strings_log";

int main(int argc, char **argv) {
    
    // set the signal handler to catch Ctrl + c interrupt
    signal(SIGINT, int_handler);

    // global params for the PCAP session
    char device[IFNAMSIZ];
    char record_file[RECORD_FILENAME_SIZE];
    char pcap_filters[PCAP_FILTER_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    pcap_t *handle;

    int opt;
    opt_args_main opt_args;

    memset(&opt_args, 0, sizeof(opt_args));

    while ((opt = getopt(argc, argv, "i:r:f:gl")) != -1){

        switch (opt){

            case 'i':
                strncpy(device, optarg, IFNAMSIZ - 1);
                opt_args.is_itf = 1;
                break;

            case 'r':
                strncpy(record_file, optarg, RECORD_FILENAME_SIZE - 1);
                opt_args.is_file = 1;
                break;

            case 'g':
                opt_args.is_godmode = 1;
                break;

            // just an option to print the list of interfaces
            case 'l':
                print_itf_list();
                return EXIT_SUCCESS;
                break;

            case 'f':
                strncpy(pcap_filters, optarg, PCAP_FILTER_SIZE - 1);
                opt_args.is_filter = 1;
                break;

            case '?':
                if (optopt == 'i')
                    fprintf (stderr, "Option -%c requires an argument [interface_name] !\n", optopt);
                else if (optopt == 'r')
                    fprintf (stderr, "Option -%c requires an argument [record_file_name] !\n", optopt);
                else if (optopt == 'f')
                    fprintf (stderr, "Option -%c requires an argument [pcap_filters] !\n", optopt);
                else
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);

                exit(EXIT_FAILURE);

            case 1:
                printf("Non-option arg: %s\n", optarg);
                exit(EXIT_FAILURE);
                break;

            default:
                printf("ERROR : Couldn't parse command line arguments\n");
                abort();
        }
    }

    if (opt_args.is_itf == 0){
        char* dev = pcap_lookupdev(errbuf);

        if (dev == NULL){
            fprintf(stderr, "ERROR : Couldn't find default device: %s\n", errbuf);
            return EXIT_FAILURE;
        }

        strncpy(device, dev, IFNAMSIZ - 1);
    }

    if(opt_args.is_file == 0){
        strncpy(record_file, default_filename, RECORD_FILENAME_SIZE - 1);
    }

    printf("\nDevice selected  : %s\n", device);
    printf("\nRecord filename : %s\n", record_file);

    init_string_record_file(record_file);

    printf("\nRecord file successfully set\n");

    if (!opt_args.is_godmode){

        /* Open the session in promiscuous mode */
        handle = pcap_open_live(device, BUFSIZ, -1, 4096, errbuf);

        if (handle == NULL){
            fprintf(stderr, "ERROR : Couldn't open device %s: %s\n", device, errbuf);
            return EXIT_FAILURE;
        }

        /* Find the properties for the device */
        if (pcap_lookupnet(device, &net, &mask, errbuf) == -1){
            fprintf(stderr, "ERROR : Couldn't get netmask for device : %s\n", device);
            return EXIT_FAILURE;
        }

        printf("\nPCAP session successfully opened\n");
    }

    else{

        handle = pcap_create("any", errbuf);
        strncpy(device, "any", IFNAMSIZ -1);

        if (handle == NULL){
            fprintf(stderr, "ERROR : Couldn't create socket handle for device any: %s\n", errbuf);
            return EXIT_FAILURE;
        }

        assert(pcap_can_set_rfmon(handle) == 1);

        assert(pcap_set_rfmon(handle, 1) == 0);

        if (pcap_activate(handle) < 0){
            fprintf(stderr, "ERROR : Couldn't activate PCAP sock : %s\n", pcap_geterr(handle));
            return EXIT_FAILURE;
        }

        printf("\nGod PCAP enabled\n");

    }

    if (opt_args.is_filter){

        /* Compile and apply the filter on ROOT when you have a pc clean*/
        if (pcap_compile(handle, &fp, pcap_filters, 1, PCAP_NETMASK_UNKNOWN) == -1){
            fprintf(stderr, "Counldn't parse filter %s: %s\n", pcap_filters, pcap_geterr(handle));
            return EXIT_FAILURE;
        }

        /* applying filters */
        if (pcap_setfilter(handle, &fp) == -1){
            fprintf(stderr, "ERROR : Couldn't install filter %s: %s\n", pcap_filters, pcap_geterr(handle));
            return EXIT_FAILURE;
        }

        printf("\nFilters have been successfully applied\n");

    }
    
    printf("\nINFO : PCAP_DATA_LINK_TYPE\t: %x\n", pcap_datalink(handle));
    
    // let's loop throuht the network
    pcap_loop(handle, -1, handle_packet, NULL);

    pcap_close(handle);

    return EXIT_SUCCESS;
    
}


void int_handler(int signum){

    printf("Exiting program with SIGINT [%d] : ok\n", signum);
    exit(EXIT_SUCCESS);
}


/* Handle packet */

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    unsigned char* raw_packet = malloc(header->caplen);

    if (raw_packet != NULL){

        memcpy(raw_packet, (u_char*)packet, header->caplen);

        // let's print the frame
        process_frame(raw_packet, header->caplen);

        // printing raw datas in hex format 
        printf("\n\nRaw Datas : \n\n");

        unsigned int i = 0;

        while(i < header->caplen){

            // every 16 bytes, print a line feed to get a clean output
            if (i % 16 == 0)
                printf("\n");

            printf("%02X ", raw_packet[i]);
            i++;
        }

        printf("\n");

        // extracting revelant strings and saving them into record file
        printf("\n\nList of strings : \n");
        print_strings(raw_packet, header->caplen);
        printf("\n");
        free(raw_packet);

    }

    else{
        printf("\nWARNING : Memory allocation error for one packet !\n");
    }

    raw_packet = NULL;
}
