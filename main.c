/* Libraries */ 

#include <signal.h>
#include <limits.h>

#include "sock_utils.h" 
#include "string_utils.h"

int DLT_SIZE = 0;

// main option fields struct

typedef struct opt_args_main {

    uint32_t max_packet;
    uint32_t timeout;
    uint8_t is_filter   : 2;
    uint8_t is_file     : 2;
    uint8_t is_itf      : 2;
    uint8_t is_godmode  : 1;
    uint8_t is_limited  : 1;


} __attribute__((packed)) opt_args_main;

// get SIGINT to proper exit freeing memory
void int_handler(int);
void handle_packet(u_char*, const struct pcap_pkthdr*, const u_char*);                

// default filemane for string record file
static const char* DEFAULT_RECORD_FILENAME = "strings_log";

// number of packets sniffed
static unsigned int num_packet = 0;

int main(int argc, char **argv) {
    
    // set the signal handler to catch Ctrl + c interrupt and proper close record file
    signal(SIGINT, int_handler);

    // global params for the PCAP session
    char device[IFNAMSIZ];
    char record_file[RECORD_FILENAME_SIZE];
    char pcap_filters[PCAP_FILTER_SIZE];
    char errbuf[PCAP_ERRBUF_SIZE];
    char* temp;
    uint64_t defined_timeout;
    uint64_t max_packet;

    // BPF filters variables
    struct bpf_program fp;
    bpf_u_int32  mask;
    bpf_u_int32 net;

    pcap_t *handle;

    // parsing the command line 
    int opt;
    opt_args_main opt_args;

    memset(&opt_args, 0, sizeof(opt_args));

    while ((opt = getopt(argc, argv, "i:r:f:d:t:c:gl")) != -1){

        switch (opt){

            // device name to bind to -i option
            case 'i':
                strncpy(device, optarg, IFNAMSIZ - 1);
                opt_args.is_itf = 1;
                break;

            // string record filename -r option, otherwise file named strings_log
            case 'r':
                strncpy(record_file, optarg, RECORD_FILENAME_SIZE - 1);
                opt_args.is_file = 1;
                break;

            // binding to any (all) devices = all frames
            case 'g':
                opt_args.is_godmode = 1;
                break;

            // limit the number of sniffed packed -c option (number of packets to capture)
            case 'c':
                // out of range number = exit
                max_packet = strtol(optarg, &temp, 10);
                if (optarg != temp && *temp == '\0' && max_packet <= UINT_MAX){
                    opt_args.max_packet = max_packet;
                    opt_args.is_limited = 1;
                }
                else {
                    fprintf(stderr, "ERROR : Incorrect number for max packet (unsigned int required)\n");
                    exit(EXIT_FAILURE);
                }
                break;

            // option to set up a provided timeout, 0 (default) for non blocking mode
            case 't':
                defined_timeout = strtoul(optarg, &temp, 10);

                // argument is properly parsed: set the timeout
                if (optarg != temp && *temp == '\0' && defined_timeout <= UINT_MAX){
                    opt_args.timeout = defined_timeout;
                }
                else{
                    fprintf(stderr, "ERROR : Timeout value format error (unsigned int required or 0 for non blocking)\n");
                    return EXIT_FAILURE;
                }
                break;

            // just an option to print the list of interfaces available
            case 'l':
                print_itf_list();
                return EXIT_SUCCESS;
                break;

            // applying filters to the capture -f option
            case 'f':
                strncpy(pcap_filters, optarg, PCAP_FILTER_SIZE - 1);
                opt_args.is_filter = 1;
                break;

            case '?':
                if (optopt == 'i')
                    fprintf(stderr, "Option -%c requires an argument [interface_name] !\n", optopt);
                else if (optopt == 'r')
                    fprintf(stderr, "Option -%c requires an argument [record_file_name] !\n", optopt);
                else if (optopt == 'f')
                    fprintf(stderr, "Option -%c requires an argument [pcap_filters] !\n", optopt);
                else if (optopt == 'c')
                    fprintf(stderr, "Option -%c requires an argument [max packets] !\n", optopt);
                else if (optopt == 't')
                    fprintf(stderr, "Option -%c requires an argument [timeout] | 0 for non blocking mode!\n", optopt);
                else
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);

                exit(EXIT_FAILURE);

            case 1:
                printf("ERROR : Non-option argument : %s\n", optarg);
                exit(EXIT_FAILURE);
                break;

            default:
                printf("FATAL ERROR : Couldn't parse command line arguments\n");
                abort();
        }
    }

    if (opt_args.is_itf == 0){

        // selecting the first device available if none was provided 
        if (get_random_device(device) == -1){
            fprintf(stderr, "ERROR : Couldn't find any device to bind to\n");
            return EXIT_FAILURE;
        }

    }

    if(opt_args.is_file == 0){
        strncpy(record_file, DEFAULT_RECORD_FILENAME, RECORD_FILENAME_SIZE - 1);
    }

    printf("\nDevice selected  : %s\n", device);
    printf("\nRecord filename : %s\n", record_file);

    init_string_record_file(record_file);

    printf("\nRecord file successfully set\n");

    // only one interface sniffing mode
    if (opt_args.is_godmode == 0){

        /* Open the session in promiscuous mode with defined timeout or not (default) */
        if (opt_args.timeout){
            handle = pcap_open_live(device, BUFSIZE, -1, opt_args.timeout, errbuf);
        }
        else{
            handle = pcap_open_live(device, BUFSIZE, -1, 1, errbuf);
        }

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

        assert(pcap_set_snaplen(handle, ETHERNET_MTU) == 0);

        // setting up timeout or by default or 0 value non blocking mode
        if (opt_args.timeout){
            assert(pcap_set_timeout(handle, opt_args.timeout) == 0);
            printf("\nTimeout successfully set\n");
        }
        else{
            assert(pcap_setnonblock(handle, -1, errbuf) != -1);
            printf("\nPCAP non blocking mode successfully set\n");
        }

        assert(pcap_set_promisc(handle, 1) != -1);

        if (pcap_can_set_rfmon(handle) != 1){
            fprintf(stderr, "ERROR : the device can't be set up in monitor mode : %s\n", pcap_geterr(handle));
            return EXIT_FAILURE;
        }

        assert(pcap_set_rfmon(handle, 1) == 0);

        if (pcap_activate(handle) < 0){
            fprintf(stderr, "ERROR : Couldn't activate PCAP sock : %s\n", pcap_geterr(handle));
            return EXIT_FAILURE;
        }

        printf("\nGod PCAP enabled\n");

    }

    if (opt_args.is_filter){

        /* Compile and apply the filter */
        if (pcap_compile(handle, &fp, pcap_filters, 1, PCAP_NETMASK_UNKNOWN) == -1){
            fprintf(stderr, "Counldn't parse filter %s: %s\n", pcap_filters, pcap_geterr(handle));
            return EXIT_FAILURE;
        }

        /* applying filters */
        if (pcap_setfilter(handle, &fp) == -1){
            fprintf(stderr, "ERROR : Couldn't install filter %s: %s\n", pcap_filters, pcap_geterr(handle));
            return EXIT_FAILURE;
        }

        printf("\nFilters has been successfully applied\n");

    }

    // getting the data link type to properly dissect frames

    int datalink_type = pcap_datalink(handle);
    printf("\nINFO : PCAP_DATA_LINK_TYPE : %x\t", datalink_type);

    // getting the datalink type to parse correctly TODO
    
    switch(datalink_type){

        case PCAP_ERROR_NOT_ACTIVATED:
            fprintf(stderr, "ERROR : Failed to get data link type\n");
            return EXIT_FAILURE;

        case DLT_RAW:
            printf("RAW Datalink\n");
            DLT_SIZE = 0;
            break;

        case DLT_LINUX_SLL:  // "any" for device will give you this
            printf("Linux SLL\n");
            DLT_SIZE = 16;
            break;

        case DLT_EN10MB:
            printf("Ethernet\n");
            DLT_SIZE = ETH2_HEADER_LEN;
            break;

         case  DLT_AX25:
            printf("AX 25\n");
            DLT_SIZE = 0;
            break;

         case DLT_IEEE802_11:
            printf("IEEE802 11\n");
            DLT_SIZE = 0;
            break;

        default:
            fprintf(stderr, "WARNING : Unknown data link type\n");
            DLT_SIZE = 0;
    }
    
    
    // let's loop throuht the network
    if (opt_args.is_limited)

        // limited capture (number of packets)
        pcap_loop(handle, opt_args.max_packet, handle_packet, NULL);
    else
        // otherwise, infinite loop
        pcap_loop(handle, -1, handle_packet, NULL);

    pcap_close(handle);

    return EXIT_SUCCESS;
    
}


void int_handler(int signum){

    close_record_file();
    printf("Exiting program with SIGINT [%x]: OK\n", signum);
    exit(EXIT_SUCCESS);
}


/* Handle packet */

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    unsigned char* raw_packet = (unsigned char*)packet; // malloc(header->caplen);

    ++num_packet;

    // let's print the frame
    printf("\nFRAME NUMBER : %u\n", num_packet);
    process_frame(raw_packet, header->caplen);

    // printing raw datas in hex format 
    
    printf("\n\nRaw Datas : \n\n");

    uint32_t i = 0;

    while(i < header->caplen){

        // every 32 bytes, print a line feed to get a clean output
        if (i % 32 == 0)
            printf("\n");

        printf("%02X ", *(raw_packet + i));
        i++;
    }

    printf("\n");

    // extracting revelant strings and saving them into record file
    printf("\n\nRevelant strings : \n");
    print_strings(raw_packet, header->caplen);
    printf("\n");

}
