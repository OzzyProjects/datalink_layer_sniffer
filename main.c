/********************************************************************************
 *                                                                              *
 *  Program      : Datalink layer sniffer                                       *
 *                                                                              *
 *  Version      : 2.1                                                          *
 *                                                                              *    
 *  Ahthor       : Armangau Etienne                                             *
 *                                                                              *
 *  Contact      : <armangau_etienne@yahoo.fr>                                  *
 *                                                                              * 
 *******************************************************************************/                                                              

#include <signal.h>
#include <limits.h>
#include <time.h>

#include "sock_utils.h" 
#include "string_utils.h"


// main option fields struct to avoid dozen of arguments to a function

typedef struct opt_args_main {

    uint32_t max_packet;
    uint32_t timeout;
    uint8_t is_filter       : 2;
    uint8_t is_file         : 1;
    uint8_t is_itf          : 1;
    uint8_t is_monitor_mode : 1;
    uint8_t is_godmode      : 1;
    uint8_t is_limited      : 1;
    uint8_t is_verbose_mode : 1;


} __attribute__((packed)) opt_args_main;

// function to display the command line options (help)

void usage();

// get SIGINT to proper exit freeing memory

void int_handler(int);

// the callback function for the PCAP session

void handle_packet(u_char*, const struct pcap_pkthdr*, const u_char*);                

// default filemane for string record file
static const char* DEFAULT_RECORD_FILENAME = "strings_log";
time_t begin_capture;

// Counter : number of packets sniffed
static unsigned int num_packet = 0;

int main(int argc, char **argv){
    
    // setting the signal handler to catch Ctrl + c interrupt and proper close the record file
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

    // This var will save the actual datalink type of the session capture
    int datalink_type;
    
    pcap_t *handle;

    // parsing the command line to set up the capture environment. More options will arrive soon like integrated bpf filters.
    int opt;
    opt_args_main opt_args;

    memset(&opt_args, 0, sizeof(opt_args_main));

    while ((opt = getopt(argc, argv, "i:r:f:d:t:c:vgmlh")) != -1){

        switch (opt){

            // device name to bind to -i option
            case 'i':
                strncpy(device, optarg, IFNAMSIZ - 1);
                opt_args.is_itf = 1;
                break;

            // string record filename -r option, otherwise file named strings_log by default
            case 'r':
                strncpy(record_file, optarg, RECORD_FILENAME_SIZE - 1);
                opt_args.is_file = 1;
                break;

            // Applying capture filters here -f option
            case 'f':
                strncpy(pcap_filters, optarg, PCAP_FILTER_SIZE);
                opt_args.is_filter= 1;
                break;

            // binding to any (all) devices = all frames are sniffed in theory but it's more complex actually
            case 'g':
                opt_args.is_godmode = 1;
                break;

            // monitor mode selected -m option, some cards don't allow this mode and some of them crash until network-manager restart
            case 'm':
                opt_args.is_monitor_mode = 1;
                break;

            // verbose mode enabled only for the network interfaces search. Will be extend to the capture processs in a while
            case 'v':
                opt_args.is_verbose_mode = 1;
                break;

            // limit the number of sniffed packets : -c option (number of packets to capture). Otherwise infinite loop
            case 'c':

                // check here for out of range number and if so exit failure
                max_packet = strtol(optarg, &temp, 10);

                if (optarg != temp && *temp == '\0' && max_packet <= UINT_MAX){
                    opt_args.max_packet = max_packet;
                    opt_args.is_limited = 1;
                }
                else {
                    fprintf(stderr, "ERROR : Incorrect number for max packet (unsigned int required)\n");
                    return EXIT_FAILURE;
                }
                break;

            // option to set up a provided timeout, 0 by default = non blocking mode
            case 't':

                // again we have to check carrefully the input and convert it int uint32_t

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

            // just an option to print the list of interfaces available. Add option -v (verbose mode) for more details
            // about device flags
            case 'l':
                print_devices_list(opt_args.is_verbose_mode);
                return EXIT_SUCCESS;
                break;

            // option -h (help) : displays all options available
            case 'h':
                usage();
                return EXIT_SUCCESS;
                break;
            
            // some options need a non optionnal argument, no argument = error
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
                fprintf(stderr, "ERROR : Non-option argument : %s\n", optarg);
                usage();
                exit(EXIT_FAILURE);
                break;

            default:
                usage();
                fprintf(stderr, "FATAL ERROR : Couldn't parse command line arguments\n");
                abort();
        }
    }

    // if no interface was provided by the user, the programm will try to find one available on the machine

    if (opt_args.is_itf == 0){

        // selecting the first device available if none was provided 

        if (get_random_device(device) == -1){
            fprintf(stderr, "ERROR : Couldn't find a network device to bind to\n");
            return EXIT_FAILURE;
        }

    }

    // setting up the string record filename if it was provided. if not, just use the default one

    if(opt_args.is_file == 0){
        strncpy(record_file, DEFAULT_RECORD_FILENAME, RECORD_FILENAME_SIZE - 1);
    }

    // printing command line to begin the capture file to keep the context of the capture
    printf("\n\nCommand line : ");

    int i = 0;

    while (i < argc) {
        printf("%s ", *(argv + i));
        i++;
    }

    // Starting the capture session displaying capture session type and capture variables used

    printf("\n\nDevice selected   : %s\n", device);
    printf("\nRecord filename     : %s\n", record_file);
    printf("\nTimeout set         : %u\t%s\n", opt_args.timeout, (!opt_args.timeout) ? "non blocking mode" : "");

    // let's open the string record file now

    init_string_record_file(record_file);

    printf("\nRecord file successfully set\n");

    // one and only one interface sniffing mode, just do a soft capture

    if (opt_args.is_godmode == 0){

        /* Open the session in promiscuous mode with defined timeout or not (default) */

        handle = pcap_open_live(device, BUFSIZE, -1, opt_args.timeout, errbuf);


        if (handle == NULL){
            fprintf(stderr, "ERROR : Couldn't open device %s: %s\n", device, errbuf);
            return EXIT_FAILURE;
        }

        /* Find the properties for the device */
        if (pcap_lookupnet(device, &net, &mask, errbuf) == -1){
            fprintf(stderr, "ERROR : Couldn't get netmask for device : %s\n", errbuf);
            return EXIT_FAILURE;
        }

        printf("\nPCAP session successfully opened\n");
    }

    // Sniffing on any device chosen

    else{

        strncpy(device, "any", IFNAMSIZ -1);
        handle = pcap_create(device, errbuf);

        if (handle == NULL){
            fprintf(stderr, "ERROR : Couldn't create socket handle for device any: %s\n", errbuf);
            return EXIT_FAILURE;
        }

        assert(pcap_set_snaplen(handle, ETHERNET_MTU) == 0);

        // setting up a custom timeout or by default it's the value 0 (non blocking mode)
        
        if (opt_args.timeout){
            assert(pcap_set_timeout(handle, opt_args.timeout) == 0);
            printf("\nTimeout successfully set\n");
        }
        else{
            assert(pcap_setnonblock(handle, -1, errbuf) != -1);
            printf("\nPCAP non blocking mode successfully set\n");
        }

        /*
        assert(pcap_set_promisc(handle, 1) != -1);
        */

        // setting the device in monitor mode if it was selected

        if (opt_args.is_monitor_mode){

            // if we can't put the device in monitor mode, so display a warning but keep continue the capture
            if (pcap_can_set_rfmon(handle) != 1){
                fprintf(stderr, "WARNING : the device can't be set up in monitor mode : %s\n", pcap_geterr(handle));
            }

            // otherwise, let's put the network card in monitor mode
            else{
                assert(pcap_set_rfmon(handle, 1) == 0);
            }
        }

        // We need now to launch the session capture

        if (pcap_activate(handle) < 0){

            fprintf(stderr, "ERROR : Couldn't activate PCAP sock : %s\n", pcap_geterr(handle));
            return EXIT_FAILURE;
        }

        // The god mode sniffing is now enabled
        printf("\nGod PCAP mode enabled\n");

    }

    // If a filter has been chosen for the capture, it's time to apply it

    if (opt_args.is_filter){

        // Compile and apply filter

        if (pcap_compile(handle, &fp, pcap_filters, 1, PCAP_NETMASK_UNKNOWN) == -1){
            fprintf(stderr, "Counldn't parse capture filters %s: %s\n", pcap_filters, pcap_geterr(handle));
            return EXIT_FAILURE;
        }

        // applying filters 
        if (pcap_setfilter(handle, &fp) == -1){
            fprintf(stderr, "ERROR : Couldn't install the filter %s: %s\n", pcap_filters, pcap_geterr(handle));
            return EXIT_FAILURE;
        }

        printf("\nFilters has been successfully applied\n");

    }

    // getting the data link type to properly dissect frames

    datalink_type = pcap_datalink(handle);

    // starting the timer here
    
    begin_capture = time(NULL);

    // passing the datalink type as argument to pcap_loop function
    
    u_char* datalink_type_ptr = __INT_TO_UCHAR_PTR(datalink_type);

    // let's loop throughtout the network

    if (opt_args.is_limited){
        // limited capture (number of packets)
        pcap_loop(handle, opt_args.max_packet, handle_packet, datalink_type_ptr);
    }
    else{
        // otherwise, infinite loop
        pcap_loop(handle, -1, handle_packet, datalink_type_ptr);
    }

    pcap_close(handle);

    int_handler(-1);

    return EXIT_SUCCESS;

}


// updating the last params, closing file etc... before closing

void int_handler(int signum){

    // printing the capture time duration
    time_t end_capture = time(NULL);
    long total_time = end_capture - begin_capture;
    int min_elapsed = (int)(total_time / 60);
    int sec_elapsed = (int)(total_time % 60);
    printf("Capture time duration : %02d min %02d sec\n", min_elapsed, sec_elapsed);

    // closing the string record file and exiting
    close_record_file();
    
    printf("Exiting program with SIGINT [%x]: OK\n", signum);
    exit(EXIT_SUCCESS);
}

// the callback function used to manage every frame sniffed

void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    unsigned char* raw_packet = (unsigned char*)packet;
   
    int datalink_type = __UCHAR_PTR_TO_INT(args);

    ++num_packet;

    // let's process the frames now

    process_layer2_packet(raw_packet, header->caplen, datalink_type);

    // printing raw datas in hex format 
    
    printf("\nRaw Datas : \n\n");

    size_t i = 0;

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

void usage(){

    printf("raw sniffer v1.0 help\t(by Ozzy)\n");
    printf("\n\t-c [max_packets] max_packet : maximum number of packets to capture (optional)\n");
    printf("\t-i [interface] interface : interface to bind to (optional)\n");
    printf("\t-r [record_file]record_file : path of the string record file (optional)\n");
    printf("\t-c [max_packets] max_packet : maximum number of packets to capture (optional)\n");
    printf("\t-c [timeout] timeout: set a custom timeout in seconds. 0 for non blocking (optional)\n");
    printf("\t-f [filter] filter : set a custom tcmpdump format filter for the capture (optional)\n");
    printf("\t-g [any] : set this option without interface to capture frames from any device (optional)\n");
    printf("\t-m [monitor mode] : set this option to set the capture device in monitor mode (optional)\n");
    printf("\t-h [help] : get help about command line options\n");
    printf("\nExample : ./raw_sock -i wlp4s0 -r strings_log -f \"not ipx\" -t 1024 -c 0\n");
    printf(" Binding to one device, recording strings to file, applying filters to the capture and setting timeout\n");
}


