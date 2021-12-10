
#include <signal.h>
#include <limits.h>
#include <time.h>

#include "sock_utils.h" 
#include "string_utils.h"	


/* opts struct for the capture session */

typedef struct opt_args_main {
	
	char device[IFNAMSIZ];
	char record_file[RECORD_FILENAME_SIZE];
	char pcap_filters[PCAP_FILTER_SIZE];

	unsigned int max_packets;
	int timeout;

	uint8_t is_filter       : 2;	/* bpf filter or not */
	uint8_t is_file         : 1;	/* rec file or not */
	uint8_t is_itf          : 1;	/* net device or not */
	uint8_t is_monitor_mode : 1;	/* mon mode enabled or not */
	uint8_t is_godmode      : 1;	/* any device or single device */
	uint8_t is_limited      : 1;	/* limit numb pckts or not (0 or neg) */
	uint8_t is_verbose_mode : 1;	/* verbose mode or not */


} opt_args_main;


/* SIGINT function to proper exit freeing memory */
void int_handler(int);

/* function to parse the command line */
int parse_cmd_line(int, char**, struct opt_args_main*);

/* callback function for the PCAP session */
void handle_packet(u_char*, const struct pcap_pkthdr*, const u_char*);

/* printing command line */
void print_cmd_line(int, char**);

/* displaying all options available */
void usage();


/* default filemane for string record file */
static const char* DEFAULT_RECORD_FILENAME = "strlog";

/* starter capture timer */
time_t begin_capture;

/* counter : number of packets sniffed */
static unsigned int num_packet = 0;


int main(int argc, char **argv)
{
    
    /* setting the signal handler to proper close the record file */
    signal(SIGINT, int_handler);

    /* global params for the PCAP session */
    char errbuf[PCAP_ERRBUF_SIZE];

    /* BPF filters variables */
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    /* status code for the command line parsing */
    int parsing_status;

    /* this var will save the actual datalink type of the session capture */
    int datalink_type;
    u_char* dll_type_ptr;

    pcap_t *handle;

    struct opt_args_main* opt_args = malloc(sizeof(struct opt_args_main));

    if (opt_args == NULL){
        fprintf(stderr, "FATAL ERROR : couldn't allocate memory for main struct\n");
        return EXIT_FAILURE;
    }

    memset(opt_args, 0, sizeof(opt_args_main));

    /* parsing the command line and setting up capture options */
    parsing_status = parse_cmd_line(argc, argv, opt_args);

    if (parsing_status < 0){
        fprintf(stderr, "FATAL ERROR : error while parsing the command line\n");
		goto fatal_error;
    }

    /* no interface provided by user, prog will try to find one's available 
    no device available -> aborting */
    if (!opt_args->is_itf && get_random_device(opt_args->device) == -1){

        fprintf(stderr, "FATAL ERROR : couldn't find a network device to bind to\n");
        goto fatal_error;

    }

    /* setting up the string record filename if it was provided */
    if (!opt_args->is_file){
        strncpy(opt_args->record_file, DEFAULT_RECORD_FILENAME, RECORD_FILENAME_SIZE - 1);
    }

    print_cmd_line(argc, argv);

    /* starting capture session displaying capture session opts */
    printf("\n\nDevice selected   : %s\n", opt_args->device);
    printf("\nRecord filename     : %s\n", opt_args->record_file);
    printf("\nTimeout set         : %u\t%s\n", opt_args->timeout, 
    	(!opt_args->timeout) ? "non blocking mode" : "");

    /* let's open the string record file now */
    init_string_record_file(opt_args->record_file);

#if DEBUG
        	printf("\nRecord file successfully set\n");
#endif

    // one and only one interface sniffing mode, just do a soft capture

    if (opt_args->is_godmode == 0){

        /* opening session in promiscuous mode with defined timeout or not (default) */
        handle = pcap_open_live(opt_args->device, BUFSIZE, -1, opt_args->timeout, errbuf);

        if (handle == NULL){
            fprintf(stderr, "ERROR : Couldn't open device %s: %s\n", opt_args->device, errbuf);
            goto fatal_error;
        }

        /* finding properties for device */
        if (pcap_lookupnet(opt_args->device, &net, &mask, errbuf) == -1){
            fprintf(stderr, "FATAL ERROR : couldn't get netmask for device : %s\n", errbuf);
            goto fatal_error;
        }

#if DEBUG
        	printf("\nPCAP session successfully opened\n");
#endif

    }

    /* sniffing on "any" device chosen */
    else{

        strncpy(opt_args->device, "any", IFNAMSIZ -1);
        handle = pcap_create(opt_args->device, errbuf);

        if (handle == NULL){
            fprintf(stderr, "FATAL ERROR : Couldn't create socket handle : %s\n", errbuf);
            goto fatal_error;
        }

        /* setting snaplen to 1500 */
        assert(pcap_set_snaplen(handle, ETHERNET_MTU) == 0);

        /* setting up a custom timeout or by default 0 (non blocking mode) */
        if (opt_args->timeout){

            assert(pcap_set_timeout(handle, opt_args->timeout) == 0);
       
#if DEBUG
        	printf("\nTimeout successfully set\n");
#endif

        } else{
            assert(pcap_setnonblock(handle, -1, errbuf) != -1);

#if DEBUG
        	printf("\nNon blocking mode successfully set\n");
#endif
            
        }

        /*
        assert(pcap_set_promisc(handle, 1) != -1);
        */

        /* setting the device in monitor mode if it was selected */
        if (opt_args->is_monitor_mode){

            /* if we can't put the device in monitor mode, so display a warning 
            but keep continue the capture */

            if (pcap_can_set_rfmon(handle) != 1){
                fprintf(stderr, "WARNING : device can't be set up in monitor mode : %s\n", 
                	pcap_geterr(handle));
            } else{
                assert(pcap_set_rfmon(handle, 1) == 0);
            }
        }

        /* we need now to launch the session capture */
        if (pcap_activate(handle) < 0){

            fprintf(stderr, "FATAL ERROR : couldn't activate PCAP sock : %s\n", 
            	pcap_geterr(handle));

            goto fatal_error;
        }

#if DEBUG
        printf("\nGod PCAP mode enabled\n");
#endif

    }

    /* if a filter has been chosen for the capture, it's time to apply it */
    if (opt_args->is_filter){

        if (pcap_compile(handle, &fp, opt_args->pcap_filters, 1, PCAP_NETMASK_UNKNOWN) == -1){
            fprintf(stderr, "counldn't parse capture filters %s: %s\n", 
            	opt_args->pcap_filters, pcap_geterr(handle));

            goto fatal_error;
        }

        /* applying filters */
        if (pcap_setfilter(handle, &fp) == -1){
            fprintf(stderr, "ERROR : couldn't install the filter %s: %s\n", 
            	opt_args->pcap_filters, pcap_geterr(handle));

            goto fatal_error;
        }

#if DEBUG
        printf("\nFilters has been successfully applied\n");
#endif

    }

    /* getting the data link type to properly dissect frames */
    datalink_type = pcap_datalink(handle);
    assert(datalink_type != PCAP_ERROR_NOT_ACTIVATED);

    dll_type_ptr = INT_TO_UCHAR_PTR(datalink_type);

    /* starting the timer here */
    begin_capture = time(NULL);

    /* let's loop throughtout the network */
    if (opt_args->is_limited){
        /* limited capture session (number of packets) */
        pcap_loop(handle, opt_args->max_packets, handle_packet, dll_type_ptr);
    } else {
        /* otherwise, infinite loop (0 or neg value)*/ 
        pcap_loop(handle, -1, handle_packet, dll_type_ptr);
    }

    pcap_close(handle);
    free(opt_args);
    int_handler(0);

    return EXIT_SUCCESS;

/* freeing memory before quitting */

fatal_error:

 	free(opt_args);
 	return EXIT_FAILURE;

}

// function used to parse the command line

int parse_cmd_line(int argc, char** argv, struct opt_args_main* opt_args)
{

	/* temp buffer to convert opt to int with strtol */
    char *temp, *temp2;
    int opt;
    long max_packet;
    long defined_timeout; 

    while ((opt = getopt(argc, argv, "i:r:f:d:t:c:vgmlh")) != -1){

        switch (opt){

            /* device name to bind to -i [iface-name] */
            case 'i':
                strncpy(opt_args->device, optarg, IFNAMSIZ - 1);
                opt_args->is_itf = 1;
                break;

            /* recording string file -r [path-record-file] */
            case 'r':
                strncpy(opt_args->record_file, optarg, RECORD_FILENAME_SIZE - 1);
                opt_args->is_file = 1;
                break;

            /* applying capture filters here -f [bpf-filter] */
            case 'f':
                strncpy(opt_args->pcap_filters, optarg, PCAP_FILTER_SIZE - 1);
                opt_args->is_filter= 1;
                break;

            /* binding to "any" device = all frames are sniffed in theory */
            case 'g':
                opt_args->is_godmode = 1;
                break;

            /* setting monitor mode -m option */
            case 'm':
                opt_args->is_monitor_mode = 1;
                break;

            /* enabling verbose mode */
            case 'v':
                opt_args->is_verbose_mode = 1;
                break;

            /* limit the number of sniffed packets : -c [number-max-packets] */
            case 'c':
                max_packet = strtol(optarg, &temp, 10);

                if (optarg != temp && *temp == '\0' && max_packet <= UINT_MAX){
                    opt_args->max_packets = (unsigned int)max_packet;
                    opt_args->is_limited = 1;

                } else {
                    fprintf(stderr, "ERROR : Incorrect number for max packets (uint required)\n");
                    return -1;
                }

                break;

            /* setting up a provided timeout, 0 by default = non blocking mode */
            case 't':
                defined_timeout = strtol(optarg, &temp2, 10);

                if (optarg != temp2 && *temp2 == '\0' && defined_timeout <= UINT_MAX){
                    opt_args->timeout = defined_timeout;

                } else{
                    fprintf(stderr, "ERROR : Timeout value format error !\n");
                    return -1;
                }

                break;

            /* just an option to print the list of interfaces available. Add option -v (verbose mode)
            for more details about device flags */
            case 'l':
                print_devices_list(opt_args->is_verbose_mode);
                free(opt_args);
                exit(EXIT_SUCCESS);
                break;

            /* option -h (help) : displays all options available */
            case 'h':
                usage();
                free(opt_args);
                exit(EXIT_SUCCESS);
                break;
            
            /* some options need an argument, no argument -> error */
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
                    fprintf(stderr, "Unknown option -%c | -h for help\n", optopt);

                free(opt_args);
                exit(EXIT_FAILURE);

            case 1:
                fprintf(stderr, "FATAL ERROR : Non-option argument : %s | -h for help\n", optarg);
                return -1;
                break;

            default:
                usage();
                fprintf(stderr, "FATAL ERROR : Couldn't parse command line arguments\n");
                return -1;
        }
    }

    return 0;

}


/* the callback function used to manage every frame sniffed */
void handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    unsigned char* raw_packet = (unsigned char*)packet;
   
    int datalink_type = UCHAR_PTR_TO_INT(args);

    ++num_packet;

    print_current_time();

    // let's process the frames now
    process_layer2_packet(raw_packet, datalink_type, header->caplen);

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


// updating the last params, closing file etc... before closing

void int_handler(int signum)
{

    /* printing the capture time duration */
    time_t end_capture = time(NULL);
    long total_time = end_capture - begin_capture;
    int min_elapsed = (int)(total_time / 60);
    int sec_elapsed = (int)(total_time % 60);

    printf("Capture time duration : %02d min %02d sec\n", min_elapsed, sec_elapsed);

    /* closing the string record file and exiting */
    close_record_file();
    
    printf("Exiting program with SIGINT [%d]: OK\n", signum);
    exit(EXIT_SUCCESS);
}


/* printing command line to begin the capture file */
void print_cmd_line(int argc, char** argv)
{

    printf("\nCommand line : ");

    int opt_n = 0;

    while (opt_n < argc) {
        printf("%s ", *(argv + opt_n));
        ++opt_n;
    }
}


/* helping function */
void usage()
{

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

