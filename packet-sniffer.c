//
//  packet-sniffer.c
//
//
//  Created by Ben Scanlan on 4/24/15
//  Networking 446 Spring 2015
//

// system call calls
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>

#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)


//#include <netinet/ether.h>


/* Maximum time that the OS will buffer packets before giving them to your program. */
#define MAX_BUFFER_TIME_MS (300)

/* Maximum time the program will wait for a packet during live capture.
 * Measured in MAX_BUFFER_TIME_MS units. Program closes when it expires. */
#define MAX_IDLE_TIME 100 /* 100*MAX_BUFFER_TIME_MS idle time at most */

/* Function that create the structures necessary to perform a packet capture and
 * determines capture source depending on arguments. Function will terminate the
 * program on error, so return value always valid. */
pcap_t* setup_capture(int argc, char *argv[], char *use_file);

/* Cleanup the state of the capture. */
void cleanup_capture(pcap_t *handle);

/* Check for abnormal conditions during capture.
 * 1 returned if a packet is ready, 0 if a packet is not available.
 * Terminates program if an unrecoverable error occurs. */
char valid_capture(int return_value, pcap_t *pcap_handle, char use_file);

int main(int argc, char *argv[]) {

    pcap_t *pcap_handle = NULL;             /* Handle for PCAP library */
    struct pcap_pkthdr *packet_hdr = NULL;  /* Packet header from PCAP */
    const u_char *packet_data = NULL;       /* Packet data from PCAP */
    int ret = 0;                            /* Return value from library calls */
    char use_file = 0;
    int *intpoint; // added by ben scanlan

    /* Flag to use file or live capture */

    /* Setup the capture and get the valid handle. */
    pcap_handle = setup_capture(argc, argv, &use_file);

    /* Loop through all the packets in the trace file.
     * ret will equal -2 when the trace file ends.
     * ret will never equal -2 for a live capture. */
    ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);

    while( ret != -2 ) {
        if( valid_capture(ret, pcap_handle, use_file) ){
            /*
             * Put your code here
             */

            /*
             * Converts address to standard hex-digits-and-colons printable form.
            */
            struct ether_header *eptr;  /* net/ethernet.h */

            /* start with the ether header... */
            eptr = (struct ether_header *) packet_data;

            fprintf(stdout,"%s" ,ether_ntoa((const struct ether_addr*)&eptr->ether_shost));
            fprintf(stdout," -> %s \n" ,ether_ntoa((const struct ether_addr*)&eptr->ether_dhost));

            //Read in length/typefield
            char len_type[] = {0, 0, 0, 0};

            // reverse endianess
            len_type [1] = packet_data[12];
            len_type [0] = packet_data[13];

            //print char array
            /*
            printf("%02X", len_type[0]);
            printf("%02X", len_type[1]);
            printf("%02X", len_type[2]);
            printf("%02X\n", len_type[3]);
            */

            // typecast
            intpoint = (int*)len_type;
            //printf("%d\n", *intpoint); // print decimal

            if ( *intpoint >= 1536) // if type
            {

            //if ip v 4
            if ( packet_data[12]==0x08 && packet_data[13] == 0x00) {

            char str[INET_ADDRSTRLEN];

            printf("\t[IPv4] ");
            inet_ntop(AF_INET, &(packet_data[26]), str, INET_ADDRSTRLEN);

            printf("%s -> ", str); // prints "0.0.0.0"

            //destination
            inet_ntop(AF_INET, &(packet_data[30]), str, INET_ADDRSTRLEN);

            printf("%s\n", str); // prints "0.0.0.0"

                // if ipv4 tcp
                if ( packet_data[23]==0x06){
                    printf("\t[TCP] ");

                    char port_type[] = {0, 0, 0, 0};

                    // reverse endianess
                    port_type [1] = packet_data[34];
                    port_type [0] = packet_data[35];
                    // typecast
                    int *intport = (int*)port_type;
                    printf("%d -> ", *intport);
                    port_type [1] = packet_data[36];
                    port_type [0] = packet_data[37];
                    printf("%d", *intport);

                    if ( packet_data[47] == 0x02)
                    {
                        printf(" SYN");

                    }

                    else if ( packet_data[47] == 0x11)
                    {
                        printf(" FIN");

                    }
                    printf("\n");
                }

                // if ipv4 UDP
                else if ( packet_data[23]==0x11){
                    printf("\t[UDP] ");

                    char port_type[] = {0, 0, 0, 0};

                    // reverse endianess
                    port_type [1] = packet_data[34];
                    port_type [0] = packet_data[35];
                    // typecast
                    int *intport = (int*)port_type;
                    printf("%d -> ", *intport);
                    port_type [1] = packet_data[36];
                    port_type [0] = packet_data[37];
                    printf("%d\n", *intport);
                }

                else {
                    char port_type[] = {0, 0, 0, 0};
                    port_type[0] = packet_data[23];
                    int *intport = (int*)port_type;
                    printf("\t[");
                    printf("%d", *intport);
                    printf("]\n");
                }
                                                   }


            // if ip v 6
            else if ( packet_data[12]==0x86 && packet_data[13] == 0xDD) {
                    char str[INET6_ADDRSTRLEN];

                    printf("\t[IPv6] ");
                    inet_ntop(AF_INET6, &(packet_data[22]), str, INET6_ADDRSTRLEN);

                    printf("%s -> ", str); // prints "0.0.0.0"

                    //destination
                    inet_ntop(AF_INET6, &(packet_data[38]), str, INET6_ADDRSTRLEN);

                    printf("%s\n", str); // prints "0.0.0.0"

                    // if ipv6 tcp
                    if ( packet_data[20]==0x06){
                        printf("\t[TCP] ");

                        char port_type[] = {0, 0, 0, 0};

                        // reverse endianess
                        port_type [1] = packet_data[54];
                        port_type [0] = packet_data[55];
                        // typecast
                        int *intport = (int*)port_type;
                        printf("%d -> ", *intport);
                        port_type [1] = packet_data[56];
                        port_type [0] = packet_data[57];
                        printf("%d", *intport);

                        if ( packet_data[67] == 0x02)
                        {
                            printf(" SYN");

                        }

                        else if ( packet_data[67] == 0x11)
                        {
                            printf(" FIN");

                        }
                        printf("\n");
                    }

                    // if ipv6 UDP
                    else if ( packet_data[20]==0x11)
                    {
                        printf("\t[UDP] ");

                        char port_type[] = {0, 0, 0, 0};

                        // reverse endianess
                        port_type [1] = packet_data[54];
                        port_type [0] = packet_data[55];
                        // typecast
                        int *intport = (int*)port_type;
                        printf("%d -> ", *intport);
                        port_type [1] = packet_data[56];
                        port_type [0] = packet_data[57];
                        printf("%d\n", *intport);
                        }

                    else {
                        char port_type[] = {0, 0, 0, 0};
                        port_type[0] = packet_data[20];
                        int *intport = (int*)port_type;
                        printf("\t[");
                        printf("%d", *intport);
                        printf("]\n");                    }

                }

            else // if it indicates the payload or 1500-1535 which is undefined, what do i do?
            {



                printf("\t[");
                printf("%d", *intpoint);
                printf("]\n");
            }


        }
            else
            {
                printf("\t[");
                printf("%d", *intpoint);
                printf("]\n");
            }

        }

        //else
            //printf("\t[" *intpoint "] ");

        /* Get the next packet */
        ret = pcap_next_ex(pcap_handle, &packet_hdr, &packet_data);
    }

    cleanup_capture(pcap_handle);
    return 0;
}

pcap_t* setup_capture(int argc, char *argv[], char *use_file) {
    char *trace_file = NULL;                /* Trace file to process */
    pcap_t *pcap_handle = NULL;             /* Handle for PCAP library to return */
    char pcap_buff[PCAP_ERRBUF_SIZE];       /* Error buffer used by pcap functions */
    char *dev_name = NULL;                  /* Device name for live capture */

    /* Check command line arguments */
    if( argc > 2 ) {
        fprintf(stderr, "Usage: %s [trace_file]\n", argv[0]);
        exit(-1);
    }
    else if( argc > 1 ){
        *use_file = 1;
        trace_file = argv[1];
    }
    else {
        *use_file = 0;
    }

    /* Open the trace file, if appropriate */
    if( *use_file ){
        pcap_handle = pcap_open_offline(trace_file, pcap_buff);
        if( pcap_handle == NULL ){
            fprintf(stderr, "Error opening trace file \"%s\": %s\n", trace_file, pcap_buff);
            exit(-1);
        }
        printf("Processing file '%s'\n", trace_file);
    }
    /* Lookup and open the default device if trace file not used */
    else{
        dev_name = pcap_lookupdev(pcap_buff);
        if( dev_name == NULL ){
            fprintf(stderr, "Error finding default capture device: %s\n", pcap_buff);
            exit(-1);
        }

        /* Use buffer length as indication of warning, per pcap_open_live(3). */
        pcap_buff[0] = 0;

        pcap_handle = pcap_open_live(dev_name, BUFSIZ, 1, MAX_BUFFER_TIME_MS, pcap_buff);
        if( pcap_handle == NULL ){
            fprintf(stderr, "Error opening capture device %s: %s\n", dev_name, pcap_buff);
            exit(-1);
        }
        if( pcap_buff[0] != 0 ) {
            printf("Warning: %s\n", pcap_buff);
        }

        printf("Capturing on interface '%s'\n", dev_name);
    }

    return pcap_handle;

}

void cleanup_capture(pcap_t *handle) {
    /* Close the trace file or device */
    pcap_close(handle);
}

char valid_capture(int return_value, pcap_t *pcap_handle, char use_file) {
    static int idle_count = 0;  /* Count of idle periods with no packets */
    char ret = 0;               /* Return value, invalid by default */

    /* A general error occurred */
    if( return_value == -1 ) {
        pcap_perror(pcap_handle, "Error processing packet:");
        cleanup_capture(pcap_handle);
        exit(-1);
    }

    /* Timeout occured for a live packet capture */
    else if( (return_value == 0) && (use_file == 0) ){
        if( ++idle_count >= MAX_IDLE_TIME ){
            printf("Timeout waiting for additional packets on interface\n");
            cleanup_capture(pcap_handle);
            exit(0);
        }
    }

    /* Unexpected/unknown return value */
    else if( return_value != 1 ) {
        fprintf(stderr, "Unexpected return value (%i) from pcap_next_ex()\n", return_value);
        cleanup_capture(pcap_handle);
        exit(-1);
    }
    /* Normal operation, packet arrived */
    else{
        idle_count = 0;
        ret = 1;
    }

    return ret;
}
