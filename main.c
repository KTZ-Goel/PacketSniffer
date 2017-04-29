/**************************************************************************************
	Process of execution for this program:
	1. Recieve a packet, interpret it as a sniff_ethernet struct, call the appropriate function to handle this.
	2. Print out information for it.
	3. Determine the Network layer protocol, call the appropriate function to handle this.
	4. Print out information for this network layer packet.
	5. Determine the transport layer protocol, call the appropriate function to handle this.
	6. Print out information for this transport layer segment.
	7. Determine the application layer protocol, call the appropriate function to handle this.
	8. Print out information for this application level protocol.
**************************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <pcap.h>
#include <colors.h>
#include <arpa/inet.h>
#include <time.h>

#include "ethernet.h"

int main(int argc, char **argv){
	printf(RESET);
	if(argc != 2){
		printf("USAGE: sniff <device>\n");
		exit(1);
	}
	
	char *device = argv[1];					//The device to sniff on
	pcap_t *handle;							//The session handle
	char errorBuffer[PCAP_ERRBUF_SIZE];		//The buffer to store error messages in
	char *filterExpression = "port 53";	//The filter expression
	struct bpf_program filterProgram;		//The compiled filter expression obtained from pcap_compile()
	bpf_u_int32 networkNumber;				//32 bit network address
	bpf_u_int32 networkMask;				//32 bit network mask
	
	printf("Sniffing packets on device: %s\n", device);
	
	//Obtain the network address and the network mask for the device
	if(pcap_lookupnet(device, &networkNumber, &networkMask, errorBuffer) == -1){
		fprintf(stderr, "Can't get netmask for device %s, %s\n", device, errorBuffer);
		networkNumber = 0;
		networkMask = 0;
	}
	
	//Obtain a handle to the device, open the session in promiscuous mode
	handle = pcap_open_live(device, BUFSIZ, 1, 1000, errorBuffer);
	if(handle == NULL){
		fprintf(stderr, "Couldn't open device: %s, %s\n", device, errorBuffer);
		return 2;
	}
	/*
	//Compile the filter expression
	//ATTENTION, author uses networkNumber instead of mask
	if(pcap_compile(handle, &filterProgram, filterExpression, 0, networkNumber) == -1){
		fprintf(stderr, "Couldn't parse filter %s, %s\n", filterExpression, pcap_geterr(handle));
		return 2;
	}
	
	//Set the filter
	if(pcap_setfilter(handle, &filterProgram) == -1){
		fprintf(stderr, "Couldn't install filter %s: %s\n", filterExpression, pcap_geterr(handle));
		return 2;
	}
	*/
	pcap_loop( handle, -1, handle_ethernet, NULL );
	pcap_close(handle);
	
	return 0;
}











	/*
	//Compile the filter expression
	//ATTENTION, author uses networkNumber instead of mask
	if(pcap_compile(handle, &filterProgram, filterExpression, 0, networkNumber) == -1){
		fprintf(stderr, "Couldn't parse filter %s, %s\n", filterExpression, pcap_geterr(handle));
		return 2;
	}
	
	//Set the filter
	if(pcap_setfilter(handle, &filterProgram) == -1){
		fprintf(stderr, "Couldn't install filter %s: %s\n", filterExpression, pcap_geterr(handle));
		return 2;
	}
	
	if(pcap_datalink(handle) != DLT_EN10MB){
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
		return 2;
	}
	*/







/**************************************************************************************************************************
This is the function prototype for the call back function passed to pcap_loop()
void got_packet(u_char *args, 
				const struct pcap_pkthdr *header,
				const u_char *packet);
***************************************************************************************************************************
int pcap_lookupnet(const char *device, 			//The device to obtain information for
				   bpf_u_int32 *netp, 			//Pointer to 32 bit int to store network address in
				   bpf_u_int32 *maskp, 			//Pointer to 32 bit int to store network mask
				   char *errbuf);				//Pointer to the error buffer
	
	returns 0 on success and -1 on failure
***************************************************************************************************************************
int pcap_compile(pcap_t *p, 					//session handle
 				  struct bpf_program *fp,		//reference to the place we will store the compiled version of our filter
               	  const char *str, 				//the expression itself
               	  int optimize, 				//1 if you want the function to perform optimization, 0 otherwise
               	  bpf_u_int32 netmask);			//The network mask
	
	returns 0 on success and -1 on 
***************************************************************************************************************************
int pcap_setfilter(pcap_t *p, 					//session handle
				   struct bpf_program *fp);		//the filter compiled by pcap_compile()
	
	returns 0 on success and -1 on failure
**************************************************************************************************************************/

