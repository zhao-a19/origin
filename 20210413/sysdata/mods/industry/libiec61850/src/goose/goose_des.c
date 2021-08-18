/*
 * goose_subscriber_example.c
 *
 * This is an example for a standalone GOOSE subscriber
 *
 * Has to be started as root in Linux.
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <netinet/in.h>

//#include "goose_receiver.h"
//#include "hal_thread.h"
//#include <inttypes.h>

#include "IEC61850SpecificProtocol.h"

#define BUFFER_MAX 2048
#define ETH "eth0"
#define ETH_P_GOOSE 0x88ba

void print_hex(const uint8_t *data, int len) {
	IEC61850SpecificProtocol_t * goose_pdu = 0;
	asn_dec_rval_t rval;

	rval = ber_decode(NULL, &asn_DEF_IEC61850SpecificProtocol, (void **)&goose_pdu, data, 2048);
	if (rval.code != RC_OK) {
		fprintf(stderr, "ber_docode failed.\n");
		return;
	}

	xer_fprint(stdout, &asn_DEF_IEC61850SpecificProtocol, goose_pdu);
	asn_DEF_IEC61850SpecificProtocol.free_struct(&asn_DEF_IEC61850SpecificProtocol, goose_pdu, 0);
}

int main(int argc, char *argv[]){
    int  sd;
    uint8_t buf[BUFFER_MAX];
    int n_rd;

    if( (sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_GOOSE))) < 0 ){
        fprintf(stderr, "create socket error.\n");
        exit(0);
    }

	//set eth0 in promisc mode
	getInterfaceIndex(sd, ETH);

    while(1){
        n_rd = recvfrom(sd, buf, BUFFER_MAX, 0, NULL, NULL);
      if (n_rd<46) {
          perror("recvfrom():");
           printf("Incomplete packet (errno is %d)\n",  errno);
           close(sd);
           exit(0);
      }
	  if (n_rd > 46) {
		print_hex(buf+26, n_rd-26);
	  }
    }
    close(sd);
    return 0;
}

