#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include "packet.h"
#include "nethelper.h"
#include "decoder.h"

//This is where you will be putting your captured network frames for testing.
//Before you do your own, please test with the ones that I provided as samples:
#include "testframes.h"

//You can update this array as you add and remove test cases, you can
//also comment out all but one of them to isolate your testing. This
//allows us to loop over all of the test cases.  Note MAKE_PACKET creates
//a test_packet_t element for each sample, this allows us to get and use
//the packet length, which will be helpful later.
test_packet_t TEST_CASES[] = {
    MAKE_PACKET(raw_packet_icmp_frame198),
    MAKE_PACKET(raw_packet_icmp_frame362),
    MAKE_PACKET(raw_packet_arp_frame78)
};

int main(int argc, char **argv) {
    //This code is here as a refresher on how to figure out how
    //many elements are in a statically defined C array. Note
    //that sizeof(TEST_CASES) is not 3, its the total number of 
    //bytes.  On my machine it comes back with 48, because each
    //element is of type test_packet_t which on my machine is 16 bytes.
    //Thus, with the scaffold I am providing 48/16 = 3, which is
    //the correct size.  
    int num_test_cases = sizeof(TEST_CASES) / sizeof(test_packet_t);

    printf("STARTING...");
    for (int i = 0; i < num_test_cases; i++) {
        printf("\n--------------------------------------------------\n");
        printf("TESTING A NEW PACKET\n");
        printf("--------------------------------------------------\n");
        test_packet_t test_case = TEST_CASES[i];

        decode_raw_packet(test_case.raw_packet, test_case.packet_len);
    }

    printf("\nDONE\n");
}

void decode_raw_packet(uint8_t *packet, uint64_t packet_len){

    printf("Packet length = %ld bytes\n", packet_len);

    //Everything we are doing starts with the ethernet PDU at the
    //front.  The below code projects an ethernet_pdu structure 
    //POINTER onto the front of the buffer so we can decode it.
    struct ether_pdu *p = (struct ether_pdu *)packet;
    uint16_t ft = ntohs(p->frame_type);

    printf("Detected raw frame type from ethernet header: 0x%x\n", ft);

    switch(ft) {
        case ARP_PTYPE:
            printf("Packet type = ARP\n");

            //Lets process the ARP packet, convert all of the network byte order
            //fields to host machine byte order
            arp_packet_t *arp = process_arp(packet);

            //Print the arp packet
            print_arp(arp);
            break;
        case IP4_PTYPE:
            printf("Frame type = IPv4, now lets check for ICMP...\n");

            //We know its IP, so lets type the raw packet as an IP packet
            ip_packet_t *ip = (ip_packet_t *)packet;

            //Now check the IP packet to see if its payload is an ICMP packet
            bool isICMP = check_ip_for_icmp(ip);
            if (!isICMP) {
                printf("ERROR: IP Packet is not ICMP\n");
                break;
            }

            //Now lets process the basic icmp packet, convert the network byte order 
            //fields to host byte order
            icmp_packet_t *icmp = process_icmp(ip);

            //Now lets look deeper and see if the icmp packet is actually an
            //ICMP ECHO packet?
            bool is_echo = is_icmp_echo(icmp);
            if (!is_echo) {
                printf("ERROR: We have an ICMP packet, but it is not of type echo\n");
                break;
            }

            //Now lets process the icmp_packet as an icmp_echo_packet, again processing
            //the network byte order fields
            icmp_echo_packet_t *icmp_echo_packet = process_icmp_echo(icmp);

            //The ICMP packet now has its network byte order fields
            //adjusted, lets print it
            print_icmp_echo(icmp_echo_packet);

            break;
    default:
        printf("UNKNOWN Frame type?\n");
    }
}

/********************************************************************************/
/*                       ARP PROTOCOL HANDLERS                                  */
/********************************************************************************/

arp_packet_t *process_arp(raw_packet_t raw_packet) {
    
    //first, take the raw packet and type-cast it into an arp packet
    //then, for each field that needs to have its "endian-ness" switched
    //create a new variable, assign it the newly converted host byte ordered value
    //then just replace the old field value with the newly converted one
    //at the end return the new arp packet with converted values

    arp_packet_t *new_arp_packet = (arp_packet_t *)raw_packet;

    ube16_t converted_frame_type = ntohs(new_arp_packet->eth_hdr.frame_type);
    new_arp_packet->eth_hdr.frame_type = converted_frame_type;

    ube16_t converted_htype = ntohs(new_arp_packet->arp_hdr.htype);
    new_arp_packet->arp_hdr.htype = converted_htype;

    ube16_t converted_ptype = ntohs(new_arp_packet->arp_hdr.ptype);
    new_arp_packet->arp_hdr.ptype = converted_ptype;

    ube16_t converted_op = ntohs(new_arp_packet->arp_hdr.op);
    new_arp_packet->arp_hdr.op = converted_op;

    return new_arp_packet;
}

void print_arp(arp_packet_t *arp){
    //create two string buffers to hold values from helper toStr functions
    //most of the fields can just be handled simply with printf statements
    //until we get to the ip & mac address fields, here we make use of the nethelper.h functions
    //could put in the extra work for fancy width spacing, but i think it looks fine like as is

    char ip[16];
    char mac[18];
    printf("ARP PACKET DETAILS\n");
    printf("htype: %#06x\n", arp->arp_hdr.htype);
    printf("ptype: %#06x\n", arp->arp_hdr.ptype);
    printf("hlen: %d\n", arp->arp_hdr.hlen);
    printf("plen: %d\n", arp->arp_hdr.plen);
    printf("op: %d\n", arp->arp_hdr.op);
    ip_toStr(arp->arp_hdr.spa, ip, 16);
    printf("spa: %s\n", ip);
    mac_toStr(arp->arp_hdr.sha, mac, 18);
    printf("sha: %s\n", mac);
    ip_toStr(arp->arp_hdr.tpa, ip, 16);
    printf("tpa: %s\n", ip);
    mac_toStr(arp->arp_hdr.tha, mac, 18);
    printf("tha: %s\n", mac);
}

/********************************************************************************/
/*                       ICMP PROTOCOL HANDLERS                                  */
/********************************************************************************/

bool check_ip_for_icmp(ip_packet_t *ip){
    //If we have an ICMP packet return true, otherwise return false
    if(ip->ip_hdr.protocol == ICMP_PTYPE)
        return true;
    else
        return false;
}

icmp_packet_t *process_icmp(ip_packet_t *ip){
    //same process as with arp packets, except we must take care to convert fields from stacked PDUs 

    icmp_packet_t *new_icmp_packet = (icmp_packet_t *)ip;

    ube16_t converted_frame_type = ntohs(new_icmp_packet->ip.eth_hdr.frame_type);
    new_icmp_packet->ip.eth_hdr.frame_type = converted_frame_type;

    ube16_t converted_identification = ntohs(new_icmp_packet->ip.ip_hdr.identification);
    new_icmp_packet->ip.ip_hdr.identification = converted_identification;

    ube16_t converted_flags_and_fragment_offset = ntohs(new_icmp_packet->ip.ip_hdr.flags_and_fragment_offset);
    new_icmp_packet->ip.ip_hdr.flags_and_fragment_offset = converted_flags_and_fragment_offset;

    ube16_t converted_header_checksum = ntohs(new_icmp_packet->ip.ip_hdr.header_checksum);
    new_icmp_packet->ip.ip_hdr.header_checksum = converted_header_checksum;

    ube16_t converted_checksum = ntohs(new_icmp_packet->icmp_hdr.checksum);
    new_icmp_packet->icmp_hdr.checksum = converted_checksum;

    return new_icmp_packet;
}

/*
 *  This function takes a known ICMP packet, and checks if its of type ECHO. We do
 *  this by checking the "type" field in the icmp_hdr and evaluating if its equal to
 *  ICMP_ECHO_REQUEST or ICMP_ECHO_RESPONSE.  If true, we return true. If not, its
 *  still ICMP but not of type ICMP_ECHO. 
 */
bool is_icmp_echo(icmp_packet_t *icmp) {
    //If we have a packet of either type ECHO, return true, otherwise return false
    if(icmp->icmp_hdr.type == ICMP_ECHO_REQUEST || icmp->icmp_hdr.type == ICMP_ECHO_RESPONSE)
        return true;
    else
        return false;
}

/*
 *  This function takes a known ICMP packet, that has already been checked to be
 *  of type ECHO and converts it to an (icmp_echo_packet_t).  Like in the other
 *  cases this is simply a type converstion, but there are also a few fields to
 *  convert from network to host byte order.
 */
icmp_echo_packet_t *process_icmp_echo(icmp_packet_t *icmp){
    //same process as with icmp packets, except with even more stacked PDUs and we must make use of ntohl()

    icmp_echo_packet_t *new_icmp_echo_packet = (icmp_echo_packet_t *) icmp;

    ube16_t converted_sequence = ntohs(new_icmp_echo_packet->icmp_echo_hdr.sequence);
    new_icmp_echo_packet->icmp_echo_hdr.sequence = converted_sequence;

    ube32_t converted_timestamp = ntohl(new_icmp_echo_packet->icmp_echo_hdr.timestamp);
    new_icmp_echo_packet->icmp_echo_hdr.timestamp = converted_timestamp;

    ube32_t converted_timestamp_ms = ntohl(new_icmp_echo_packet->icmp_echo_hdr.timestamp_ms);
    new_icmp_echo_packet->icmp_echo_hdr.timestamp_ms = converted_timestamp_ms;

    return new_icmp_echo_packet;
}

/*
 *  This function pretty prints the icmp_packet.  After it prints the header aka PDU
 *  it calls print_icmp_payload to print out the echo packet variable data.  To do
 *  this it needs to calculate the length of the "payload" field.  To make things
 *  easier for you to call print_icmp_payload you can use a macro I provided.  Thus...
 * 
 *  uint16_t payload_size = ICMP_Payload_Size(icmp_packet);
 * 
 *  gives the size of the payload buffer.
 */
void print_icmp_echo(icmp_echo_packet_t *icmp_packet){
    //i got cancer formatting this, but it's beautiful now!
    uint16_t payload_size = ICMP_Payload_Size(icmp_packet);
    
    printf("ICMP PACKET DETAILS\n");
    printf("type: %#04x\n", icmp_packet->icmp_echo_hdr.icmp_hdr.type);
    printf("checksum: %#06x\n", icmp_packet->icmp_echo_hdr.icmp_hdr.checksum);
    printf("id: %#06x\n", icmp_packet->icmp_echo_hdr.id);
    printf("sequence: %#06x\n", icmp_packet->icmp_echo_hdr.sequence);
    printf("timestamp: %#x%x\n", icmp_packet->icmp_echo_hdr.timestamp, icmp_packet->icmp_echo_hdr.timestamp_ms);
    printf("payload: %d bytes\n", payload_size);
    time_t timestamp = icmp_packet->icmp_echo_hdr.timestamp;
    time_t timestamp_ms = icmp_packet->icmp_echo_hdr.timestamp_ms;
    struct tm * ts;
    ts = localtime(&timestamp);
    printf("ECHO Timestamp: %d-%02d-%02d %02d:%02d:%02d.%d\n", ts->tm_year + 1900, ts->tm_mon + 1, ts->tm_mday, ts->tm_hour, ts->tm_min, ts->tm_sec, timestamp_ms);

    //Now print the payload data
    print_icmp_payload(icmp_packet->icmp_payload, payload_size);
}

void print_icmp_payload(uint8_t *payload, uint16_t payload_size) {
    printf("\nPAYLOAD\n\n");
    int line_length = 8;
    for(int i = 0; i < payload_size; i++) {
        if((i % line_length) == 0)    //if at the start of a new line, print the offset
            printf("%#06x", i);
        printf(" %#04x", payload[i]);   //always print our payload 
        if(i % line_length == line_length - 1)    //if we're at line end, add a newline
            printf("\n");
    }
}


