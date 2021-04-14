#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <netinet/in.h> 
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define PKT_LEN 8192
#define DST_ADDR "10.0.0.255"


/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
//Define structures for both IP and UDP headers
typedef struct
{
    #if BYTE_ORDER == BIG_ENDIAN
    unsigned char version:4;
    unsigned char ihl:4;

    unsigned char tos:8;

    unsigned short int len:8;

    unsigned short int id:16;

    unsigned char flag:3;
    unsigned short int offset:13;
    
    unsigned char ttl:8;
    unsigned char protocol:8;
    unsigned short int checksum:16;
    unsigned int src_addr:32;
    unsigned int dst_addr:32;
    #else
    unsigned char ihl:4;
    unsigned char version:4;

    unsigned char tos:8;

    unsigned short int len:8;

    unsigned short int id:16;

    unsigned char flag:3;
    unsigned short int offset:13;
    
    unsigned char ttl:8;
    unsigned char protocol:8;
    unsigned short int checksum:16;
    unsigned int src_addr:32;
    unsigned int dst_addr:32;
    #endif

}ip_header;

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            SRC_PORT           |           DST_PORT            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Length            |             Checksum          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

typedef struct
{
    unsigned short int src_port;
    unsigned short int dst_port;
    unsigned short int len;
    unsigned short int chksum;
}udp_header;

/*
0                   1                   2                   
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Sync | RT Addr |T| Subaddr | wrd cnt |P| Pddng |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

typedef struct __attribute__((__packed__))
{
    #if BYTE_ORDER == BIG_ENDIAN
    unsigned char sync_bits:3;
    unsigned char rt_address:5;

    unsigned char tr_bit:1;
    unsigned char subaddress:5;
    unsigned char word_count1:2;

    unsigned char word_count2:3;
    unsigned char parity_bit:1;
    unsigned char padding:4;
    #else
    unsigned char rt_address:5;
    unsigned char sync_bits:3;
    
    unsigned char word_count1:2;
    unsigned char subaddress:5;
    unsigned char tr_bit:1;

    unsigned char padding:4;
    unsigned char parity_bit:1;
    unsigned char word_count2:3;   
    #endif

}command_word_s;

/*
0                   1                   2                   
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Sync |   CHAR 1    |      CHAR 2     |P| Pddng |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

typedef struct __attribute__((__packed__)) 
{
    #if BYTE_ORDER == BIG_ENDIAN
    unsigned char sync_bits:3;
    unsigned char character_A1:5;

    unsigned char character_A2:3;
    unsigned char character_B1:5;

    unsigned char character_B2:3;
    unsigned char parity_bit:1;
    unsigned char padding:4;
    #else
    unsigned char character_A1:5;
    unsigned char sync_bits:3;

    unsigned char character_B1:5;
    unsigned char character_A2:3;

    unsigned char padding:4;
    unsigned char parity_bit:1;
    unsigned char character_B2:3;
    #endif

}data_word_s;

typedef struct __attribute__((__packed__))
{
    #if BYTE_ORDER == BIG_ENDIAN
    unsigned char sync_bits:3;
    unsigned char reserved0:5;

    unsigned char reserved1:8;
 
    unsigned char reserved2:8;
    unsigned char padding:4;
    #else
    unsigned char reserved0:5;
    unsigned char sync_bits:3;
    
    unsigned char reserved1:8;

    unsigned char padding:4;
    unsigned char reserved2:4;
    #endif
}generic_word_s;



//Used to calculate IP checksum
unsigned short csum(unsigned short *buf, int nwords)
{
        unsigned long sum;
        for(sum=0; nwords>0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return (unsigned short)(~sum);

}

int create_raw_socket()
{
    int raw_socket;
    struct sockaddr_in src;
    struct sockaddr_in dst;
    char buffer[PKT_LEN];
    int one = 1;
    const int *val = &one;
    ip_header *ip = (ip_header *) buffer;
    udp_header *udp = (udp_header *)(buffer + sizeof(ip_header));

    //either set the payload as a command word or data word depending on what you'd like to send (uncomment whichever).
    command_word_s *payload = (command_word_s *)(buffer + sizeof(ip_header) + sizeof(udp_header));
    //data_word_s *payload = (data_word_s *)(buffer + sizeof(ip_header) + sizeof(udp_header));

    memset(buffer, 0, PKT_LEN);
    //Create raw socket
    raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_socket < 0)
    {
        perror("Error opening socket\n");
        exit(-1);
    }
    else
    {
        printf("Socket opened\n");
    }
    //defining source destination IP and port
    src.sin_family = AF_INET;
    src.sin_addr.s_addr = INADDR_ANY;
    src.sin_port = htons(8080);
    //defining destination IP/port
    dst.sin_family = AF_INET;
    dst.sin_port = htons(2001);
    src.sin_addr.s_addr = inet_addr(DST_ADDR);

    //set desired values for IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 16;
    ip->len = sizeof(ip_header) + sizeof(udp_header) + sizeof(command_word_s);
    ip->id = htons(54321);
    ip->ttl = 5;
    ip->protocol = 17; //UDP
    ip->src_addr = inet_addr("10.0.0.10");
    ip->dst_addr = inet_addr(DST_ADDR);
    ip->checksum = csum((unsigned short *)buffer, sizeof(ip_header) + sizeof(udp_header));

    //create UDP header
    udp->src_port = htons(8080);
    udp->dst_port = htons(2001);
    udp->len = htons(sizeof(udp_header) + sizeof(command_word_s));
    udp->chksum = 0;

    //Define payload (This is where you can set the bits to whatever you'd like to mimic s/c commands)
    payload->sync_bits = 7;
    payload->rt_address = 31;
    payload->tr_bit = 1;
    payload->subaddress = 31;
    payload->word_count1 = 3;
    payload->word_count2 = 7;
    payload->parity_bit = 1;
    payload->padding = 15;


    if(setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("Option error\n");
        exit(-1);
    }
    else
    {
        printf("Options are OK.\n");
    }

    if(sendto(raw_socket, buffer, ip->len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0)
    {
        perror("Send error.\n");
    }
    else
    {
        printf("sent");
    }

    return 0;

}

int main()
{
    create_raw_socket();
    return 0;
}