#ifdef _MSC_VER
 /*
  * we do not want the warnings about the old deprecated and unsecure CRT functions
  * since these examples can be compiled under *nix as well
  */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include <Windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include<cstring>
#include<cstdio>

using namespace std;

/* 用于存放用户、口令、是否成功信息 */
string ftp[100];

/* 4 bytes IP address */
typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header 20Bytes */
typedef struct ip_header
{
    u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
    u_char	tos;			// Type of service 
    u_short tlen;			// Total length 
    u_short identification; // Identification
    u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
    u_char	ttl;			// Time to live
    u_char	proto;			// Protocol
    u_short crc;			// Header checksum
    u_char	saddr[4];		// Source address
    u_char	daddr[4];		// Destination address
    u_int	op_pad;			// Option + Padding
}ip_header;


/* MAC header 14Bytes */
typedef struct mac_header {
    u_char dest_addr[6];
    u_char src_addr[6];
    u_char type[2];
}mac_header;

/* TCP header 20Bytes */
typedef struct tcp_header
{
    u_short sport;            //源端口号  
    u_short dport;             //目的端口号  
    u_int th_seq;                //序列号  
    u_int th_ack;               //确认号  
    u_int th1 : 4;              //tcp头部长度  
    u_int th_res : 4;             //6位中的4位首部长度  
    u_int th_res2 : 2;            //6位中的2位首部长度  
    u_char th_flags;            //6位标志位  
    u_short th_win;             //16位窗口大小  
    u_short th_sum;             //16位tcp检验和  
    u_short th_urp;             //16位紧急指针  
}tcp_header;

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int netmask;
    char packet_filter[] = "tcp";
    struct bpf_program fcode;

    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    /* Check if the user specified a valid adapter */
    if (inum < 1 || inum > i)
    {
        printf("\nAdapter number out of range.\n");

        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    /* Open the adapter */
    if ((adhandle = pcap_open_live(d->name,	// name of the device
        65536,			// portion of the packet to capture. 
                       // 65536 grants that the whole packet will be captured on all the MACs.
        1,				// promiscuous mode (nonzero means promiscuous)
        1000,			// read timeout
        errbuf			// error buffer
        )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Check the link layer. We support only Ethernet for simplicity. */
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    if (d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask = 0xffffff;


    //compile the filter
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    //set the filter
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", d->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* 重定向输出到文件 */
    freopen("ftp_login_message.txt", "w", stdout);

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
   ;


    struct tm* ltime;
    char timestr[100];
    mac_header* mh;
    ip_header* ih;
    tcp_header* th;
    u_short sport, dport;
    time_t local_tv_sec;
    int flag = 0;
    /*
     * unused parameter
     */
   (VOID)(param);

        /* print TCP user pass and log*/
        int tcp_head = 54;     // 14MAC+20IP+20TCP
        string com;
        for (int i = 0; i < 4; ++i)
            com += (char)pkt_data[tcp_head + i];
        if (com == "USER")
        {
            string user;
            ostringstream sout;
            for (int i = tcp_head + 5; pkt_data[i] != 13; ++i)    //以0d结尾
            {
                sout << pkt_data[i];
            }
            user = sout.str();
            ftp[0] = user;
        }
        else if (com == "PASS")
        {
            string pass;
            ostringstream sout;
            for (int i = tcp_head + 5; pkt_data[i] != 13; ++i)    //以0d结尾
            {
                sout << pkt_data[i];
            }
            pass = sout.str();
            ftp[1] = pass;
        }
        else if (com == "230 ")
        {
            ftp[2] = "SUCCEED";
            flag = 3;
        }
        else if (com == "530 ")
        {
            ftp[2] = "FAILD";
            flag = 3;
        }

        if (flag == 3)
        {
            /* convert the timestamp to readable format */
            local_tv_sec = header->ts.tv_sec;
            ltime = localtime(&local_tv_sec);
            strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);

            /* print timestamp and length of the packet */
            printf("%s,", timestr);

            /* retireve the position of the mac header */
            mh = (mac_header*)pkt_data;

            /* retireve the position of the ip header */
            ih = (ip_header*)(pkt_data +
                sizeof(mac_header)); //length of ethernet header

            /* print mac Source address */
            for (int i = 0; i < 6; ++i)
            {
                if (i != 5)
                    printf("%02X-", mh->src_addr[i]);
                else
                    printf("%02X,", mh->src_addr[i]);
            }

            /* print ip Source address*/
            for (int i = 0; i < 4; ++i)
            {
                if (i != 3)
                    printf("%d.", ih->saddr[i]);
                else
                    printf("%d,", ih->saddr[i]);
            }

            /* print mac Destination address*/
            for (int i = 0; i < 6; ++i)
            {
                if (i != 5)
                    printf("%02X_", mh->dest_addr[i]);
                else
                    printf("%02X,", mh->dest_addr[i]);
            }

            /* print ip Destination address*/
            for (int i = 0; i < 4; ++i)
            {
                if (i != 3)
                    printf("%d.", ih->daddr[i]);
                else
                    printf("%d,", ih->daddr[i]);
            }
            cout << ftp[0] << ",";
            cout << ftp[1] << ",";
            cout << ftp[2] << endl;
            flag = 0;
        }
}