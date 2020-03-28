/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

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

using namespace std;

/* used for flow controll */
clock_t starttime, endtime;

/* new the place for data of flow controll */
vector<string> indata;
vector<string> outdata;
vector<int> indata_len;
vector<int> outdata_len;

/* new the temporary string for transfrom */
string in_string;
string out_string;


/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
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


/* MAC header */
typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
}mac_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

/* prototype of the flow control */
void flow_control(mac_header* mh, ip_header* ih, int len);

/* prototype of the in_exsit */
int in_exsit(string a);

/* prototype of the out_exsit */
int out_exsit(string a);

/* prototype of the print statistic */
void prt_stc();

#define FROM_NIC
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
#ifdef FROM_NIC
			
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	/* Check if the user specified a valid adapter */
	if(inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");
		
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Check the link layer. We support only Ethernet for simplicity. */
	if(pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr,"\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	if(d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask=0xffffff; 


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	//set the filter
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	starttime = clock();
	pcap_loop(adhandle, 0, packet_handler, NULL);
#else	
	/* Open the capture file */
	if ((adhandle = pcap_open_offline("C:\\Users\\18705996097\\Desktop\\dns.pcap",			// name of the device
		errbuf					// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file.\n");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
#endif
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	/* print statistic */
	endtime = clock();
	if ((double)(endtime - starttime) / CLK_TCK >= 60)
		prt_stc();

	struct tm *ltime;
	char timestr[100];
	mac_header* mh;
	ip_header *ih;
	u_int ip_len;
	u_short sport,dport;
	time_t local_tv_sec;
	/*
	 * unused parameter
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S",ltime);

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

	/* print packet len*/
	printf("%d", header->len);
	printf("\n");

	/*flow control once for 60s */
	flow_control(mh, ih, int(header->len));
}

/*flow control once for 60s */
void flow_control(mac_header* mh, ip_header* ih, int len)
{
	char inbuf[1000];
	char outbuf[1000];

	/* sprint mac Source address */
	for (int i = 0; i < 6; ++i)
	{
		if (i != 5)
			sprintf(inbuf + 3 * i, "%02X-", mh->src_addr[i]);
		else
			sprintf(inbuf + 3 * i, "%02X,", mh->src_addr[i]);
	}

	/* sprint ip Source address*/
	for (int i = 0; i < 4; ++i)
	{
		if (i != 3)
			sprintf(inbuf + 4 * i + 18, "%03d.", ih->saddr[i]);
		else
			sprintf(inbuf + 4 * i + 18, "%03d ", ih->saddr[i]);
	}

	/* sprint mac Destination address*/
	for (int i = 0; i < 6; ++i)
	{
		if (i != 5)
			sprintf(outbuf + 3 * i, "%02X_", mh->dest_addr[i]);
		else
			sprintf(outbuf + 3 * i, "%02X,", mh->dest_addr[i]);
	}

	/* sprint ip Destination address*/
	for (int i = 0; i < 4; ++i)
	{
		if (i != 3)
			sprintf(outbuf + 4 * i + 18, "%03d.", ih->daddr[i]);
		else
			sprintf(outbuf + 4 * i + 18, "%03d ", ih->daddr[i]);
	}

	in_string = inbuf;
	out_string = outbuf;
	//	cout << "test" << (double)(endtime - starttime) / CLK_TCK << " string: "<< tmp_string << endl;
	int in_index = in_exsit(in_string);
	int out_index = out_exsit(out_string);
	if (in_index != -1)
	{
		indata_len[in_index] += len;
	}
	else
	{
		indata.push_back(in_string);
		indata_len.push_back(len);
	}
	if (out_index != -1)
	{
		outdata_len[out_index] += len;
	}
	else
	{
		outdata.push_back(out_string);
		outdata_len.push_back(len);
	}
}

	/* print the statistics */
void prt_stc()
{
		printf("indata:\n");
		for (int i = 0; i < indata.size(); ++i)
		{
			cout << indata[i];
			printf(" receive len: %d", indata_len[i]);

			/* out of limit 1MB alarm */
			if (indata_len[i] >= 1000000)
				printf("the length of this packet is out of 1MB!!!\n");
			printf("\n");
		}
		printf("\n");
		printf("outdata:\n");
		for (int i = 0; i < outdata.size(); ++i)
		{
			cout << outdata[i];
			printf(" send len: %d", outdata_len[i]);

			/* out of limit 1MB alarm */
			if (outdata_len[i] >= 1000000)
				printf("the length of this packet is out of 1MB!!!\n");
			printf("\n");
		}
		printf("\n");

		/* reset the statistics*/
		outdata.clear();
		indata.clear();
		indata_len.clear();
		outdata_len.clear();
		system("pause");
		starttime = clock();
}
/* judge inaddress exist */
int in_exsit(string a)
{
	for (int i = 0; i < indata.size(); ++i)
	{
		if (a == indata[i])
			return i;
	}
	return -1;
}

/* judge outaddress exist */
int out_exsit(string a)
{
	for (int i = 0; i < outdata.size(); ++i)
	{
		if (a == outdata[i])
			return i;
	}
	return -1;
}