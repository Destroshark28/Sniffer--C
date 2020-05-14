#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS 

#include "stdio.h"
#include "winsock2.h"
#include <windows.h>
#include <conio.h>
#include <iostream>
#include <vector>
#include <stack>
#include <process.h>

#pragma comment(lib,"ws2_32.lib") //For winsock

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) //this removes the need of mstcpip.h

void StartSniffing(SOCKET Sock); //This will sniff here and there

void ProcessPacket(char*, int); //This will decide how to digest
void PrintIpHeader(char*);
void PrintIcmpPacket(char*, int);
void PrintUdpPacket(char*, int);
void PrintTcpPacket(char*, int);
void PrintIGMPpacket(char*, int);
void PrintData(char*, int);

typedef struct IPHeader
{
	unsigned char IPHeaderLen : 4; // §Õ§Ý§Ú§ß§Ñ 4-§Ò§Ú§ä§ß§à§Ô§à §Ù§Ñ§Ô§à§Ý§à§Ó§Ü§Ñ
	unsigned char IPVersion : 4; //§Ó§Ö§â§ã§Ú§ñ §Ù§Ñ§Ô§à§Ý§à§Ó§Ü§Ñ
	unsigned char IPTOS; // §ä§Ú§á §ã§Ö§â§Ó§Ú§ã§Ñ
	USHORT IPTotalLength; // §Õ§Ý§Ú§ß§Ñ §Ó§ã§Ö§Ô§à §á§Ñ§Ü§Ö§ä§Ñ
	USHORT IPID; 

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char IPMoreFragment : 1;
	unsigned char IPDoNotFragment : 1;
	unsigned char IPReservedZero : 1;

	unsigned char IPFragmentOffsetFlag; //fragment offset

	unsigned char IPTTL; // §Ó§â§Ö§Þ§ñ §Ø§Ú§Ù§ß§Ú
	unsigned char IPProtocol; // §á§â§à§ä§à§Ü§à§Ý
	USHORT IPCheckSum; // §Ü§à§ß§ä§â§à§Ý§î§ß§Ñ§ñ §ã§å§Þ§Þ§Ñ
	unsigned int IPSRCAddress; // IP-§Ñ§Õ§â§Ö§ã §à§ä§á§â§Ñ§Ó§Ú§ä§Ö§Ý§ñ
	unsigned int IPDESTAddress; // IP-§Ñ§Õ§â§Ö§ã §ß§Ñ§Ù§ß§Ñ§é§Ö§ß§Ú§ñ
} IPV4Header;

typedef struct UDPHeader
{
	USHORT sourcePort; // §á§à§â§ä §à§ä§á§â§Ñ§Ó§Ú§ä§Ö§Ý§ñ
	USHORT destPort; // §á§à§â§ä §ß§Ñ§Ù§ß§Ñ§é§Ö§ß§Ú§ñ
	USHORT UDPLength; //§Õ§Ý§Ú§ß§Ñ UDP §á§Ñ§Ü§Ö§ä§Ñ
	USHORT UDPCheckSum; //  §Ü§à§ß§ä§â§à§Ý§î§ß§Ñ§ñ §ã§å§Þ§Þ§Ñ
};

// TCP header
typedef struct TCPHeader
{
	USHORT sourcePort; //§á§à§â§ä §Ú§ã§ä§à§é§ß§Ú§Ü§Ñ
	USHORT destPort; // destination §á§à§â§ä §ß§Ñ§Ù§ß§Ñ§é§Ö§ß§Ú§ñ
	unsigned int sequenceNumber; // §á§à§â§ñ§Õ§Ü§à§Ó§í§Û §ß§à§Þ§Ö§â
	unsigned int acknowledgementNumber; // §ß§à§Þ§Ö§â §á§à§Õ§ä§Ó§Ö§â§Ø§Õ§Ö§ß§Ú§ñ

	unsigned char nonceSum : 1; //§à§Õ§ß§à§â§Ñ§Ù§à§Ó§Ñ§ñ §ã§å§Þ§Þ§Ñ. §ª§ã§á§à§Ý§î§Ù§å§Ö§ä§ã§ñ §Õ§Ý§ñ §å§Ý§å§é§ê§Ö§ß§Ú§ñ §â§Ñ§Ò§à§ä§í §Þ§Ö§ç§Ñ§ß§Ú§Ù§Þ§Ñ §ñ§Ó§ß§à§Ô§à §å§Ó§Ö§Õ§à§Þ§Ý§Ö§ß§Ú§ñ §à §á§Ö§â§Ö§Ô§â§å§Ù§Ü§Ö
	unsigned char reserved : 3; //§Ù§Ñ§â§Ö§Ù§Ö§â§Ó§Ú§â§à§Ó§Ñ§ß§à. §©§Ñ§â§Ö§Ù§Ö§â§Ó§Ú§â§à§Ó§Ñ§ß§à §Õ§Ý§ñ §Ò§å§Õ§å§ë§Ö§Ô§à §Ú§ã§á§à§Ý§î§Ù§à§Ó§Ñ§ß§Ú§ñ
	unsigned char dataOffset : 4; //§Õ§Ý§Ú§ß§Ñ §Ù§Ñ§Ô§à§Ý§à§Ó§Ü§Ñ	

	unsigned char finishFlag : 1; 
	unsigned char synchroniseFlag : 1; 
	unsigned char resetFlag : 1; 
	unsigned char pushFlag : 1; 
	unsigned char acknowledgementFlag : 1; 
	unsigned char urgentFlag : 1; 

	unsigned char ECNEchoFlag : 1; //ECN-Echo Flag
	unsigned char congestionWindowReducedFlag : 1; 

	////////////////////////////////

	USHORT window; // §Ü§à§Ý§Ú§é§Ö§ã§ä§Ó§à §Ò§Ñ§Û§ä §Õ§Ñ§ß§ß§í§ç
	USHORT checksum; //  §Ü§à§ß§ä§â§à§Ý§î§ß§Ñ§ñ §ã§å§Þ§Þ§Ñ
	USHORT urgent_pointer; //§å§Ü§Ñ§Ù§Ñ§ä§Ö§Ý§î §Ó§Ñ§Ø§ß§à§ã§ä§Ú
};

typedef struct ICMPHeader
{
	BYTE ICMPErrorType;
	BYTE typeSubCode; 
	USHORT checkSum; // §Ü§à§ß§ä§â§à§Ý§î§ß§Ñ§ñ §ã§å§Þ§Þ§Ñ
	USHORT ID;
	USHORT seq;
};

typedef struct IGMPHeader {
	BYTE IGMPType; 
	BYTE typeSubCode;
	USHORT checkSum; // §Ü§à§ß§ä§â§à§Ý§î§ß§Ñ§ñ §ã§å§Þ§Þ§Ñ
};

FILE *logfile;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i, j;
struct sockaddr_in source, dest;
char hex[2];

//Its free!
IPV4Header *iphdr;
TCPHeader *tcpheader;
UDPHeader *udpheader;
ICMPHeader *icmpheader;
IGMPHeader *igmpheader;

int main()
{
	SOCKET sniffer;
	struct in_addr addr;
	int in;

	char hostname[100];
	struct hostent *local;
	WSADATA wsa;

	logfile = fopen("log.txt", "w");
	if (logfile == NULL)
	{
		printf("Unable to create file.");
	}

	//Initialise Winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("WSAStartup() failed.\n");
		return 1;
	}
	printf("Initialised");

	//Create a RAW Socket
	printf("\nCreating RAW Socket...");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET)
	{
		printf("Failed to create raw socket.\n");
		return 1;
	}
	printf("Created.");

	//Retrive the local hostname
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
	{
		printf("Error : %d", WSAGetLastError());
		return 1;
	}
	printf("\nHost name : %s \n", hostname);

	//Retrive the available IPs of the local host
	local = gethostbyname(hostname);
	printf("\nAvailable Network Interfaces : \n");
	if (local == NULL)
	{
		printf("Error : %d.\n", WSAGetLastError());
		return 1;
	}

	for (i = 0; local->h_addr_list[i] != 0; ++i)
	{
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		printf("Interface Number : %d Address : %s\n", i, inet_ntoa(addr));
	}

	printf("Enter the interface number you would like to sniff : ");
	scanf("%d", &in);

	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr, local->h_addr_list[in], sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	printf("\nBinding socket to local system and port 0 ...");
	if (bind(sniffer, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR)
	{
		printf("bind(%s) failed.\n", inet_ntoa(addr));
		return 1;
	}
	printf("Binding successful");

	//Enable this socket with the power to sniff : SIO_RCVALL is the key Receive ALL ;)

	j = 1;
	printf("\nSetting socket to sniff...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD)&in, 0, 0) == SOCKET_ERROR)
	{
		printf("WSAIoctl() failed.\n");
		return 1;
	}
	printf("Socket set.");

	//Begin
	printf("\nStarted Sniffing\n");
	printf("Packet Capture Statistics...\n");

	StartSniffing(sniffer); //Happy Sniffing

	//End
	closesocket(sniffer);
	WSACleanup();

	return 0;
}

void StartSniffing(SOCKET sniffer)
{
	char *Buffer = (char *)malloc(65536); //Its Big!
	int mangobyte;

	if (Buffer == NULL)
	{
		printf("malloc() failed.\n");
		return;
	}

	do
	{
		mangobyte = recvfrom(sniffer, Buffer, 65536, 0, 0, 0); //Eat as much as u can

		if (mangobyte > 0)
		{
			ProcessPacket(Buffer, mangobyte);
		}
		else
		{
			printf("recvfrom() failed.\n");
		}
	} while (mangobyte > 0);

	free(Buffer);
}

void ProcessPacket(char* Buffer, int Size)
{
	iphdr = (IPV4Header *)Buffer;
	++total;
	
	switch (iphdr->IPProtocol) //Check the Protocol and do accordingly...
	{
	case 1: //ICMP Protocol
		++icmp;
		PrintIcmpPacket(Buffer, Size);
		break;

	case 2: //IGMP Protocol
		++igmp;
		PrintIGMPpacket(Buffer, Size);
		break;

	case 6: //TCP Protocol
		++tcp;
		PrintTcpPacket(Buffer, Size);
		break;

	case 17: //UDP Protocol
		++udp;
		PrintUdpPacket(Buffer, Size);
		break;

	default: //Some Other Protocol like ARP etc.
		++others;
		break;
	}
	printf("TCP : %d UDP : %d ICMP : %d IGMP : %d Others : %d Total : %d\r", tcp, udp, icmp, igmp, others, total);
}

void PrintIpHeader(char* Buffer)
{
	unsigned short iphdrlen;

	iphdr = (IPV4Header *)Buffer;
	iphdrlen = iphdr->IPHeaderLen * 4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->IPSRCAddress;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->IPDESTAddress;

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");
	fprintf(logfile, " |-IP Version : %d\n", (unsigned int)iphdr->IPVersion);
	fprintf(logfile, " |-IP Header Length : %d DWORDS or %d Bytes\n", (unsigned int)iphdr->IPHeaderLen, ((unsigned int)(iphdr->IPHeaderLen)) * 4);
	fprintf(logfile, " |-Type Of Service : %d\n", (unsigned int)iphdr->IPTOS);
	fprintf(logfile, " |-IP Total Length : %d Bytes(Size of Packet)\n", ntohs(iphdr->IPTotalLength));
	fprintf(logfile, " |-Identification : %d\n", ntohs(iphdr->IPID));
	fprintf(logfile, " |-Reserved ZERO Field : %d\n", (unsigned int)iphdr->IPReservedZero);
	fprintf(logfile, " |-Dont Fragment Field : %d\n", (unsigned int)iphdr->IPDoNotFragment);
	fprintf(logfile, " |-More Fragment Field : %d\n", (unsigned int)iphdr->IPMoreFragment);
	fprintf(logfile, " |-TTL : %d\n", (unsigned int)iphdr->IPTTL);
	fprintf(logfile, " |-Protocol : %d\n", (unsigned int)iphdr->IPProtocol);
	fprintf(logfile, " |-Checksum : %d\n", ntohs(iphdr->IPCheckSum));
	fprintf(logfile, " |-Source IP : %s\n", inet_ntoa(source.sin_addr));
	fprintf(logfile, " |-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
}

void PrintTcpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4Header *)Buffer;
	iphdrlen = iphdr->IPHeaderLen * 4;

	tcpheader = (TCPHeader*)(Buffer + iphdrlen);
	if ((Size - sizeof(TCPHeader) - iphdr->IPHeaderLen * 4) == 0)
		return;
	fprintf(logfile, "\n\n***********************TCP Packet*************************\n");

	PrintIpHeader(Buffer);

	fprintf(logfile, "\n");
	fprintf(logfile, "TCP Header\n");
	fprintf(logfile, " |-Source Port : %u\n", ntohs(tcpheader->sourcePort));
	fprintf(logfile, " |-Destination Port : %u\n", ntohs(tcpheader->destPort));
	fprintf(logfile, " |-Sequence Number : %u\n", ntohl(tcpheader->sequenceNumber));
	fprintf(logfile, " |-Acknowledge Number : %u\n", ntohl(tcpheader->acknowledgementNumber));
	fprintf(logfile, " |-Header Length : %d DWORDS or %d BYTES\n"
		, (unsigned int)tcpheader->dataOffset, (unsigned int)tcpheader->dataOffset * 4);
	fprintf(logfile, " |-CWR Flag : %d\n", (unsigned int)tcpheader->congestionWindowReducedFlag);
	fprintf(logfile, " |-ECN Flag : %d\n", (unsigned int)tcpheader->ECNEchoFlag);
	fprintf(logfile, " |-Urgent Flag : %d\n", (unsigned int)tcpheader->urgentFlag);
	fprintf(logfile, " |-Acknowledgement Flag : %d\n", (unsigned int)tcpheader->acknowledgementFlag);
	fprintf(logfile, " |-Push Flag : %d\n", (unsigned int)tcpheader->pushFlag);
	fprintf(logfile, " |-Reset Flag : %d\n", (unsigned int)tcpheader->resetFlag);
	fprintf(logfile, " |-Synchronise Flag : %d\n", (unsigned int)tcpheader->synchroniseFlag);
	fprintf(logfile, " |-Finish Flag : %d\n", (unsigned int)tcpheader->finishFlag);
	fprintf(logfile, " |-Window : %d\n", ntohs(tcpheader->window));
	fprintf(logfile, " |-Checksum : %d\n", ntohs(tcpheader->checksum));
	fprintf(logfile, " |-Urgent Pointer : %d\n", tcpheader->urgent_pointer);
	fprintf(logfile, "\n");
	fprintf(logfile, " DATA Dump ");
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "TCP Header\n");
	PrintData(Buffer + iphdrlen, tcpheader->dataOffset * 4);

	fprintf(logfile, "Data Payload\n");
	PrintData(Buffer + iphdrlen + tcpheader->dataOffset * 4
		, (Size - tcpheader->dataOffset * 4 - iphdr->IPHeaderLen * 4));

	fprintf(logfile, "\n###########################################################");
}

void PrintUdpPacket(char *Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4Header *)Buffer;
	iphdrlen = iphdr->IPHeaderLen * 4;

	udpheader = (UDPHeader *)(Buffer + iphdrlen);
	if ((Size - sizeof(UDPHeader) - iphdr->IPHeaderLen * 4) == 0)
		return;
	fprintf(logfile, "\n\n***********************UDP Packet*************************\n");

	PrintIpHeader(Buffer);

	fprintf(logfile, "\nUDP Header\n");
	fprintf(logfile, " |-Source Port : %d\n", ntohs(udpheader->sourcePort));
	fprintf(logfile, " |-Destination Port : %d\n", ntohs(udpheader->destPort));
	fprintf(logfile, " |-UDP Length : %d\n", ntohs(udpheader->UDPLength));
	fprintf(logfile, " |-UDP Checksum : %d\n", ntohs(udpheader->UDPCheckSum));

	fprintf(logfile, "\n");
	fprintf(logfile, "IP Header\n");

	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "UDP Header\n");

	PrintData(Buffer + iphdrlen, sizeof(UDPHeader));

	fprintf(logfile, "Data Payload\n");

	PrintData(Buffer + iphdrlen + sizeof(UDPHeader), (Size - sizeof(UDPHeader) - iphdr->IPHeaderLen * 4));

	fprintf(logfile, "\n###########################################################");
}

void PrintIcmpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4Header *)Buffer;
	iphdrlen = iphdr->IPHeaderLen * 4;

	icmpheader = (ICMPHeader*)(Buffer + iphdrlen);

	if ((Size - sizeof(ICMPHeader) - iphdr->IPHeaderLen * 4) == 0)
		return;

	fprintf(logfile, "\n\n***********************ICMP Packet*************************\n");
	PrintIpHeader(Buffer);

	fprintf(logfile, "\n");

	fprintf(logfile, "ICMP Header\n");
	fprintf(logfile, " |-Type : %d", (unsigned int)(icmpheader->ICMPErrorType));

	if ((unsigned int)(icmpheader->ICMPErrorType) == 11)
	{
		fprintf(logfile, " (TTL Expired)\n");
	}
	else if ((unsigned int)(icmpheader->ICMPErrorType) == 0)
	{
		fprintf(logfile, " (ICMP Echo Reply)\n");
	}

	fprintf(logfile, " |-Code : %d\n", (unsigned int)(icmpheader->typeSubCode));
	fprintf(logfile, " |-Checksum : %d\n", ntohs(icmpheader->checkSum));
	fprintf(logfile, " |-ID : %d\n", ntohs(icmpheader->ID));
	fprintf(logfile, " |-Sequence : %d\n", ntohs(icmpheader->seq));
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "UDP Header\n");
	PrintData(Buffer + iphdrlen, sizeof(ICMPHeader));

	fprintf(logfile, "Data Payload\n");
	PrintData(Buffer + iphdrlen + sizeof(ICMPHeader), (Size - sizeof(ICMPHeader) - iphdr->IPHeaderLen * 4));

	fprintf(logfile, "\n###########################################################");
}

void PrintIGMPpacket(char* Buffer, int Size) {
	unsigned short iphdrlen;

	iphdr = (IPV4Header *)Buffer;
	iphdrlen = iphdr->IPHeaderLen * 4;

	igmpheader = (IGMPHeader*)(Buffer + iphdrlen);

	if ((Size - sizeof(IGMPHeader) - iphdr->IPHeaderLen * 4) == 0)
		return;

	fprintf(logfile, "\n\n***********************IGMP Packet*************************\n");
	PrintIpHeader(Buffer);

	fprintf(logfile, "\n");

	fprintf(logfile, "IGMP Header\n");
	fprintf(logfile, " |-Type : %d", (unsigned int)(igmpheader->IGMPType));
	fprintf(logfile, " |-Code : %d\n", (unsigned int)(igmpheader->typeSubCode));
	fprintf(logfile, " |-Checksum : %d\n", ntohs(igmpheader->checkSum));
	fprintf(logfile, "\n");

	fprintf(logfile, "IP Header\n");
	PrintData(Buffer, iphdrlen);

	fprintf(logfile, "UDP Header\n");
	PrintData(Buffer + iphdrlen, sizeof(IGMPHeader));

	fprintf(logfile, "Data Payload\n");
	PrintData(Buffer + iphdrlen + sizeof(IGMPHeader), (Size - sizeof(IGMPHeader) - iphdr->IPHeaderLen * 4));

	fprintf(logfile, "\n###########################################################");
}


void PrintData(char* data, int Size)
{
	char a, line[17], c;
	int j;

	for (i = 0; i < Size; i++) {
		c = data[i];
		fprintf(logfile, " %.2x", (unsigned char)c);		//16-§ä§Ú §Ù§ß§Ñ§é§Ö§ß§Ú §Õ§Ý§ñ §Ü§Ñ§Ø§Õ§à§Ô§à §ã§Ú§Þ§Ó§à§Ý§Ñ
		a = (c >= 32 && c <= 128) ? (unsigned char)c : '.';		//§Ú §Õ§à§Ò§Ñ§Ó§Ý§Ö§ß§Ú§Ö §ï§ä§à§Ô§à §ã§Ú§Þ§Ó§à§Ý§Ñ §Ó §ã§ä§â§à§Ü§å §Õ§Ñ§ß§ß§í§ç
		line[i % 16] = a;

		if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1)		//§Ö§ã§Ý§Ú §á§à§ã§Ý§Ö§Õ§ß§Ú§Û §ã§Ú§Þ§Ó§à§Ý §ã§ä§â§à§Ü§Ú, §ä§à §Ó§í§Ó§Ö§Õ§Ú§ä§Ö §ã§ä§â§à§Ü§å - 16 §ã§Ú§Þ§Ó§à§Ý§à§Ó §Ó 1 §ã§ä§â§à§Ü§Ö
		{
			line[i % 16 + 1] = '\0';

			fprintf(logfile, "          "); // §Ò§à§Ý§î§ê§à§Û §á§â§à§Ò§Ö§Ý

			for (j = strlen(line); j < 16; j++) { //§£§í§Ó§Ö§Õ§Ú§ä§Ö §Õ§à§á§à§Ý§ß§Ú§ä§Ö§Ý§î§ß§í§Ö §á§â§à§Ò§Ö§Ý§í §Õ§Ý§ñ §á§à§ã§Ý§Ö§Õ§ß§Ú§ç §ã§ä§â§à§Ü, §Õ§Ý§Ú§ß§Ñ §Ü§à§ä§à§â§í§ç §Þ§à§Ø§Ö§ä §Ò§í§ä§î §Þ§Ö§ß§î§ê§Ö 16 §ã§Ú§Þ§Ó§à§Ý§à§Ó
				fprintf(logfile, "   ");
			}

			fprintf(logfile, "%s \n", line);
		}
	}

	fprintf(logfile, "\n");
}