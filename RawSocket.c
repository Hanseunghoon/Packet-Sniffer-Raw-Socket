#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define BUF_SIZE 256

#include "pcap.h"
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#pragma comment (lib, "wpcap.lib") 
#pragma comment(lib, "ws2_32.lib")
struct hostent *hptr;

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)   // WinSock 

void StartSniffing(SOCKET Sock);
void ProcessPacket(char*, int);
void PrintIpHeader(char*);
void PrintTcpPacket(char*, int);
void PrintUdpPacket(char*, int);
void PrintData(unsigned char*, int);
void PrintIcmpPacket(char*, int);

// IP ��� ����ü
typedef struct ip_hdr
{
	unsigned char ip_header_len : 4;      // ��� ����
	unsigned char ip_version : 4;         // ����
	unsigned char ip_tos;               // ���� Ÿ�� type of service
	unsigned short ip_total_length;         // ��ü ����
	unsigned short ip_id;               // ID
	unsigned char ip_frag_offset : 5;      // fragment offset
	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;
	unsigned char ip_frag_offset1;
	unsigned char ip_ttl;               // TTL(Time To Live)
	unsigned char ip_protocol;            // IP protocol
	unsigned short ip_checksum;            // IP CheckSum
	unsigned int ip_srcaddr;            // Source IP Address
	unsigned int ip_destaddr;            // Destination IP Address
} IPV4_HDR;

// TCP ��� ����ü
typedef struct tcp_header
{
	unsigned short source_port;         // Source Port No.
	unsigned short dest_port;         // Destination Port No.
	unsigned int sequence;            // Seq No.
	unsigned int acknowledge;         // Ack No.

	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window_size;         // Window Size
	unsigned short checksum;         // CheckSum
	unsigned short urgent_pointer;
} TCP_HDR;

// UDP ��� ����ü
typedef struct udp_header
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned short udp_length;         // Datagram length
	unsigned short udp_checksum;
} UDP_HDR;

// ICMP ��� ����ü
typedef struct icmp_hdr
{
	byte type; // ICMP Error type
	byte code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
}ICMP_HDR;

int icmp = 0, tcp = 0, udp = 0, total = 0, i, j;  // �� ���� �ʱ�ȭ �� ����

struct sockaddr_in source, dest;      // �����, ������ ����

// IP, TCP, UCP, ICMP �� ����� ���� ����ü ����
IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
UDP_HDR *udpheader;
ICMP_HDR *icmpheader;

int main(int argc, char* argv[])
{
	SOCKET sniffer;
	struct in_addr addr;
	int in;

	char hostname[100];
	struct hostent *local;
	WSADATA wsa;

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);
	printf("\n -----------------------------\n");
	printf(" l�� Made By Han seunghoon ��l\n");
	printf(" -----------------------------\n\n");

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
	printf(" Initializing Windows socket...  ");

	// ���� ���� �˻�
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);
		printf("Windows Socket Error!\n"); // ���� ���� ���� ��
		return 1;
	}

	printf("Initialization completed!\n");

	// RAW Socket ����
	printf(" Creating RAW socket...  ");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

	if (sniffer == INVALID_SOCKET) {
		printf("Failed to create RAW socket\n"); // ���� ���� ���� �� (������ ���� �ʼ�)
		return 1;
	}

	printf("RAW Socket Creation Complete!");

	// ȣ��Ʈ�� �̸��� hostname�� ����
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
		printf("Error : %d", WSAGetLastError());
		return 1;
	}

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);
	printf("\n <Host : %s>\n", hostname);

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9);
	local = gethostbyname(hostname); // ȣ��Ʈ �̸��� IP�ּҷ� ��ȯ (Domain -> IP)
	printf("\n Available Network Devices : \n");

	if (local == NULL) {
		printf("Error : %d.\n", WSAGetLastError());
		return 1;
	}

	for (i = 0; local->h_addr_list[i] != 0; ++i) {
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		// hostent ����ü ���� h_addr_list ����� ���ĵ� IP address�� in_addr����ü(addr)������ �����Ų��.
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		printf(" \tDevice No. : %d : %s\n", i, inet_ntoa(addr));
		// IP�ּ� 10������ ��ȯ���� ���
	}
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
	printf(" What should we proceed with? (Enter to the No.) : ");
	scanf("%d", &in);

	printf("error\n");

	memset(&dest, 0, sizeof(dest)); // sockaddr_in����ü ���� dest����� 0���� �ʱ�ȭ��Ų��.
	memcpy(&dest.sin_addr.s_addr, local->h_addr_list[in], sizeof(dest.sin_addr.s_addr));

	/* sockaddr_in ����ü(dest)�� ���(IP�ּҸ� �����ϴ� ���)�� �����Ѵ�. h_addr_list[������ ��Ʈ��ũ �������̽�] */
	dest.sin_family = AF_INET;

	// IPv4
	dest.sin_port = 0;

	// Port No �ʱ�ȭ (���� �ý��� (��Ʈ 0)�� ���� ���ε� ��..)
	printf("\n Socket binding to local system...  ");

	if (bind(sniffer, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR) {
		printf("bind() error(%s).\n", inet_ntoa(addr));
		return 1;
	}

	// bind()�� ȣ�� �ϸ鼭 sniffer(�ο� ����)�� IP �ּҿ� ��Ʈ ����, IPv4�� �� �Ҵ��Ѵ�.
	// �ش� ������(dest.sin_addr.s_addr)�� ���� ��Ŷ�� �������Ѵ�.

	printf("Bind Success! \n");

	j = 1;
	printf("\n Adjusting socket...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD)&in, 0, 0) == SOCKET_ERROR) {
		printf("WSAIoctl() error\n");
		return 1;
	}

	// ���� ���� ������ �����ϴ� �Լ��̴�.(�ο� ������ �������� �ʱ�ȭ)
	printf(" Socket Adjustment Complete!\n");

	printf("\n Start!\n");
	printf(" Collecting packets...\n");

	StartSniffing(sniffer);

	closesocket(sniffer);
	WSACleanup();          // ������ �ʱ�ȭ

	return 0;
}

void StartSniffing(SOCKET sniffer)
{
	char *Buffer = (char *)malloc(65536); // ���� �����Ҵ� iphdr����ü�� ip_id�� ���� 0~65536
	int byte;

	if (Buffer == NULL) {
		printf("malloc() error\n");
		return;
	}

	do {
		byte = recvfrom(sniffer, Buffer, 65536, 0, 0, 0);

		if (byte > 0)
			ProcessPacket(Buffer, byte);
		else
			printf("recvfrom() error\n");

	} while (byte > 0);

	free(Buffer);
}

void ProcessPacket(char* Buffer, int Size) // sniffer ������ ��Ŷ�� �޾Ҵٸ�
{
	iphdr = (IPV4_HDR *)Buffer; // iphdr���� ip_protocol(���� ��������)�� ���� ���� ���� ���� ����(TCP, UDP, ICMP, IGMP ��)
	++total;

	switch (iphdr->ip_protocol)
	{
	case 6:  // TCP Protocol
		++tcp;
		printf("\n< TCP : %d || Total : %d >\r", tcp, total);
		PrintTcpPacket(Buffer, Size); // TCP�� ��쿡�� ���޹��� ��Ŷ�� ��Ŷ�� ����� �� PrintTcpPacket�Լ��� �����ϸ� ���ڷ� �����Ѵ�.
		break;
	case 17: // UDP Protocol
		++udp;
		printf("\n< UDP : %d || Total : %d >\r", udp, total);
		PrintUdpPacket(Buffer, Size);
		break;
	case 1: // ICMP Protocol
		++icmp;
		printf("\n< ICMP : %d || Total : %d >\r", icmp, total);
		PrintIcmpPacket(Buffer, Size);
		break;
	}
}

void PrintIpHeader(char* Buffer)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;         // ip_header_len���� ����� 4�� ���ؼ� ���� ��� ���̸� ���Ѵ�.(32bit)

	memset(&source, 0, sizeof(source));            // sockaddr_in ����ü(source)�� ��� ��θ� 0���� �ʱ�ȭ �Ѵ�. sockaddr_in ����ü ��� �غ�
	source.sin_addr.s_addr = iphdr->ip_srcaddr;      // iphdr(IPv4)�� ��� ip_scraddr(����� IP�� ��Ÿ�������� ���)�� ���� ����

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;      // ������ ip�ּҸ� ����

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);
	printf("\n*************************************************************");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);

	printf("\n");
	printf(" IP Header--------------------------------------------------\n");
	printf(" |  Source IP : %s \n", inet_ntoa(source.sin_addr));
	printf(" |  Destination IP : %s \n", inet_ntoa(dest.sin_addr));
	printf(" |  IP Length : %d Bytes(Size of Packet) \n", ntohs(iphdr->ip_total_length)); // ��� + �������� �� ����
	printf(" |  IP inherence Num : %d \n", ntohs(iphdr->ip_id));
	printf(" |  TTL : %d \n", (unsigned int)iphdr->ip_ttl);
	printf(" |  CheckSum : %d \n", ntohs(iphdr->ip_checksum));
	printf(" -----------------------------------------------------------\n");
}

void PrintTcpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	tcpheader = (TCP_HDR*)(Buffer + iphdrlen);         // TCP_HDR ����ü�� ������ tcpheader

	PrintIpHeader(Buffer);                        // IP���������� ������ log���Ͽ� ���� �Լ��� �����ϸ鼭 ���� ���������� ������ �����Ѵ�.

	printf("\n\n-------------------------TCP Packet----------------------\n");
	printf(" TCP Header----------------------------------------------\n");
	printf(" | Source Port No. : %u \n", ntohs(tcpheader->source_port));
	printf(" | Destination Port No. : %u \n", ntohs(tcpheader->dest_port));
	printf(" | SEQ No. : %u \n", ntohl(tcpheader->sequence));

	if (tcpheader->acknowledge == 0)
		printf(" | ACK No. : %u \n", ntohl(tcpheader->acknowledge));
	else
		printf(" | ACK No. : %u \n", ntohl(tcpheader->acknowledge));

	printf(" | TCP Length : %u \n", (unsigned int)tcpheader->data_offset * 4);
	printf(" | TCP CheckSum : %u \n", ntohl(tcpheader->checksum));
	printf(" TCP Flags----------------------------------------------------\n");
	printf(" | SYN : %d \n", (unsigned int)tcpheader->syn);
	printf(" | ACK : %d \n", (unsigned int)tcpheader->ack);
	printf(" | FIN : %d \n", (unsigned int)tcpheader->fin);
	printf(" --------------------------------------------------------\n");

	if ((unsigned int)tcpheader->ack == 0 && (unsigned int)tcpheader->fin == 1) {
		printf("������#################\n\n");
		exit(1);
	}

	printf("\n");

	if (ntohs(tcpheader->dest_port) == 80) {
		printf("HTTP Data Payload\n");
		PrintData((unsigned char*)Buffer + iphdrlen + tcpheader->data_offset * 4, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));
	}
	/*else if (ntohs(tcpheader->dest_port) == 443) {
	   printf("HTTPS Data Payload\n");
	   PrintData((unsigned char*)Buffer + iphdrlen + tcpheader->data_offset * 4, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));
	}*/
	else if (ntohs(tcpheader->dest_port) == 53) {
		printf("DNS Data Payload\n");
		PrintData((unsigned char*)Buffer + iphdrlen + tcpheader->data_offset * 4, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));
	}
	else if (ntohs(tcpheader->dest_port) == 25) {
		printf("SMTP Data Payload\n");
		PrintData((unsigned char*)Buffer + iphdrlen + tcpheader->data_offset * 4, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));
	}
	else if (ntohs(tcpheader->dest_port) == 587) {
		printf("SMTP Data Payload\n");
		PrintData((unsigned char*)Buffer + iphdrlen + tcpheader->data_offset * 4, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));
	}
	else if (ntohs(tcpheader->dest_port) == 110) {
		printf("POP3 Data Payload\n");
		PrintData((unsigned char*)Buffer + iphdrlen + tcpheader->data_offset * 4, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));
	}
	else if (ntohs(tcpheader->dest_port) == 143) {
		printf("IMAP Data Payload\n");
		PrintData((unsigned char*)Buffer + iphdrlen + tcpheader->data_offset * 4, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));
	}
	else if (ntohs(tcpheader->dest_port) == 465) {
		printf("SMTP(SSL Security) Data Payload\n");
		PrintData((unsigned char*)Buffer + iphdrlen + tcpheader->data_offset * 4, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));
	}
	else if (ntohs(tcpheader->dest_port) == 993) {
		printf("IMAP(SSL Security) Data Payload\n");
		PrintData((unsigned char*)Buffer + iphdrlen + tcpheader->data_offset * 4, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));
	}
	else if (ntohs(tcpheader->dest_port) == 995) {
		printf("POP3(SSL Security) Data Payload\n");
		PrintData((unsigned char*)Buffer + iphdrlen + tcpheader->data_offset * 4, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));
	}

	printf("\n");
}

void PrintUdpPacket(char* Buffer, int Size) {
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	udpheader = (UDP_HDR*)(Buffer + iphdrlen);

	PrintIpHeader(Buffer);               // IP ���������� ������ log���Ͽ� ���� �Լ��� �����ϸ鼭 ���� ���������� ������ �����Ѵ�.

	printf("\n\n---------------------------UDP Packet---------------------------\n");
	printf(" UDP Header-----------------------------------------------\n");
	printf(" | Sourcer Port No. : %u \n", ntohs(udpheader->source_port));
	printf(" | Destination Port No. : %u \n", ntohs(udpheader->dest_port));
	printf(" | UDP Length : %d \n", ntohs(udpheader->udp_length));
	printf(" | UDP CheckSum : %d \n", ntohs(udpheader->udp_checksum));
	printf(" --------------------------------------------------------\n");
	printf("\n");

	if (ntohs(udpheader->dest_port) == 80) {
		printf("HTTP Data Payload\n");
		PrintData((unsigned char*)Buffer + iphdrlen + sizeof(UDP_HDR), (Size - sizeof(UDP_HDR) - iphdr->ip_header_len * 4));
	}
	/*else if (ntohs(tcpheader->dest_port) == 443) {
	   printf("HTTPS Data Payload\n");
	   PrintData((unsigned char*)Buffer + iphdrlen + sizeof(UDP_HDR), (Size - sizeof(UDP_HDR) - iphdr->ip_header_len * 4));
	}*/
	else if (ntohs(udpheader->dest_port) == 53) {
		printf("DNS Data Payload\n");
		PrintData((unsigned char*)Buffer + iphdrlen + sizeof(UDP_HDR), (Size - sizeof(UDP_HDR) - iphdr->ip_header_len * 4));
	}

	printf("\n");
}

void PrintIcmpPacket(char* Buffer, int Size) {
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;

	icmpheader = (ICMP_HDR*)(Buffer + iphdrlen);

	PrintIpHeader(Buffer);         // IP���������� ������ log���Ͽ� ���� �Լ��� �����ϸ鼭 ���� ���������� ������ �����Ѵ�.

	printf("\n\n---------------------------ICMP Packet---------------------------\n");
	printf("ICMP Header-----------------------------------------------\n");
	printf(" | ICMP Code No. : %d \n", (unsigned int)(icmpheader->type));
	printf(" | ICMP Code No. : %d \n", (unsigned int)(icmpheader->code));
	printf(" | ICMP Checksum : %d \n", ntohs(icmpheader->checksum));
	printf(" | ICMP ID : %d \n", ntohs(icmpheader->id));
	printf(" | ICMP Sequence : %d \n", ntohs(icmpheader->seq));
	printf(" --------------------------------------------------------\n");
	printf("\n");

	printf("ICMP Data Payload\n");
	PrintData((unsigned char*)Buffer + iphdrlen + sizeof(ICMP_HDR), (Size - sizeof(ICMP_HDR) - iphdr->ip_header_len * 4));

	printf("\n");
}

void PrintData(unsigned char* data, int size)
{
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0) {
			printf("         ");

			for (j = i - 16; j < i; j++) {
				if (data[j] >= 32 && data[j] <= 128)
					printf("%c", (unsigned char)data[j]);      // ����, ���ڳ� ������ �װ� ���
				else
					printf(".");                        // �ƴϸ� .���
			}
			printf("\n");
		}

		if (i % 16 == 0)
			printf("   ");

		printf(" %02X", (unsigned int)data[i]);

		if (i == size - 1) {                           // ������ ����̸�
			for (j = 0; j < 15 - i % 16; j++)
				printf("   ");                           // �߰� �� �������� ����

			printf("         ");

			for (j = i - i % 16; j <= i; j++) {
				if (data[j] >= 32 && data[j] <= 128)
					printf("%c", (unsigned char)data[j]);
				else
					printf(".");
			}
			printf("\n");
		}
	}
}