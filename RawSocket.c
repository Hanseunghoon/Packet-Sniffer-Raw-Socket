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

// IP 헤더 구조체
typedef struct ip_hdr
{
	unsigned char ip_header_len : 4;      // 헤더 길이
	unsigned char ip_version : 4;         // 버전
	unsigned char ip_tos;               // 서비스 타입 type of service
	unsigned short ip_total_length;         // 전체 길이
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

// TCP 헤더 구조체
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

// UDP 헤더 구조체
typedef struct udp_header
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned short udp_length;         // Datagram length
	unsigned short udp_checksum;
} UDP_HDR;

// ICMP 헤더 구조체
typedef struct icmp_hdr
{
	byte type; // ICMP Error type
	byte code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
}ICMP_HDR;

int icmp = 0, tcp = 0, udp = 0, total = 0, i, j;  // 각 변수 초기화 및 선언

struct sockaddr_in source, dest;      // 출발지, 목적지 설정

// IP, TCP, UCP, ICMP 각 헤더에 대한 구조체 선언
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
	printf(" l☆ Made By Han seunghoon ☆l\n");
	printf(" -----------------------------\n\n");

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
	printf(" Initializing Windows socket...  ");

	// 소켓 버전 검사
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);
		printf("Windows Socket Error!\n"); // 소켓 버전 에러 시
		return 1;
	}

	printf("Initialization completed!\n");

	// RAW Socket 생성
	printf(" Creating RAW socket...  ");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

	if (sniffer == INVALID_SOCKET) {
		printf("Failed to create RAW socket\n"); // 소켓 생성 실패 시 (관리자 권한 필수)
		return 1;
	}

	printf("RAW Socket Creation Complete!");

	// 호스트의 이름을 hostname에 저장
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR) {
		printf("Error : %d", WSAGetLastError());
		return 1;
	}

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);
	printf("\n <Host : %s>\n", hostname);

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9);
	local = gethostbyname(hostname); // 호스트 이름을 IP주소로 변환 (Domain -> IP)
	printf("\n Available Network Devices : \n");

	if (local == NULL) {
		printf("Error : %d.\n", WSAGetLastError());
		return 1;
	}

	for (i = 0; local->h_addr_list[i] != 0; ++i) {
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		// hostent 구조체 안의 h_addr_list 멤버에 정렬된 IP address를 in_addr구조체(addr)안으로 복사시킨다.
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		printf(" \tDevice No. : %d : %s\n", i, inet_ntoa(addr));
		// IP주소 10진수로 변환시켜 출력
	}
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);
	printf(" What should we proceed with? (Enter to the No.) : ");
	scanf("%d", &in);

	printf("error\n");

	memset(&dest, 0, sizeof(dest)); // sockaddr_in구조체 안의 dest멤버를 0으로 초기화시킨다.
	memcpy(&dest.sin_addr.s_addr, local->h_addr_list[in], sizeof(dest.sin_addr.s_addr));

	/* sockaddr_in 구조체(dest)의 멤버(IP주소를 저장하는 멤버)에 복사한다. h_addr_list[로컬의 네트워크 인터페이스] */
	dest.sin_family = AF_INET;

	// IPv4
	dest.sin_port = 0;

	// Port No 초기화 (로컬 시스템 (포트 0)에 소켓 바인딩 중..)
	printf("\n Socket binding to local system...  ");

	if (bind(sniffer, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR) {
		printf("bind() error(%s).\n", inet_ntoa(addr));
		return 1;
	}

	// bind()를 호출 하면서 sniffer(로우 소켓)에 IP 주소와 포트 정보, IPv4등 을 할당한다.
	// 해당 목적지(dest.sin_addr.s_addr)로 가는 패킷을 스니핑한다.

	printf("Bind Success! \n");

	j = 1;
	printf("\n Adjusting socket...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD)&in, 0, 0) == SOCKET_ERROR) {
		printf("WSAIoctl() error\n");
		return 1;
	}

	// 소켓 제어 정보를 정의하는 함수이다.(로우 소켓의 제어정보 초기화)
	printf(" Socket Adjustment Complete!\n");

	printf("\n Start!\n");
	printf(" Collecting packets...\n");

	StartSniffing(sniffer);

	closesocket(sniffer);
	WSACleanup();          // 윈소켓 초기화

	return 0;
}

void StartSniffing(SOCKET sniffer)
{
	char *Buffer = (char *)malloc(65536); // 버퍼 동적할당 iphdr구조체의 ip_id의 값은 0~65536
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

void ProcessPacket(char* Buffer, int Size) // sniffer 소켓이 패킷을 받았다면
{
	iphdr = (IPV4_HDR *)Buffer; // iphdr안의 ip_protocol(상위 프로토콜)의 값에 따라 여러 경우로 나뉨(TCP, UDP, ICMP, IGMP 등)
	++total;

	switch (iphdr->ip_protocol)
	{
	case 6:  // TCP Protocol
		++tcp;
		printf("\n< TCP : %d || Total : %d >\r", tcp, total);
		PrintTcpPacket(Buffer, Size); // TCP의 경우에는 전달받은 패킷과 패킷의 사이즈를 또 PrintTcpPacket함수를 선언하며 인자로 전달한다.
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
	iphdrlen = iphdr->ip_header_len * 4;         // ip_header_len안의 값들과 4를 곱해서 원래 헤더 길이를 구한다.(32bit)

	memset(&source, 0, sizeof(source));            // sockaddr_in 구조체(source)의 멤버 모두를 0으로 초기화 한다. sockaddr_in 구조체 사용 준비
	source.sin_addr.s_addr = iphdr->ip_srcaddr;      // iphdr(IPv4)의 멤버 ip_scraddr(출발지 IP를 나타내기위한 멤버)의 값을 대입

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;      // 목적지 ip주소를 대입

	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 4);
	printf("\n*************************************************************");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14);

	printf("\n");
	printf(" IP Header--------------------------------------------------\n");
	printf(" |  Source IP : %s \n", inet_ntoa(source.sin_addr));
	printf(" |  Destination IP : %s \n", inet_ntoa(dest.sin_addr));
	printf(" |  IP Length : %d Bytes(Size of Packet) \n", ntohs(iphdr->ip_total_length)); // 헤더 + 데이터의 총 길이
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

	tcpheader = (TCP_HDR*)(Buffer + iphdrlen);         // TCP_HDR 구조체용 포인터 tcpheader

	PrintIpHeader(Buffer);                        // IP프로토콜의 정보를 log파일에 적는 함수를 선언하면서 하위 프로토콜의 정보를 정의한다.

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
		printf("찍혔다#################\n\n");
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

	PrintIpHeader(Buffer);               // IP 프로토콜의 정보를 log파일에 적는 함수를 선언하면서 하위 프로토콜의 정보를 정의한다.

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

	PrintIpHeader(Buffer);         // IP프로토콜의 정보를 log파일에 적는 함수를 선언하면서 하위 프로토콜의 정보를 정의한다.

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
					printf("%c", (unsigned char)data[j]);      // 만약, 숫자나 영어라면 그걸 출력
				else
					printf(".");                        // 아니면 .출력
			}
			printf("\n");
		}

		if (i % 16 == 0)
			printf("   ");

		printf(" %02X", (unsigned int)data[i]);

		if (i == size - 1) {                           // 마지막 출력이면
			for (j = 0; j < 15 - i % 16; j++)
				printf("   ");                           // 추가 빈 공간으로 분할

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