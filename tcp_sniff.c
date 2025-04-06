#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

/* Ethernet 헤더 구조체 */
struct ethheader {
  u_char  ether_dhost[6]; /* 목적지 MAC 주소 */
  u_char  ether_shost[6]; /* 출발지 MAC 주소 */
  u_short ether_type;     /* 프로토콜 타입 (IP, ARP, RARP 등) */
};

/* IP 헤더 구조체 */
struct ipheader {
  unsigned char      iph_ihl:4, // IP 헤더 길이
                     iph_ver:4; // IP 버전
  unsigned char      iph_tos;   // 서비스 타입
  unsigned short int iph_len;   // IP 패킷 길이 (데이터 + 헤더)
  unsigned short int iph_ident; // 식별자
  unsigned short int iph_flag:3, // 플래그
                     iph_offset:13; // 플래그 오프셋
  unsigned char      iph_ttl;     // 생존 시간(TTL)
  unsigned char      iph_protocol; // 프로토콜 타입
  unsigned short int iph_chksum;  // IP 데이터그램 체크섬
  struct  in_addr    iph_sourceip; // 출발지 IP 주소
  struct  in_addr    iph_destip;   // 목적지 IP 주소
};

/* TCP 헤더 구조체 */
struct tcpheader {
    u_short tcp_sport;               /* 출발지 포트 */
    u_short tcp_dport;               /* 목적지 포트 */
    u_int   tcp_seq;                 /* 시퀀스 번호 */
    u_int   tcp_ack;                 /* 확인 응답 번호 */
    u_char  tcp_offx2;               /* 데이터 오프셋 */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;               /* TCP 플래그 */
#define TH_FIN  0x01    /* 연결 종료 */
#define TH_SYN  0x02    /* 연결 시작 */
#define TH_RST  0x04    /* 연결 재설정 */
#define TH_PUSH 0x08    /* 데이터 밀어넣기 */
#define TH_ACK  0x10    /* 확인 응답 */
#define TH_URG  0x20    /* 긴급 포인터 유효 */
#define TH_ECE  0x40    /* ECN-Echo */
#define TH_CWR  0x80    /* 혼잡 윈도우 감소 */
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* 윈도우 크기 */
    u_short tcp_sum;                 /* 체크섬 */
    u_short tcp_urp;                 /* 긴급 포인터 */
};

// MAC 주소를 읽기 쉬운 형식으로 출력하는 함수
void print_mac_address(const u_char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// 패킷 페이로드를 출력하는 함수
void print_payload(const u_char *payload, int len) {
    int max_display = 64; // 최대 표시 바이트 수
    int display_len = len < max_display ? len : max_display;
    
    if (display_len <= 0) {
        printf("   [페이로드 데이터 없음]\n");
        return;
    }
    
    printf("   페이로드 (%d 바이트, 처음 %d 바이트 표시):\n", len, display_len);
    printf("   ");
    
    // 16진수 및 ASCII 표현 출력
    for (int i = 0; i < display_len; i++) {
        // 출력 가능한 문자는 그대로, 아닌 경우 점(.) 출력
        if (isprint(payload[i]))
            printf("%c", payload[i]);
        else
            printf(".");
    }
    
    if (len > max_display)
        printf("... [추가 %d 바이트]", len - max_display);
    
    printf("\n");
}

// 패킷 캡처 콜백 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
    // 이더넷 헤더 구조체로 변환
    struct ethheader *eth = (struct ethheader *)packet;
    
    // IP 패킷인지 확인 (0x0800은 IP 타입)
    if (ntohs(eth->ether_type) == 0x0800) { 
        // IP 헤더의 위치 계산
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        
        // TCP 패킷만 처리
        if (ip->iph_protocol == IPPROTO_TCP) {
            // IP 헤더 길이 계산 (4바이트 단위)
            int ip_header_len = (ip->iph_ihl & 0x0F) * 4;
            
            // TCP 헤더 위치 계산
            struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);
            
            // TCP 헤더 길이 계산 (4바이트 단위)
            int tcp_header_len = TH_OFF(tcp) * 4;
            
            // 페이로드 오프셋과 길이 계산
            int payload_offset = sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_length = ntohs(ip->iph_len) - ip_header_len - tcp_header_len;
            
            // 페이로드 길이가 음수면 0으로 설정
            if (payload_length < 0) payload_length = 0;
            
            // 페이로드 데이터 위치
            const u_char *payload = packet + payload_offset;
            
            printf("\n===== 새로운 TCP 패킷 =====\n");
            
            // 이더넷 헤더 정보 출력
            printf("이더넷 헤더:\n");
            printf("   목적지 MAC: ");
            print_mac_address(eth->ether_dhost);
            printf("\n   출발지 MAC: ");
            print_mac_address(eth->ether_shost);
            printf("\n");
            
            // IP 헤더 정보 출력
            printf("IP 헤더:\n");
            printf("   출발지 IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   목적지 IP: %s\n", inet_ntoa(ip->iph_destip));
            printf("   IP 헤더 길이: %d 바이트\n", ip_header_len);
            
            // TCP 헤더 정보 출력
            printf("TCP 헤더:\n");
            printf("   출발지 포트: %d\n", ntohs(tcp->tcp_sport));
            printf("   목적지 포트: %d\n", ntohs(tcp->tcp_dport));
            printf("   TCP 헤더 길이: %d 바이트\n", tcp_header_len);
            
            // 플래그 정보 출력
            printf("   플래그: ");
            if (tcp->tcp_flags & TH_FIN) printf("FIN ");
            if (tcp->tcp_flags & TH_SYN) printf("SYN ");
            if (tcp->tcp_flags & TH_RST) printf("RST ");
            if (tcp->tcp_flags & TH_PUSH) printf("PUSH ");
            if (tcp->tcp_flags & TH_ACK) printf("ACK ");
            if (tcp->tcp_flags & TH_URG) printf("URG ");
            printf("\n");
            
            // 페이로드 데이터 출력
            print_payload(payload, payload_length);
        }
    }
}

int main()
{
    pcap_t *handle;  // PCAP 핸들
    char errbuf[PCAP_ERRBUF_SIZE];  // 에러 버퍼
    struct bpf_program fp;  // 필터 프로그램
    char filter_exp[] = "tcp";  // TCP 패킷만 캡처하는 필터
    bpf_u_int32 net;  // 네트워크 주소
    bpf_u_int32 mask;  // 네트워크 마스크
    
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char *dev = NULL;

    // 모든 네트워크 장치 가져오기
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "네트워크 장치를 찾을 수 없습니다: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    // 첫 번째 장치 선택
    device = alldevs;
    if (device != NULL) {
        dev = device->name;
    } else {
        fprintf(stderr, "사용 가능한 네트워크 장치가 없습니다.\n");
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    printf("장치: %s\n", dev);

    // 네트워크 주소와 마스크 가져오기
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "장치 %s의 넷마스크를 가져올 수 없습니다: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // 네트워크 장치에서 라이브 PCAP 세션 열기
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "장치 %s를 열 수 없습니다: %s\n", dev, errbuf);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    // 장치 목록 해제
    pcap_freealldevs(alldevs);
    
    // 필터 컴파일 및 적용
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "필터 %s를 분석할 수 없습니다: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "필터 %s를 설치할 수 없습니다: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }
    
    printf("패킷 캡처 시작 (TCP 전용)...\n");
    
    // 패킷 캡처 시작
    pcap_loop(handle, -1, got_packet, NULL);
    
    // 정리
    pcap_freecode(&fp);
    pcap_close(handle);
    
    return 0;
}