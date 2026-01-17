#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

// network order
uint32_t ip2int(const char *ip_str) {
#if 1
    struct in_addr addr;

    if (inet_pton(AF_INET, ip_str, &addr) == 1) {
        return addr.s_addr;
        //uint32_t ip_num = ntohl(addr.s_addr); // 호스트 바이트 순서로 변환
    } 

    return 0;
#else

    unsigned int bytes[4];
    if (sscanf(ip_str, "%u.%u.%u.%u", &bytes[0], &bytes[1], &bytes[2], &bytes[3]) != 4) {
        return 0;
    }

    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
#endif
}

