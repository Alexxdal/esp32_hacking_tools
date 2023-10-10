#include <string.h>

int mac_compare(unsigned char* addr1, unsigned char* addr2){
    return memcmp(addr1, addr2, 6U) == 0;
}