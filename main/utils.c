#include <string.h>
#include "esp_system.h"

int mac_compare(unsigned char* addr1, unsigned char* addr2){
    return memcmp(addr1, addr2, 6U) == 0;
}

bool mac_compare_no_memcmp(unsigned char* addr1, unsigned char* addr2){
    for(unsigned char i = 0; i < 6; i++)
    {
        if(addr1[i] != addr2[i]){
            return false;
        }
    }
    return true;
}

/**
 * @brief Debug functions to print MAC address from given buffer to serial
 * 
 * @param a mac address buffer
 */
void printf_mac_address(const uint8_t *a){
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
    a[0], a[1], a[2], a[3], a[4], a[5]);
    printf("\n");
}