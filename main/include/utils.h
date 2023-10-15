#ifndef UTILS_H
#define UTILS_H

/**
 * @brief Compare two mac address
 * 
 * @param addr1 First address to compare
 * @param addr2 Second address to compare
 */
int mac_compare(unsigned char* addr1, unsigned char* addr2);

/**
 * @brief Compare two mac address
 * 
 * @param addr1 First address to compare
 * @param addr2 Second address to compare
 */
bool mac_compare_no_memcmp(unsigned char* addr1, unsigned char* addr2);

/**
 * @brief Convert mac address to string
 * 
 * @param a mac address bytes
 * @param output char buffer output
 */
void mac2string(const uint8_t *a, char *output);

#endif