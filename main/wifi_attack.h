#include <libwifi.h>

#define MAX_SCAN_RESULTS 24
#define MAX_STATION 10

typedef struct __attribute__((packed)) {
    unsigned char ssid[64];
    unsigned char bssid[6];
    uint8_t channel;
    int8_t signal;
    bool wps;
    char encryption[LIBWIFI_SECURITY_BUF_LEN];
    char group_chipers[LIBWIFI_SECURITY_BUF_LEN];
    char pairwise_chipers[LIBWIFI_SECURITY_BUF_LEN];
    char auth_key_suites[LIBWIFI_SECURITY_BUF_LEN];
} beacon_data_t;

typedef struct __attribute__((packed)){
    unsigned char bssid[6];
    uint32_t frames;
    int8_t signal;
} station_t;


/*
* Compare two MAC address
*/
int isEqual(unsigned char* addr1, unsigned char* addr2);

/*
* Init wifi interface
*/
void wifi_attack_init(void);

/*
* Set sniffing filter
*/
void set_filter(unsigned char* mac);

/*
* Set wifi channel
*/
void set_channel(uint8_t channel);

/*
* Set filter end enable it
*/
void set_filter_enable(unsigned char* mac, bool enable);

/*
* Send deauthentication packet
*/
uint8_t SendDeauth(unsigned char* dest, unsigned char* source, int reasonCode);


/*int passive_scan_start()
{
    bzero(scan_results, sizeof(scan_results));
    current_scan_result = 0;
    passive_scan = true;
    for(int channel = 1; channel < 14; channel++){
        set_channel(channel);
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
    return current_scan_result;
}


int active_scan_start()
{
    bzero(scan_results, sizeof(scan_results));
    current_scan_result = 0;
    active_scan = true;
    for(int channel = 1; channel < 14; channel++){
        set_channel(channel);
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
    return current_scan_result;
}


void set_monitor(unsigned char* bssid, uint8_t channel){
    set_filter(bssid);
    set_channel(channel);
    monitor = true;
}*/
