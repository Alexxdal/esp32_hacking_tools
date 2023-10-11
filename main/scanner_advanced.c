#include <string.h>
#include <libwifi.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "ap_scanner.h"
#include "scanner_advanced.h"
#include "sniffer.h"
#include "utils.h"
#include "wifi_controller.h"

static const char *TAG = "SCANNER_ADVANCED";
static uint8_t ap = 0;
static uint8_t channel = 1;
static bool scan_done = false;
static wifictl_ap_records_t ap_record = { 0 };

/*
* Timers
*/
esp_timer_handle_t scan_timeout_handle;
esp_timer_handle_t channel_hop_handle;

static void beacon_frame_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    //ESP_LOGI(TAG, "Got beacon frame");
    struct libwifi_frame frame = { 0 };
    wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *) event_data;
    unsigned long data_len = ppkt->rx_ctrl.sig_len;
    int ret = libwifi_get_wifi_frame(&frame, (const unsigned char*)ppkt->payload, data_len, 0);
    if (ret < 0) {
        goto free_mem;
    }

    struct libwifi_bss bss = { 0 };
    ret = libwifi_parse_beacon(&bss, &frame);
    if (ret < 0) {
        //libwifi_free_bss(&bss);
        goto free_mem;
    }
    //Check if bssid is already present in scan results array
    for(int i = 0; i < ap; i++){
        if( mac_compare((unsigned char *)&ap_record.records[i].bssid, (unsigned char *)&bss.bssid)){
            libwifi_free_bss(&bss);
            goto free_mem;
        }
    }

    if( ap < CONFIG_SCAN_MAX_AP ) {
        //Ok questo beacon non è presente nei risultati
        memcpy(&ap_record.records[ap].bssid, &bss.bssid, sizeof(bss.bssid));
        strcpy((char *)&ap_record.records[ap].ssid, bss.hidden ? "(hidden)" : (char *)&bss.ssid);
        ap_record.records[ap].primary = bss.channel;
        ap_record.records[ap].rssi = ppkt->rx_ctrl.rssi;
        ap_record.records[ap].wps = bss.wps;
        ap++;
        //libwifi_get_security_type(&bss, ap_record.records[ap].encryption);
        //libwifi_get_group_ciphers(&bss, ap_record[ap].group_chipers);
        //libwifi_get_pairwise_ciphers(&bss, ap_record[ap].pairwise_chipers);
        //libwifi_get_auth_key_suites(&bss, ap_record[ap].auth_key_suites);
    }
    libwifi_free_bss(&bss);
free_mem:
    libwifi_free_wifi_frame(&frame);
}

static void scan_done_timeout(void* arg)
{
    ESP_ERROR_CHECK(esp_event_handler_unregister(ESP_EVENT_ANY_BASE, ESP_EVENT_ANY_ID, &beacon_frame_handler));
    ESP_ERROR_CHECK(esp_timer_stop(channel_hop_handle));
    wifictl_sniffer_stop();
    ap_record.count = ap;
    scan_done = true;
    ESP_LOGI(TAG, "Scan done found %d ap.", ap);
    for( int i = 0; i < ap; i++ )
    {
        printf("BSSID: %02x:%02x:%02x:%02x:%02x:%02x\t", ap_record.records[i].bssid[0], ap_record.records[i].bssid[1], ap_record.records[i].bssid[2], ap_record.records[i].bssid[3], ap_record.records[i].bssid[4], ap_record.records[i].bssid[5]);
        printf("%s\t\t", ap_record.records[i].ssid);
        printf("CHANNEL: %d\t\t", ap_record.records[i].primary);
        printf("RSSSI: %d\n", ap_record.records[i].rssi);
    }
}

static void channel_hop_timer(void* arg)
{
    if( channel == 13 ){
        channel = 1;
    }else{
        channel++;
    }
    wifictl_set_channel( channel );
    ESP_LOGI(TAG, "Switched to channel %d.", channel);
}

void passive_scan_start( void )
{
    scan_done = false;
    ap = 0;
    const esp_timer_create_args_t scan_timeout_args = {
        .callback = &scan_done_timeout
    };
    const esp_timer_create_args_t channel_hop_args = {
        .callback = &channel_hop_timer
    };
    wifictl_sniffer_start(channel);
    ESP_ERROR_CHECK(esp_timer_create(&scan_timeout_args, &scan_timeout_handle));
    ESP_ERROR_CHECK(esp_timer_start_once(scan_timeout_handle, SCAN_TIMEOUT * 1000000));
    ESP_ERROR_CHECK(esp_timer_create(&channel_hop_args, &channel_hop_handle));
    ESP_ERROR_CHECK(esp_timer_start_periodic(channel_hop_handle, 500 * 1000));
    ESP_ERROR_CHECK(esp_event_handler_register(SNIFFER_EVENTS, PKT_BEACON, &beacon_frame_handler, NULL));
}