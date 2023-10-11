#include "scanner_advanced.h"
#include "sniffer.h"
#include "utils.h"
#include <string.h>
#include <libwifi.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_timer.h"

static const char *TAG = "SCANNER_ADVANCED";
static esp_timer_handle_t scan_timeout_handle;
uint8_t ap = 0;
bool scan_done = false;
wifictl_ap_records_t ap_record = { 0 };


static void beacon_frame_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGI(TAG, "Got beacon frame");
    struct libwifi_frame frame = { 0 };
    struct libwifi_bss bss = { 0 };
    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) event_data;
    unsigned long data_len = ppkt->rx_ctrl.sig_len;
    int ret = libwifi_get_wifi_frame(&frame, (const unsigned char*)ppkt->payload, data_len, has_radiotap);
    if (ret < 0) {
        goto free_mem;
    }
    ret = libwifi_parse_beacon(&bss, &frame);
    if (ret < 0) {
        libwifi_free_bss(&bss);
        goto free_mem;
    }
    //Check if bssid is already present in scan results array
    for(int i = 0; i < ap; i++){
        if( mac_compare((unsigned char *)&ap_record.records[ap].bssid, (unsigned char *)&bss.bssid) ){
            libwifi_free_bss(&bss);
            goto free_mem;
        }
    }
    //Ok questo beacon non è presente nei risultati
    memcpy(&ap_record.records[ap].bssid, &bss.bssid, sizeof(bss.bssid));
    strcpy((char *)&ap_record.records[ap].ssid, bss.hidden ? "(hidden)" : (char *)&bss.ssid);
    ap_record.records[ap].primary = bss.channel;
    ap_record.records[ap].rssi = ppkt->rx_ctrl.rssi;
    ap_record.records[ap].wps = bss.wps;
    ap++;
    ap_record.count = ap;
    //libwifi_get_security_type(&bss, ap_record[ap].encryption);
    //libwifi_get_group_ciphers(&bss, ap_record[ap].group_chipers);
    //libwifi_get_pairwise_ciphers(&bss, ap_record[ap].pairwise_chipers);
    //libwifi_get_auth_key_suites(&bss, ap_record[ap].auth_key_suites);
free_mem:
    libwifi_free_wifi_frame(&frame);
}

static void scan_timeout(void* arg)
{

}

void passive_scan_start( void )
{
    ap = 0;
    const esp_timer_create_args_t scan_timeout_args = {
        .callback = &scan_timeout
    };
    ESP_ERROR_CHECK(esp_timer_create(&scan_timeout_args, &scan_timeout_handle));
    ESP_ERROR_CHECK(esp_timer_start_once(scan_timeout_handle, SCAN_TIMEOUT * 1000000));
    ESP_ERROR_CHECK(esp_event_handler_register(SNIFFER_EVENTS, PKT_BEACON, &beacon_frame_handler, NULL));
    wifictl_sniffer_start(1);
}

int passive_scan_done( wifictl_ap_records_t *ap_record )
{
    wifictl_sniffer_stop();
    ESP_ERROR_CHECK(esp_event_handler_unregister(ESP_EVENT_ANY_BASE, ESP_EVENT_ANY_ID, &beacon_frame_handler));
    return;
}