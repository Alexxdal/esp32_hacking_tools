#include "sniffer.h"

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "utils.h"
#include <libwifi.h>

static const char *TAG = "SNIFFER"; 
static unsigned char mac_filter[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; 
static bool apply_filter = false;
ESP_EVENT_DEFINE_BASE(SNIFFER_EVENTS);


esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3){
    return 0;
}


static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type)
{
    ESP_LOGV(TAG, "Captured frame %d.", (int) type);
    int has_radiotap = 0;
    struct libwifi_frame frame = {0};
    wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    /*
    * Check frame lenght
    */
    if (ppkt->rx_ctrl.sig_len < 100){
        return;
    }
    /*
    * Try parse frame
    */
    unsigned long data_len = ppkt->rx_ctrl.sig_len;
    int ret = libwifi_get_wifi_frame(&frame, (const unsigned char*)ppkt->payload, data_len, has_radiotap);
    if (ret < 0) {
        goto free_mem;
    }  
    /*
    * Filter frames by MAC address
    */
    if( apply_filter == true ){
        if( !mac_compare(frame.header.mgmt_ordered.addr1, (unsigned char *)&mac_filter) && !mac_compare(frame.header.mgmt_ordered.addr2, (unsigned char *)&mac_filter)){
            goto free_mem;
        }
    }

    int32_t event_id = PKT_UNKNOWN;
    if(frame.frame_control.type == TYPE_MANAGEMENT)
    {
        switch(frame.frame_control.subtype){
            case SUBTYPE_BEACON:
                event_id = PKT_BEACON;
                break;
            case SUBTYPE_PROBE_RESP:
                event_id = PKT_PROBE_RESPONSE;
                break;
            case SUBTYPE_PROBE_REQ:
                event_id = PKT_PROBE_REQUEST;
                break;
            case SUBTYPE_ASSOC_REQ:
                event_id = PKT_ASSOC_REQUEST;
                break;
            case SUBTYPE_ASSOC_RESP:
                event_id = PKT_ASSOC_RESPONSE;
                break;
            case SUBTYPE_REASSOC_REQ:
                event_id = PKT_REASSOC_REQUEST;
                break;
            case SUBTYPE_REASSOC_RESP:
                event_id = PKT_REASSOC_RESPONSE;
                break;
            case SUBTYPE_TIME_ADV:
                event_id = PKT_TIME_ADV;
                break;
            case SUBTYPE_ATIM:
                event_id = PKT_ATIM;
                break;
            case SUBTYPE_DISASSOC:
                event_id = PKT_DISASSOC;
                break;
            case SUBTYPE_AUTH:
                event_id = PKT_AUTH;
                break;
            case SUBTYPE_DEAUTH:
                event_id = PKT_DEAUTH;
                break;
            case SUBTYPE_ACTION:
                event_id = PKT_ACTION;
                break;
            case SUBTYPE_ACTION_NOACK:
                event_id = PKT_NOACK;
                break;
            
            default:
                event_id = PKT_UNKNOWN;
                break;
        }   
    }
    
    if(frame.frame_control.type == TYPE_DATA)
    {
        switch(frame.frame_control.subtype){
            case SUBTYPE_DATA:
                /*
                * Check if there is an handshake
                */
                if(libwifi_check_wpa_handshake(&frame) > 0){
                    switch(libwifi_check_wpa_message(&frame)){
                        case HANDSHAKE_M1:
                            event_id = PKT_HANDSHAKE_M1;
                            break;
                        case HANDSHAKE_M2:
                            event_id = PKT_HANDSHAKE_M2;
                            break;
                        case HANDSHAKE_M3:
                            event_id = PKT_HANDSHAKE_M3;
                            break;
                        case HANDSHAKE_M4:
                            event_id = PKT_HANDSHAKE_M4;
                            break;
                        case HANDSHAKE_INVALID:
                            event_id = PKT_DATA;
                            break;
                    }
                }
                else {
                    event_id = PKT_DATA;
                }
                break;
            case SUBTYPE_DATA_NULL:
                event_id = PKT_DATA_NULL;
                break;
            case SUBTYPE_DATA_QOS_DATA:
                event_id = PKT_DATA_QOS_DATA;
                break;
            case SUBTYPE_DATA_QOS_DATA_CF_ACK:
                event_id = PKT_DATA_QOS_DATA_CF_ACK;
                break;
            case SUBTYPE_DATA_QOS_DATA_CF_POLL:
                event_id = PKT_DATA_QOS_DATA_CF_POLL;
                break;
            case SUBTYPE_DATA_QOS_DATA_CF_ACK_CF_POLL:
                event_id = PKT_DATA_QOS_DATA_CF_ACK_CF_POLL;
                break;
            case SUBTYPE_DATA_QOS_NULL:
                event_id = PKT_DATA_QOS_NULL;
                break;
            case SUBTYPE_DATA_QOS_CF_POLL:
                event_id = PKT_DATA_QOS_CF_POLL;
                break;
            case SUBTYPE_DATA_QOS_CF_ACK_CF_POLL:
                event_id = PKT_DATA_QOS_CF_ACK_CF_POLL;
                break;

            default:
                event_id = PKT_UNKNOWN;
                break;
        }
    }
    ESP_ERROR_CHECK(esp_event_post(SNIFFER_EVENTS, event_id, ppkt, ppkt->rx_ctrl.sig_len + sizeof(wifi_promiscuous_pkt_t), 0U));
free_mem:
    libwifi_free_wifi_frame(&frame);
    return;
}

void wifictl_sniffer_filter_frame_types(bool data, bool mgmt, bool ctrl) {
    wifi_promiscuous_filter_t filter = { .filter_mask = 0 };
    if(data) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    }
    else if(mgmt) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
    }
    else if(ctrl) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    }
    esp_wifi_set_promiscuous_filter(&filter);
}

void wifictl_sniffer_start(uint8_t channel) {
    ESP_LOGI(TAG, "Starting promiscuous mode...");
    // ESP32 cannot switch port, if there is some STA connected to AP
    ESP_LOGD(TAG, "Kicking all connected STAs from AP");
    ESP_ERROR_CHECK(esp_wifi_deauth_sta(0));
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void wifictl_sniffer_stop() {
    ESP_LOGI(TAG, "Stopping promiscuous mode...");
    esp_wifi_set_promiscuous(false);
}