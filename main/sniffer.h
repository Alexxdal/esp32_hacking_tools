#ifndef SNIFFER_H
#define SNIFFER_H

#include "esp_event.h"

ESP_EVENT_DECLARE_BASE(SNIFFER_EVENTS);

enum pkt_events {
    /*
    * MANAGEMENT FRAME SUBTYPE
    */
    PKT_BEACON,
    PKT_PROBE_REQUEST,
    PKT_PROBE_RESPONSE,
    PKT_ASSOC_REQUEST,
    PKT_ASSOC_RESPONSE,
    PKT_REASSOC_REQUEST,
    PKT_REASSOC_RESPONSE,
    PKT_TIME_ADV,
    PKT_ATIM,
    PKT_DISASSOC,
    PKT_AUTH,
    PKT_DEAUTH,
    PKT_ACTION,
    PKT_NOACK,
    /*
    * DATA FRAME SUBTYPE
    */
    PKT_DATA,
    PKT_DATA_NULL,
    PKT_DATA_QOS_DATA,
    PKT_DATA_QOS_DATA_CF_ACK,
    PKT_DATA_QOS_DATA_CF_POLL,
    PKT_DATA_QOS_DATA_CF_ACK_CF_POLL,
    PKT_DATA_QOS_NULL,
    PKT_DATA_QOS_CF_POLL,
    PKT_DATA_QOS_CF_ACK_CF_POLL,
    /*
    * DATA FRAME HANDSHAKE
    */
    PKT_HANDSHAKE_M1,
    PKT_HANDSHAKE_M2,
    PKT_HANDSHAKE_M3,
    PKT_HANDSHAKE_M4,

    PKT_UNKNOWN
};

/**
 * @brief Sets sniffer filter for specific frame types. 
 * 
 * @param data sniff data frames
 * @param mgmt sniff management frames
 * @param ctrl sniff control frames
 */
void wifictl_sniffer_filter_frame_types(bool data, bool mgmt, bool ctrl);

/**
 * @brief Start promiscuous mode on given channel
 * 
 * @param channel channel on which sniffer should operate
 */
void wifictl_sniffer_start(uint8_t channel);

/**
 * @brief Stop promisuous mode
 * 
 */
void wifictl_sniffer_stop();

#endif