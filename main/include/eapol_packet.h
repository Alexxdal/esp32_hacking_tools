#ifndef EAPOL_PACKET_H
#define EAPOL_PACKET_H

#include "../../components/libwifi-esp32/src/libwifi/core/frame/frame.h"
#include <stdint.h>

#define SNAP 0xaa
#define TYPE_START          0x01
#define TYPE_EAP_PACKET     0x00

/*
* Logical-Link control types
*/
#define AUTH_8021X 0x888e

/*
* 802.1X Authenticator version
*/
#define AUTH_8021X_2001 0x01

/*
* 802.1X Authenticator type
*/
#define AUTH_8021X_TYPE_EAP     0x00
#define AUTH_8021X_TYPE_START   0x01

/*
* Extensible Authentication protocol type
*/
#define EXT_AUTH_PROTO_TYPE_IDENTITY     0x01
#define EXT_AUTH_PROTO_TYPE_EXPANDED     0xfe


static const unsigned char eapol_start_data[] = {
    //Logical link control
    SNAP,               //DSAP
    SNAP,               //SSAP
    0x03,               //Control field
    0x00, 0x00, 0x00,   //Organization code
    0x88, 0x8e,         //Type 802.1X Authentication (0x888e)
    //802.1X Authentication
    0x01,               //Version: 802.1X-2001
    TYPE_START,         //Type start
    0x00, 0x00          //Length
};


struct libwifi_logical_link_control {
    uint8_t DSAP;
    uint8_t SSAP;
    uint8_t control_field;
    uint8_t organization_code[3];
    uint16_t type;
} __attribute__((packed));

struct libwifi_authentication_8021X {
    uint8_t version;
    uint8_t type;
    uint16_t length;
} __attribute__((packed));

struct libwifi_extensible_auth_protocol {
    uint8_t code;
    uint8_t id;
    uint16_t length;
    uint8_t type;
} __attribute__((packed));


struct libwifi_eapol_start {
    struct libwifi_mgmt_unordered_frame_header frame_header;
    struct libwifi_logical_link_control logical_link_control;
    struct libwifi_authentication_8021X authentication_8021X;
    struct libwifi_extensible_auth_protocol extensible_auth_protocol;
} __attribute__((packed));


int libwifi_create_eapol_start(struct libwifi_eapol_start *eapol_start,
                             const unsigned char receiver[6],
                             const unsigned char transmitter[6],
                             const unsigned char address3[6]);

size_t libwifi_dump_eapol_start(struct libwifi_eapol_start *eapol_start, unsigned char *buf, size_t buf_len);


size_t libwifi_get_eapol_start_length(struct libwifi_eapol_start *eapol_start);

#endif
