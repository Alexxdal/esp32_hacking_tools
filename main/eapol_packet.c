/* Copyright 2021 The libwifi Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "eapol_packet.h"
#include "../components/libwifi-esp32/src/libwifi/core/misc/byteswap.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static const char* TAG = "EAPOL_PACKET";

int libwifi_create_eapol_start(struct libwifi_eapol_start *eapol_start,
                             const unsigned char receiver[6],
                             const unsigned char transmitter[6],
                             const unsigned char address3[6]) {

    memset(eapol_start, 0, sizeof(struct libwifi_eapol_start));
    eapol_start->frame_header.frame_control.type = TYPE_DATA;
    eapol_start->frame_header.frame_control.subtype = SUBTYPE_DATA;
    eapol_start->frame_header.frame_control.flags.to_ds = 0x1;
    memcpy(&eapol_start->frame_header.addr1, receiver, 6);
    memcpy(&eapol_start->frame_header.addr2, transmitter, 6);
    memcpy(&eapol_start->frame_header.addr3, address3, 6);
    eapol_start->frame_header.seq_control.sequence_number = (rand() % 4096);

    eapol_start->logical_link_control.DSAP = SNAP;
    eapol_start->logical_link_control.SSAP = SNAP;
    eapol_start->logical_link_control.control_field = 0x03;
    eapol_start->logical_link_control.type = AUTH_8021X;
    eapol_start->authentication_8021X.version = AUTH_8021X_2001;
    eapol_start->authentication_8021X.type = AUTH_8021X_TYPE_START;
    eapol_start->authentication_8021X.length = 0;
    return 0;
}


size_t libwifi_dump_eapol_start(struct libwifi_eapol_start *eapol_start, unsigned char *buf, size_t buf_len) {
    size_t eapol_len = sizeof(eapol_start->frame_header) + sizeof(struct libwifi_logical_link_control) + sizeof(struct libwifi_authentication_8021X);
    if (eapol_len > buf_len) {
        return -EINVAL;
    }
    size_t offset = 0;
    memcpy(buf + offset, &eapol_start->frame_header, sizeof(struct libwifi_mgmt_unordered_frame_header));

    offset += sizeof(struct libwifi_mgmt_unordered_frame_header);
    eapol_start->logical_link_control.type = ntohs(eapol_start->logical_link_control.type);
    memcpy(buf + offset, &eapol_start->logical_link_control, sizeof(eapol_start->logical_link_control));

    offset += sizeof(struct libwifi_logical_link_control);
    memcpy(buf + offset, &eapol_start->authentication_8021X, sizeof(eapol_start->authentication_8021X));

    return eapol_len;
}

size_t libwifi_get_eapol_start_length(struct libwifi_eapol_start *eapol_start) {
    return sizeof(eapol_start->frame_header) + sizeof(struct libwifi_logical_link_control) + sizeof(struct libwifi_authentication_8021X);;
}