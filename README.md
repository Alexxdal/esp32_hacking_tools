# Getting started

Make a copy of "libnet80211.a" -> "libnet80211.a.old"
Run
    ???/.espressif/tools/xtensa-esp32-elf/esp-2020r3-8.4.0/xtensa-esp32-elf/bin/xtensa-esp32-elf-objcopy --weaken-symbol=ieee80211_raw_frame_sanity_check ???/esp/esp-idf/components/esp_wifi/lib/esp32/libnet80211.a ???/esp/esp-idf/components/esp_wifi/lib/esp32/libnet80211.a2
    Copy libnet80211.a2 in place of libnet80211.a

Now "ieee80211_raw_frame_sanity_check" is a weak link that will be overridden by the function with the same name from the project
