#include <string.h>
#include <sys/param.h>
#include <stdlib.h>
#include <ctype.h>

#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_tls.h"
#include "esp_netif_sntp.h"
#include "esp_sntp.h"
#include "esp_http_client.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/gpio.h"
#include "esp_adc/adc_cali.h"

// #include "protocol_examples_common.h"
// #include "protocol_examples_utils.h"

#include "lvgl.h"
#include "iot_button.h"

#include "wifi_sntp.h"
#include "esp_sparkbot_bsp.h"
#include "bsp_board_extra.h"

#include "baidu.h"

#include "cJSON.h"
#include "dirent.h"

#include "ui.h"
#include "app_imu.h"
#include "app_wifi.h"
#include "app_weather.h"
#include "app_audio_record.h"
#include "app_animation.h"
#include "app_power.h"

#include "esp_mac.h"
#include "wifi/wifi_config.h"
#include "wifi/web_server.h"

#include "esp_camera.h"
#include "esp_sleep.h"
#include "tracked_chassis_control.h"

#include "driver/rtc_io.h"
static const char *TAG = "main";

static void button_handler(touch_button_handle_t out_handle, touch_button_message_t *out_message, void *arg)
{
    (void)out_handle; // Unused
    lv_obj_t *current_screen = lv_disp_get_scr_act(NULL);
    int button = (int)arg;

    if (out_message->event == TOUCH_BUTTON_EVT_ON_PRESS)
    {
        ESP_LOGI(TAG, "Button[%d] Press", (int)arg);
        for (int i = 0; i < sizeof(ui_pages) / sizeof(ui_page_name_t); i++)
        {
            if (ui_pages[i].page == current_screen)
            {
                printf("current screen is %s\n", ui_pages[i].name);
                break;
            }
        }
        switch (button)
        {
        case 1:
            ui_send_sys_event(current_screen, LV_EVENT_UP_CLICK, NULL);
            break;
        case 2:
            ui_send_sys_event(current_screen, LV_EVENT_LEFT_CLICK, NULL);
            break;
        case 3:
            ui_send_sys_event(current_screen, LV_EVENT_RIGHT_CLICK, NULL);
            break;
        case 4:
            ui_send_sys_event(current_screen, LV_EVENT_DOWN_CLICK, NULL);
        default:
            break;
        }
    }
    else if (out_message->event == TOUCH_BUTTON_EVT_ON_RELEASE)
    {
        // ESP_LOGI(TAG, "Button[%d] Release", (int)arg);
    }
    else if (out_message->event == TOUCH_BUTTON_EVT_ON_LONGPRESS)
    {
        ESP_LOGI(TAG, "Button[%d] LongPress", (int)arg);
        switch (button)
        {
        case 1:
            ui_send_sys_event(current_screen, LV_EVENT_UP_LONG_CLICK, NULL);
            // wifi_init(2);
            break;
        case 2:
            ui_send_sys_event(current_screen, LV_EVENT_LEFT_LONG_CLICK, NULL);
            break;
        case 3:
            ui_send_sys_event(current_screen, LV_EVENT_RIGHT_LONG_CLICK, NULL);
            break;
        case 4:
            ui_send_sys_event(current_screen, LV_EVENT_DOWN_LONG_CLICK, NULL);
            break;
        default:
            break;
        }
    }
}

static void button_long_press_cb(void *arg, void *usr_data)
{
    ESP_LOGI(TAG, "BUTTON_LONG_PRESS_START");
    nvs_flash_erase();
    esp_restart();
}

void memory_monitor()
{
    static char buffer[128]; /* Make sure buffer is enough for `sprintf` */
    if (1)
    {
        sprintf(buffer, "   Biggest /     Free /    Total\n"
                        "\t  SRAM : [%8d / %8d / %8d]\n"
                        "\t PSRAM : [%8d / %8d / %8d]",
                heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
                heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
                heap_caps_get_total_size(MALLOC_CAP_INTERNAL),
                heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM),
                heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
                heap_caps_get_total_size(MALLOC_CAP_SPIRAM));
        ESP_LOGI("MEM", "%s", buffer);
        // vTaskDelay(5000 / portTICK_PERIOD_MS);
    }
}
char chip_mac[6];
void app_main(void)
{

    esp_sleep_wakeup_cause_t cause = esp_sleep_get_wakeup_cause();
    if (cause == ESP_SLEEP_WAKEUP_EXT0)
    {
        ESP_LOGI(TAG, "Wake up by EXT0");
    }
    else
    {
        ESP_LOGE(TAG, "Unknown wakeup cause: %d", cause);
    }
    /* Initialize NVS. */
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }

    /* Initialize the power adc */
    power_adc_init();
    bsp_i2c_init();
    /**
     * @brief Connect to the network
     */

    ESP_LOGI(TAG, "Initializing network...");
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_LOGI(TAG, "GUI init");

    app_animation_start();

    ESP_LOGI(TAG, "IMU init");

    app_imu_init();
    bsp_touch_button_create(button_handler);
    /* Initialize the camera */
    const camera_config_t camera_config = BSP_CAMERA_DEFAULT_CONFIG;
    err = esp_camera_init(&camera_config);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Camera Init Failed");
        return;
    }
    sensor_t *s = esp_camera_sensor_get();
    s->set_vflip(s, BSP_CAMERA_VFLIP);
    s->set_hmirror(s, BSP_CAMERA_HMIRROR);
    ESP_LOGI(TAG, "Camera Init done");

    // ESP_ERROR_CHECK(example_connect());
    uint8_t mac[6];
    esp_base_mac_addr_get(mac);
    for (uint8_t i = 0; i < 3; i++)
    {
        sprintf(chip_mac + i * 2, "%02X", mac[i + 3]);
    }
    ESP_LOGI(TAG, "chip_mac:%s", chip_mac);
    memory_monitor();
    // 连接wifi
    ESP_ERROR_CHECK(app_sr_start());
    memory_monitor();
    uint8_t auto_wifi_flag = nvs_get_u8_data(SET_NVS_WIFI_AUTO_CONNECT);
    if (auto_wifi_flag || strlen((char *)WIFI_SSID) > 0)
    {
        err = wifi_init(1);
        memory_monitor();

        if (err == ESP_OK)
        {
            // first_get_api_nvs();
            default_api_key();
            wifi_sntp_start();

            app_weather_start();
            app_network_start();
            send_network_event(NET_EVENT_WEATHER);
            get_baidu_audio_token();
        }
    }
    else
    {
        set_wifi_ip_text("no wifi");
    }
    /* Monitor free heap */
    tracked_chassis_control_start();
    memory_monitor();
    // esp_sleep_enable_touchpad_wakeup();
    // const int ext_wakeup_pin_0 = 0;         // 使能0脚为唤醒外部中断0
    // ESP_ERROR_CHECK(rtc_gpio_pullup_en(0)); // 内部上拉
    // ESP_ERROR_CHECK(rtc_gpio_pulldown_dis(0));
    // // 使能外部中断唤醒功能
    // esp_sleep_enable_ext0_wakeup(ext_wakeup_pin_0, ESP_EXT1_WAKEUP_ANY_LOW);
    // // rtc_gpio_isolate(GPIO_NUM_12);//将12脚隔离
    // ESP_LOGI(TAG, "Entering deep sleep");
    // esp_deep_sleep_start(); // 开始深度休眠
    // ESP_LOGI(TAG, "Exit  deep sleep");
}
