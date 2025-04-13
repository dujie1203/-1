#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/unistd.h>
#include <sys/stat.h>
#include <dirent.h>

#include "esp_err.h"
#include "esp_log.h"

#include "esp_vfs.h"
#include "esp_spiffs.h"
#include "esp_http_server.h"

#include "web_server.h"
#include "cJSON.h"
#include "esp_wifi.h"

#include "mbedtls/sha256.h"
#include "jquery_min_js_gz.h"
#include "bootstrap_min_css_gz.h"
#include "bootstrap_bundle_min_js_gz.h"
#include "esp_ota_ops.h"

#include "esp_camera.h"
#include "esp_timer.h"
#include "tracked_chassis_control.h"
#include "wifi_config.h"
#define SCRATCH_BUFSIZE 8192
extern char chip_mac[6];
extern bool g_wifi_sta_ap_state;

struct file_server_data
{
    /* Base path of file storage */
    char base_path[ESP_VFS_PATH_MAX + 1];

    /* Scratch buffer for temporary storage during file transfer */
    char scratch[SCRATCH_BUFSIZE];
};

/* Max length a file path can have on storage */
#define FILE_PATH_MAX (ESP_VFS_PATH_MAX + CONFIG_SPIFFS_OBJ_NAME_LEN)
/* Max size of an individual file. Make sure this
 * value is same as that set in upload_script.html */
#define MAX_FILE_SIZE (200 * 1024) // 200 KB
#define MAX_FILE_SIZE_STR "200KB"
static const char *TAG = "WEBSERVER";
extern const char root_start[] asm("_binary_root_html_start");
extern const char root_end[] asm("_binary_root_html_end");
extern const char index_start[] asm("_binary_index_html_start");
extern const char index_end[] asm("_binary_index_html_end");

// HTTP GET Handler
static esp_err_t root_get_handler(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Serve root");
    const uint32_t index_len = index_end - index_start;
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, index_start, index_len);

    return ESP_OK;
}
/* Copies the full path into destination buffer and returns
 * pointer to path (skipping the preceding base path) */
static const char *get_path_from_uri(char *dest, const char *base_path, const char *uri, size_t destsize)
{

    const size_t base_pathlen = strlen(base_path);
    size_t pathlen = strlen(uri);

    const char *quest = strchr(uri, '?');
    if (quest)
    {
        pathlen = MIN(pathlen, quest - uri);
    }
    const char *hash = strchr(uri, '#');
    if (hash)
    {
        pathlen = MIN(pathlen, hash - uri);
    }

    if (base_pathlen + pathlen + 1 > destsize)
    {
        /* Full path string won't fit into destination buffer */
        return NULL;
    }

    /* Construct full path (base + path) */
    strcpy(dest, base_path);
    strlcpy(dest + base_pathlen, uri, pathlen + 1);
    // ESP_LOGI(TAG, "Requested path: %s", dest);
    /* Return pointer to path, skipping the base */
    return dest + base_pathlen;
}

static const httpd_uri_t root = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = root_get_handler,
};

// HTTP Error (404) Handler - Redirects all requests to the root page
esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    // Set status
    httpd_resp_set_status(req, "302 Temporary Redirect");
    // Redirect to the "/" root directory
    httpd_resp_set_hdr(req, "Location", "/");
    // iOS requires content in the response to detect a captive portal, simply redirecting is not sufficient.
    httpd_resp_send(req, "Redirect to the captive portal", HTTPD_RESP_USE_STRLEN);

    ESP_LOGI(TAG, "Redirecting to root");
    return ESP_OK;
}
// WiFi Scan Handler 热点扫描
#define DEFAULT_WIFI_SCAN_COUNT 20
static wifi_ap_record_t wifi_scan_list[DEFAULT_WIFI_SCAN_COUNT];
static uint16_t wifi_scan_count = DEFAULT_WIFI_SCAN_COUNT;

static void get_wifi_list(void)
{
    esp_wifi_scan_start(NULL, true);
    esp_wifi_scan_get_ap_num(&wifi_scan_count);
    // printf("Number of access points found: %d\n", wifi_scan_count);
    if (wifi_scan_count > 0)
    {
        if (wifi_scan_count > DEFAULT_WIFI_SCAN_COUNT)
            wifi_scan_count = DEFAULT_WIFI_SCAN_COUNT;
        ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&wifi_scan_count, wifi_scan_list));
        // printf("  SSID             | Channel | RSSI | Authmode\n");
        // for (int i = 0; i < wifi_scan_count; i++)
        // {
        //     printf("%32s | %7d | %4d | %s\n", (char *)wifi_scan_list[i].ssid, wifi_scan_list[i].primary, wifi_scan_list[i].rssi, (wifi_scan_list[i].authmode == WIFI_AUTH_OPEN) ? "open" : "unknown");
        // }
    }
}
static esp_err_t wifi_scan_handler(httpd_req_t *req)
{
    cJSON *wifi_infos_obj = cJSON_CreateObject();
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    get_wifi_list();
    cJSON *wifi_infos = cJSON_CreateArray(); // 创建一个数组
    char *ssid;
    for (int i = 0; i < wifi_scan_count; i++)
    {
        cJSON *wifi_info = cJSON_CreateObject();
        cJSON_AddNumberToObject(wifi_info, "rssi", wifi_scan_list[i].rssi);
        cJSON_AddStringToObject(wifi_info, "ssid", (char *)(wifi_scan_list[i].ssid));
        cJSON_AddItemToArray(wifi_infos, wifi_info);
    }
    cJSON_AddItemToObject(wifi_infos_obj, "wifi_infos", wifi_infos); // 各模块数据
    char *wifi_infos_obj_json = cJSON_Print(wifi_infos_obj);         // JSON数据结构转换为JSON字符串
    httpd_resp_send(req, wifi_infos_obj_json, strlen(wifi_infos_obj_json));
    ESP_LOGI(TAG, "wifi scan get successfully!");
    return ESP_OK;
}
static const httpd_uri_t wifi_scan = {
    .uri = "/wifi_scan", // Match all URIs of type /upload/path/to/file
    .method = HTTP_GET,
    .handler = wifi_scan_handler,
};
static esp_err_t mqtt_data_handler(httpd_req_t *req)
{
    char mqtt_uri[128] = "";
    char mqtt_port_str[32] = "";
    char mqtt_username[32] = "";
    char mqtt_password[32] = "";

    int total_len = req->content_len;
    int cur_len = 0;
    char buf[SCRATCH_BUFSIZE];
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len)
    {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0)
        {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';
    ESP_LOGI(TAG, "mqtt_data_handler:%s", buf);
    cJSON *root = cJSON_Parse(buf);
    int len1;
    char *uri = cJSON_GetObjectItem(root, "mqtt_uri")->valuestring;
    len1 = strlen(uri);
    memcpy(mqtt_uri, uri, len1);
    mqtt_uri[len1] = '\0';

    char *port = cJSON_GetObjectItem(root, "mqtt_port")->valuestring;
    len1 = strlen(port);
    memcpy(mqtt_port_str, port, len1);
    mqtt_port_str[len1] = '\0';

    char *mqtt_user = cJSON_GetObjectItem(root, "mqtt_user")->valuestring;
    len1 = strlen(mqtt_user);
    memcpy(mqtt_username, mqtt_user, len1);
    mqtt_username[len1] = '\0';

    char *mqtt_passwd = cJSON_GetObjectItem(root, "mqtt_passwd")->valuestring;
    len1 = strlen(mqtt_passwd);
    memcpy(mqtt_password, mqtt_passwd, len1);
    mqtt_password[len1] = '\0';

    ESP_LOGI(TAG, "mqtt_uri:%s, mqtt_port:%s, mqtt_user:%s, mqtt_passwd:%s", mqtt_uri, mqtt_port_str, mqtt_username, mqtt_password);
    ESP_ERROR_CHECK(from_nvs_set_value("mqtt_uri", mqtt_uri));
    ESP_ERROR_CHECK(from_nvs_set_value("mqtt_port", mqtt_port_str));
    ESP_ERROR_CHECK(from_nvs_set_value("mqtt_user", mqtt_username));
    ESP_ERROR_CHECK(from_nvs_set_value("mqtt_passwd", mqtt_password));

    cJSON_Delete(root);
    // End response
    httpd_resp_send_chunk(req, NULL, 0);

    return ESP_OK;
}
static esp_err_t send_wifi_handler(httpd_req_t *req)
{
    char user_id[32] = "";
    char user_code[64] = "";
    char qcp_code[12] = "";
    int total_len = req->content_len;
    int cur_len = 0;
    char buf[SCRATCH_BUFSIZE];
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len)
    {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0)
        {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    // char *str_u = "abcdefg";
    // for(int i = 0; i<sizeof(str_u);i++){
    //     putchar(str_u[i]);
    // }
    buf[total_len] = '\0';
    // for (int i = 0; i < total_len; i++)
    // {
    //     putchar(buf[i]);
    // }
    cJSON *root = cJSON_Parse(buf);
    //  int ssid = cJSON_GetObjectItem(root, "wifi_name")->valueint;
    //  int code = cJSON_GetObjectItem(root, "wifi_code")->valueint;

    char *ssid = cJSON_GetObjectItem(root, "wifi_name")->valuestring;
    char *code = cJSON_GetObjectItem(root, "wifi_code")->valuestring;
    int checked_flag = cJSON_GetObjectItem(root, "checkbox_value")->valueint;
    // nvs_set_u8_data(SET_NVS_WIFI_AUTO_CONNECT,(uint8_t)checked_flag);
    cJSON *cdk = cJSON_GetObjectItem(root, "decive_code");
    if (cdk != NULL)
    {
        char *decive_code = cJSON_GetObjectItem(root, "decive_code")->valuestring;
        int len3 = strlen(decive_code);
        if (len3 > 5)
        {
            memcpy(qcp_code, decive_code, strlen(decive_code));
            qcp_code[len3] = '\0';
            ESP_ERROR_CHECK(from_nvs_set_value("cdk", qcp_code));
        }
    }
    int len1 = strlen(ssid);
    int len2 = strlen(code);
    memcpy(user_id, ssid, strlen(ssid));
    memcpy(user_code, code, strlen(code));
    user_id[len1] = '\0';
    user_code[len2] = '\0';
    cJSON_Delete(root);
    //  ESP_LOGI(TAG, "json load  finished. SSID:%d password:%d ",ssid,code);
    // ESP_LOGI(TAG, "json load  finished. SSID:%s password:%s ", user_id, user_code);

    // printf("\r\nwifi_ssid:");
    // for(int i = 0;i<len1;i++){
    //     printf("%c",user_id[i]);
    // }

    // printf("\r\nwifi_code:");
    // for(int i = 0;i<len2;i++){
    //     printf("%c",user_code[i]);
    // }
    ESP_ERROR_CHECK(from_nvs_set_value("ssid", user_id));
    ESP_ERROR_CHECK(from_nvs_set_value("password", user_code));
    nvs_set_u8_data(SET_NVS_WIFI_AUTO_CONNECT, (uint8_t)checked_flag);

    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    if (strcmp(user_id, "\0") != 0 && strcmp(user_code, "\0") != 0)
    {
        // xSemaphoreGive(ap_sem);
        ESP_LOGI(TAG, "set wifi name and password successfully! goto station mode");
    }

    return ESP_OK;
}
static const httpd_uri_t wifi_data = {
    .uri = "/wifi_data", // Match all URIs of type /upload/path/to/file
    .method = HTTP_POST,
    .handler = send_wifi_handler,
};

/* Handler to upload a file onto the server */
static esp_err_t upload_post_handler(httpd_req_t *req)
{
    char filepath[FILE_PATH_MAX];
    FILE *fd = NULL;
    struct stat file_stat;
    /* Skip leading "/upload" from URI to get filename */
    /* Note sizeof() counts NULL termination hence the -1 */
    const char *filename = get_path_from_uri(filepath, ((struct file_server_data *)req->user_ctx)->base_path,
                                             req->uri + sizeof("/upload") - 1, sizeof(filepath));
    if (!filename)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Filename too long");
        return ESP_FAIL;
    }

    /* Filename cannot have a trailing '/' */
    if (filename[strlen(filename) - 1] == '/')
    {
        ESP_LOGE(TAG, "Invalid filename : %s", filename);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Invalid filename");
        return ESP_FAIL;
    }

    if (stat(filepath, &file_stat) == 0)
    {
        ESP_LOGE(TAG, "File already exists will rewirte it : %s", filepath);
        // /* Respond with 400 Bad Request */
        // httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "File already exists");
        // return ESP_FAIL;
    }

    /* File cannot be larger than a limit */
    if (req->content_len > MAX_FILE_SIZE)
    {
        ESP_LOGE(TAG, "File too large : %d bytes", req->content_len);
        /* Respond with 400 Bad Request */
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "File size must be less than " MAX_FILE_SIZE_STR "!");
        /* Return failure to close underlying connection else the
         * incoming file content will keep the socket busy */
        return ESP_FAIL;
    }

    fd = fopen(filepath, "w");
    if (!fd)
    {
        ESP_LOGE(TAG, "Failed to create file : %s", filepath);
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to create file");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "create file : %s", filepath);
    ESP_LOGI(TAG, "Receiving file : %s...", filename);

    /* Retrieve the pointer to scratch buffer for temporary storage */
    char *buf = ((struct file_server_data *)req->user_ctx)->scratch;
    int received;
    char is_req_body_started = false;
    /* Content length of the request gives
     * the size of the file being uploaded */
    int remaining = req->content_len;

    while (remaining > 0)
    {

        ESP_LOGI(TAG, "Remaining size : %d", remaining);
        /* Receive the file part by part into a buffer */
        if ((received = httpd_req_recv(req, buf, MIN(remaining, SCRATCH_BUFSIZE))) <= 0)
        {
            if (received == HTTPD_SOCK_ERR_TIMEOUT)
            {
                /* Retry if timeout occurred */
                continue;
            }

            /* In case of unrecoverable error,
             * close and delete the unfinished file*/
            fclose(fd);
            unlink(filepath);

            ESP_LOGE(TAG, "File reception failed!");
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to receive file");
            return ESP_FAIL;
        }

        /* Write buffer content to file on storage */
        if (received && (received != fwrite(buf, 1, received, fd)))
        {
            /* Couldn't write everything to file!
             * Storage may be full? */
            fclose(fd);
            unlink(filepath);

            ESP_LOGE(TAG, "File write failed!");
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to write file to storage");
            return ESP_FAIL;
        }

        /* Keep track of remaining size of
         * the file left to be uploaded */
        remaining -= received;
    }
    /* Close file upon upload completion */
    fclose(fd);
    ESP_LOGI(TAG, "File reception complete");
    httpd_resp_send_chunk(req, NULL, 0);
    /* Redirect onto root to see the updated file list */
    //     httpd_resp_set_status(req, "303 See Other");
    //     httpd_resp_set_hdr(req, "Location", "/");
    // #ifdef CONFIG_EXAMPLE_HTTPD_CONN_CLOSE_HEADER
    //     httpd_resp_set_hdr(req, "Connection", "close");
    // #endif
    //     httpd_resp_sendstr(req, "File uploaded successfully");
    return ESP_OK;
}

/* Handler to delete a file from the server */
static esp_err_t delete_post_handler(httpd_req_t *req)
{
    char filepath[FILE_PATH_MAX];
    struct stat file_stat;

    /* Skip leading "/delete" from URI to get filename */
    /* Note sizeof() counts NULL termination hence the -1 */
    const char *filename = get_path_from_uri(filepath, ((struct file_server_data *)req->user_ctx)->base_path,
                                             req->uri + sizeof("/delete") - 1, sizeof(filepath));
    if (!filename)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Filename too long");
        return ESP_FAIL;
    }

    /* Filename cannot have a trailing '/' */
    if (filename[strlen(filename) - 1] == '/')
    {
        ESP_LOGE(TAG, "Invalid filename : %s", filename);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Invalid filename");
        return ESP_FAIL;
    }
    /* Check if file exists */
    bool file_exists = false;
    char src[FILE_PATH_MAX];
    memset(src, 0, sizeof(src));
    sprintf(src, "%s%s.jpg", ((struct file_server_data *)req->user_ctx)->base_path, filename);
    ESP_LOGI(TAG, "filepath : %s", src);
    if (stat(src, &file_stat) == 0)
    {
        file_exists = true;
        ESP_LOGI(TAG, "Deleting file : %s", src);
        unlink(src);
    }
    memset(src, 0, sizeof(src));
    sprintf(src, "%s%s.png", ((struct file_server_data *)req->user_ctx)->base_path, filename);
    ESP_LOGI(TAG, "filepath : %s", src);
    if (stat(src, &file_stat) == 0)
    {
        file_exists = true;
        ESP_LOGI(TAG, "Deleting file : %s", src);
        unlink(src);
    }
    if (!file_exists)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "File does not exist");
        return ESP_FAIL;
    }
    httpd_resp_send_chunk(req, NULL, 0);

    /* Redirect onto root to see the updated file list */
    //     httpd_resp_set_status(req, "303 See Other");
    //     httpd_resp_set_hdr(req, "Location", "/");
    // #ifdef CONFIG_EXAMPLE_HTTPD_CONN_CLOSE_HEADER
    //     httpd_resp_set_hdr(req, "Connection", "close");
    // #endif
    //     httpd_resp_sendstr(req, "File deleted successfully");
    return ESP_OK;
}
/* Receive .Bin file */
static esp_err_t OTA_update_post_handler(httpd_req_t *req)
{
    esp_ota_handle_t ota_handle;

    char ota_buff[1024];
    int content_length = req->content_len;
    int content_received = 0;
    int recv_len;
    bool is_req_body_started = false;
    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);

    // Unsucessful Flashing
    do
    {
        /* Read the data for the request */
        if ((recv_len = httpd_req_recv(req, ota_buff, MIN(content_length, sizeof(ota_buff)))) < 0)
        {
            if (recv_len == HTTPD_SOCK_ERR_TIMEOUT)
            {
                ESP_LOGI("OTA", "Socket Timeout");
                /* Retry receiving if timeout occurred */
                continue;
            }
            ESP_LOGI("OTA", "OTA Other Error %d", recv_len);
            return ESP_FAIL;
        }

        printf("OTA RX: %d of %d\r", content_received, content_length);

        // Is this the first data we are receiving
        // If so, it will have the information in the header we need.
        if (!is_req_body_started)
        {
            is_req_body_started = true;

            // Lets find out where the actual data staers after the header info
            char *body_start_p = strstr(ota_buff, "\r\n\r\n") + 4;
            int body_part_len = recv_len - (body_start_p - ota_buff);

            // int body_part_sta = recv_len - body_part_len;
            // printf("OTA File Size: %d : Start Location:%d - End Location:%d\r\n", content_length, body_part_sta, body_part_len);
            printf("OTA File Size: %d\r\n", content_length);

            esp_err_t err = esp_ota_begin(update_partition, OTA_SIZE_UNKNOWN, &ota_handle);
            if (err != ESP_OK)
            {
                printf("Error With OTA Begin, Cancelling OTA\r\n");
                return ESP_FAIL;
            }
            else
            {
                printf("Writing to partition subtype %d at offset 0x%ld\r\n", update_partition->subtype, update_partition->address);
            }

            // Lets write this first part of data out
            esp_ota_write(ota_handle, body_start_p, body_part_len);
        }
        else
        {
            // Write OTA data
            esp_ota_write(ota_handle, ota_buff, recv_len);

            content_received += recv_len;
        }

    } while (recv_len > 0 && content_received < content_length);

    // End response
    // httpd_resp_send_chunk(req, NULL, 0);

    if (esp_ota_end(ota_handle) == ESP_OK)
    {
        // Lets update the partition
        if (esp_ota_set_boot_partition(update_partition) == ESP_OK)
        {
            const esp_partition_t *boot_partition = esp_ota_get_boot_partition();

            // Webpage will request status when complete
            // This is to let it know it was successful

            ESP_LOGI("OTA", "Next boot partition subtype %d at offset 0x%ld", boot_partition->subtype, boot_partition->address);
            ESP_LOGI("OTA", "Please Restart System...");
            httpd_resp_send_chunk(req, NULL, 0);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            esp_restart();
        }
        else
        {
            ESP_LOGI("OTA", "\r\n\r\n !!! Flashed Error !!!");
        }
    }
    else
    {
        ESP_LOGI("OTA", "\r\n\r\n !!! OTA End Error !!!");
    }

    return ESP_OK;
}
static esp_err_t jquery_js_gz_hd(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/javascript");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_send(req, jquery_js_gz, jquery_js_gz_len);
    return ESP_OK;
}
static esp_err_t bootstrap_js_gz_hd(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/javascript");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_send(req, bootstrap_js_gz, bootstrap_js_gz_len);
    return ESP_OK;
}
static esp_err_t bootstrap_css_gz_hd(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/css");
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    httpd_resp_send(req, bootstrap_css_gz, bootstrap_css_gz_len);

    return ESP_OK;
}
#define PART_BOUNDARY "123456789000000000000987654321"
static const char *_STREAM_BOUNDARY = "\r\n--" PART_BOUNDARY "\r\n";
static const char *_STREAM_CONTENT_TYPE = "multipart/x-mixed-replace;boundary=" PART_BOUNDARY;
static const char *_STREAM_PART = "Content-Type: image/jpeg\r\nContent-Length: %u\r\n\r\n";
static bool stream_task_running = false;
#define ASYNC_WORKER_TASK_PRIORITY 5
#define ASYNC_WORKER_TASK_STACK_SIZE 4096
#define MAX_ASYNC_REQUESTS 4
// Async requests are queued here while they wait to
// be processed by the workers
static QueueHandle_t async_req_queue;

// Track the number of free workers at any given time
static SemaphoreHandle_t worker_ready_count;

// Each worker has its own thread
static TaskHandle_t worker_handles[MAX_ASYNC_REQUESTS];

typedef esp_err_t (*httpd_req_handler_t)(httpd_req_t *req);

typedef struct
{
    httpd_req_t *req;
    httpd_req_handler_t handler;
} httpd_async_req_t;

static bool is_on_async_worker_thread(void)
{
    // is our handle one of the known async handles?
    TaskHandle_t handle = xTaskGetCurrentTaskHandle();
    for (int i = 0; i < MAX_ASYNC_REQUESTS; i++)
    {
        if (worker_handles[i] == handle)
        {
            return true;
        }
    }
    return false;
}
// Submit an HTTP req to the async worker queue
static esp_err_t submit_async_req(httpd_req_t *req, httpd_req_handler_t handler)
{
    // must create a copy of the request that we own
    httpd_req_t *copy = NULL;
    esp_err_t err = httpd_req_async_handler_begin(req, &copy);
    if (err != ESP_OK)
    {
        return err;
    }

    httpd_async_req_t async_req = {
        .req = copy,
        .handler = handler,
    };

    // How should we handle resource exhaustion?
    // In this example, we immediately respond with an
    // http error if no workers are available.
    int ticks = 0;

    // counting semaphore: if success, we know 1 or
    // more asyncReqTaskWorkers are available.
    if (xSemaphoreTake(worker_ready_count, ticks) == false)
    {
        ESP_LOGE(TAG, "No workers are available");
        httpd_req_async_handler_complete(copy); // cleanup
        return ESP_FAIL;
    }

    // Since worker_ready_count > 0 the queue should already have space.
    // But lets wait up to 100ms just to be safe.
    if (xQueueSend(async_req_queue, &async_req, pdMS_TO_TICKS(100)) == false)
    {
        ESP_LOGE(TAG, "worker queue is full");
        httpd_req_async_handler_complete(copy); // cleanup
        return ESP_FAIL;
    }

    return ESP_OK;
}
static void async_req_worker_task(void *p)
{
    ESP_LOGI(TAG, "starting async req task worker");

    while (true)
    {

        // counting semaphore - this signals that a worker
        // is ready to accept work
        xSemaphoreGive(worker_ready_count);

        // wait for a request
        httpd_async_req_t async_req;
        if (xQueueReceive(async_req_queue, &async_req, portMAX_DELAY))
        {

            ESP_LOGI(TAG, "invoking %s", async_req.req->uri);

            // call the handler
            async_req.handler(async_req.req);

            // Inform the server that it can purge the socket used for
            // this request, if needed.
            if (httpd_req_async_handler_complete(async_req.req) != ESP_OK)
            {
                ESP_LOGE(TAG, "failed to complete async req");
            }
        }
    }

    ESP_LOGW(TAG, "worker stopped");
    vTaskDelete(NULL);
}

static void start_async_req_workers(void)
{

    // counting semaphore keeps track of available workers
    worker_ready_count = xSemaphoreCreateCounting(
        MAX_ASYNC_REQUESTS, // Max Count
        0);                 // Initial Count
    if (worker_ready_count == NULL)
    {
        ESP_LOGE(TAG, "Failed to create workers counting Semaphore");
        return;
    }

    // create queue
    async_req_queue = xQueueCreate(1, sizeof(httpd_async_req_t));
    if (async_req_queue == NULL)
    {
        ESP_LOGE(TAG, "Failed to create async_req_queue");
        vSemaphoreDelete(worker_ready_count);
        return;
    }

    // start worker tasks
    for (int i = 0; i < MAX_ASYNC_REQUESTS; i++)
    {

        bool success = xTaskCreate(async_req_worker_task, "async_req_worker",
                                   ASYNC_WORKER_TASK_STACK_SIZE, // stack size
                                   (void *)0,                    // argument
                                   ASYNC_WORKER_TASK_PRIORITY,   // priority
                                   &worker_handles[i]);

        if (!success)
        {
            ESP_LOGE(TAG, "Failed to start asyncReqWorker");
            continue;
        }
    }
}
esp_err_t jpg_stream_httpd_handler(httpd_req_t *req)
{
    esp_err_t res = ESP_OK;
    stream_task_running = true;
    if (is_on_async_worker_thread() == false)
    {
        // submit
        if (submit_async_req(req, jpg_stream_httpd_handler) == ESP_OK)
        {
            return ESP_OK;
        }
        else
        {
            httpd_resp_set_status(req, "503 Busy");
            httpd_resp_sendstr(req, "<div> no workers available. server busy.</div>");
            return ESP_OK;
        }
    }
    camera_fb_t *fb = NULL;
    size_t _jpg_buf_len;
    uint8_t *_jpg_buf;
    char *part_buf[64];

    res = httpd_resp_set_type(req, _STREAM_CONTENT_TYPE);
    if (res != ESP_OK)
    {
        return res;
    }
    while (stream_task_running)
    {
        fb = esp_camera_fb_get();
        if (!fb)
        {
            ESP_LOGE(TAG, "Camera capture failed");
            res = ESP_FAIL;
            break;
        }
        if (fb->format != PIXFORMAT_JPEG)
        {
            bool jpeg_converted = frame2jpg(fb, 80, &_jpg_buf, &_jpg_buf_len);
            if (!jpeg_converted)
            {
                ESP_LOGE(TAG, "JPEG compression failed");
                esp_camera_fb_return(fb);
                res = ESP_FAIL;
            }
        }
        else
        {
            _jpg_buf_len = fb->len;
            _jpg_buf = fb->buf;
        }

        if (res == ESP_OK)
        {
            res = httpd_resp_send_chunk(req, _STREAM_BOUNDARY, strlen(_STREAM_BOUNDARY));
        }
        if (res == ESP_OK)
        {
            size_t hlen = snprintf((char *)part_buf, 64, _STREAM_PART, _jpg_buf_len);

            res = httpd_resp_send_chunk(req, (const char *)part_buf, hlen);
        }
        if (res == ESP_OK)
        {
            res = httpd_resp_send_chunk(req, (const char *)_jpg_buf, _jpg_buf_len);
        }
        if (fb->format != PIXFORMAT_JPEG)
        {
            free(_jpg_buf);
        }
        esp_camera_fb_return(fb);
        if (res != ESP_OK)
        {
            break;
        }
    }
    return res;
}
static esp_err_t rocker_data_handler(httpd_req_t *req)
{
    int total_len = req->content_len;
    int cur_len = 0;
    char buf[SCRATCH_BUFSIZE];
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len)
    {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0)
        {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';
    cJSON *root = cJSON_Parse(buf);
    int x = cJSON_GetObjectItem(root, "x")->valueint;
    int y = cJSON_GetObjectItem(root, "y")->valueint;
    // ESP_LOGI(TAG, "rocker_data_handler:%d %d", x, y);
    char motor_data[32];
    float x_value = x / 100.0;
    float y_value = y / 100.0;
    sprintf(motor_data, "x%.2f y%.2f", x_value, y_value);
    tracked_chassis_motion_control(motor_data);
    cJSON_Delete(root);

    // End response
    httpd_resp_send_chunk(req, NULL, 0);

    return ESP_OK;
}
static esp_err_t baidu_api_data_handler(httpd_req_t *req)
{
    int total_len = req->content_len;
    int cur_len = 0;
    char buf[SCRATCH_BUFSIZE];
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len)
    {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0)
        {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';
    cJSON *root = cJSON_Parse(buf);
    sprintf(baidu_api_key, cJSON_GetObjectItem(root, "baidu_api_key")->valuestring);
    sprintf(baidu_secret_key, cJSON_GetObjectItem(root, "baidu_secret_key")->valuestring);
    baidu_tts_speed = atoi(cJSON_GetObjectItem(root, "baidu_tts_speed")->valuestring);
    baidu_tts_pit = atoi(cJSON_GetObjectItem(root, "baidu_tts_pit")->valuestring);
    baidu_tts_vol = atoi(cJSON_GetObjectItem(root, "baidu_tts_vol")->valuestring);
    baidu_tts_per = atoi(cJSON_GetObjectItem(root, "baidu_tts_per")->valuestring);

    api_nvs_set_value("baidu_key", baidu_api_key);
    api_nvs_set_value("secret_key", baidu_secret_key);
    api_nvs_set_u16_data("tts_speed", baidu_tts_speed);
    api_nvs_set_u16_data("tts_pit", baidu_tts_pit);
    api_nvs_set_u16_data("tts_vol", baidu_tts_vol);
    api_nvs_set_u16_data("tts_per", baidu_tts_per);

    cJSON_Delete(root);

    // End response
    httpd_resp_send_chunk(req, NULL, 0);

    return ESP_OK;
}
static esp_err_t llm_api_data_handler(httpd_req_t *req)
{
    int total_len = req->content_len;
    int cur_len = 0;
    char buf[SCRATCH_BUFSIZE];
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len)
    {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0)
        {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';
    cJSON *root = cJSON_Parse(buf);
    sprintf(llm_url, cJSON_GetObjectItem(root, "llm_url")->valuestring);
    sprintf(llm_api_key, cJSON_GetObjectItem(root, "llm_api_key")->valuestring);
    sprintf(llm_modle, cJSON_GetObjectItem(root, "llm_modle")->valuestring);

    api_nvs_set_value("llm_url", llm_url);
    api_nvs_set_value("llm_key", llm_api_key);
    api_nvs_set_value("llm_modle", llm_modle);

    cJSON_Delete(root);

    // End response
    httpd_resp_send_chunk(req, NULL, 0);

    return ESP_OK;
}
static esp_err_t asr_weather_data_handler(httpd_req_t *req)
{
    int total_len = req->content_len;
    int cur_len = 0;
    char buf[SCRATCH_BUFSIZE];
    int received = 0;
    if (total_len >= SCRATCH_BUFSIZE)
    {
        /* Respond with 500 Internal Server Error */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "content too long");
        return ESP_FAIL;
    }
    while (cur_len < total_len)
    {
        received = httpd_req_recv(req, buf + cur_len, total_len);
        if (received <= 0)
        {
            /* Respond with 500 Internal Server Error */
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to post control value");
            return ESP_FAIL;
        }
        cur_len += received;
    }
    buf[total_len] = '\0';
    cJSON *root = cJSON_Parse(buf);
    sprintf(qweather_api_key, cJSON_GetObjectItem(root, "qweather_api_key")->valuestring);
    sprintf(asr_api_key, cJSON_GetObjectItem(root, "asr_api_key")->valuestring);

    api_nvs_set_value("w_key", qweather_api_key);
    api_nvs_set_value("asr_key", asr_api_key);

    cJSON_Delete(root);

    // End response
    httpd_resp_send_chunk(req, NULL, 0);

    return ESP_OK;
}
httpd_handle_t server = NULL;
esp_err_t start_webserver(void)
{
    start_async_req_workers();

    const char *base_path = "/data";
    static struct file_server_data *server_data = NULL;

    if (server_data)
    {
        ESP_LOGE(TAG, "File server already started");
        return ESP_ERR_INVALID_STATE;
    }

    /* Allocate memory for server data */
    server_data = malloc(sizeof(struct file_server_data));
    if (!server_data)
    {
        ESP_LOGE(TAG, "Failed to allocate memory for server data");
        return ESP_ERR_NO_MEM;
    }
    strlcpy(server_data->base_path, base_path,
            sizeof(server_data->base_path));
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    /* Use the URI wildcard matching function in order to
     * allow the same handler to respond to multiple different
     * target URIs which match the wildcard scheme */
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.max_uri_handlers = 16;
    // config.core_id = 0;
    config.stack_size = 1024 * 6; // 32KB
    config.max_open_sockets = 10;
    config.lru_purge_enable = true;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK)
    {
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &root);
        httpd_register_uri_handler(server, &wifi_data);
        httpd_register_uri_handler(server, &wifi_scan);
        httpd_uri_t mqtt_data = {
            .uri = "/mqtt_data",
            .method = HTTP_POST,
            .handler = mqtt_data_handler,
        };
        httpd_register_uri_handler(server, &mqtt_data);
        /* URI handler for uploading files to server */
        httpd_uri_t file_upload = {
            .uri = "/upload/*", // Match all URIs of type /upload/path/to/file
            .method = HTTP_POST,
            .handler = upload_post_handler,
            .user_ctx = server_data // Pass server data as context
        };
        httpd_register_uri_handler(server, &file_upload);

        /* URI handler for deleting files from server */
        httpd_uri_t file_delete = {
            .uri = "/delete/*", // Match all URIs of type /delete/path/to/file
            .method = HTTP_POST,
            .handler = delete_post_handler,
            .user_ctx = server_data // Pass server data as context
        };
        httpd_register_uri_handler(server, &file_delete);

        /* OTA update URI handler */
        httpd_uri_t ota_upload = {
            .uri = "/update",
            .method = HTTP_POST,
            .handler = OTA_update_post_handler,
            .user_ctx = server_data};
        httpd_register_uri_handler(server, &ota_upload);

        httpd_uri_t jquery_js_gz_uri = {
            .uri = "/jquery.min.js",
            .method = HTTP_GET,
            .handler = jquery_js_gz_hd,
            .user_ctx = NULL};
        httpd_register_uri_handler(server, &jquery_js_gz_uri);

        httpd_uri_t bootstrap_js_gz_uri = {
            .uri = "/bootstrap.bundle.min.js",
            .method = HTTP_GET,
            .handler = bootstrap_js_gz_hd,
            .user_ctx = NULL};
        httpd_register_uri_handler(server, &bootstrap_js_gz_uri);

        httpd_uri_t bootstrap_css_gz_uri = {
            .uri = "/bootstrap.min.css",
            .method = HTTP_GET,
            .handler = bootstrap_css_gz_hd,
            .user_ctx = NULL};
        httpd_register_uri_handler(server, &bootstrap_css_gz_uri);

        httpd_uri_t stream_uri = {
            .uri = "/stream",
            .method = HTTP_GET,
            .handler = jpg_stream_httpd_handler,
            .user_ctx = NULL};
        httpd_register_uri_handler(server, &stream_uri);
        httpd_uri_t rocker_data = {
            .uri = "/rocker_data", // Match all URIs of type /upload/path/to/file
            .method = HTTP_POST,
            .handler = rocker_data_handler,
        };
        httpd_register_uri_handler(server, &rocker_data);
        httpd_uri_t baidu_api_data = {
            .uri = "/baidu_api_data", // Match all URIs of type /upload/path/to/file
            .method = HTTP_POST,
            .handler = baidu_api_data_handler,
        };
        httpd_register_uri_handler(server, &baidu_api_data);
        httpd_uri_t llm_api_data = {
            .uri = "/llm_api_data", // Match all URIs of type /upload/path/to/file
            .method = HTTP_POST,
            .handler = llm_api_data_handler,
        };
        httpd_register_uri_handler(server, &llm_api_data);
        httpd_uri_t asr_weather_data = {
            .uri = "/asr_weather_data", // Match all URIs of type /upload/path/to/file
            .method = HTTP_POST,
            .handler = asr_weather_data_handler,
        };
        httpd_register_uri_handler(server, &asr_weather_data);
        httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, http_404_error_handler);
    }
    return ESP_OK;
}
void stop_webserver()
{
    httpd_stop(server);
}