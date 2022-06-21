#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_netif.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "esp_crt_bundle.h"

#include "driver/gpio.h"
#include "math.h"

#include "mqtt.h"
#include "wifi.h"

#define GPIO_INPUT_USER_BUTTON	0

#define WEB_SERVER "89.208.228.82"
#define WEB_PORT "443"
#define WEB_FILE "/file.bin"

#define HTTP_RESPONSE_LEN   512
#define BUF_SIZE            512

static const char *TAG = "TLS";
static xSemaphoreHandle btnSemHandle;

static const char *REQUEST = "GET " WEB_FILE " HTTP/1.0\r\n"
    "Host: "WEB_SERVER"\r\n"
    "User-Agent: esp-idf/1.0 esp32\r\n"
    "\r\n";

static void IRAM_ATTR gpioIsrHandler(void *arg) {

	xSemaphoreGiveFromISR(btnSemHandle, NULL);
}

static void prep_data_for_publish(char *data, size_t bytes_read, const char *c_file_size) {
    const char *separate = "/";

    sprintf(data, "%d", bytes_read);
    strcat(data, separate);
    strcat(data, c_file_size);
}

static size_t get_file_size(const char *response) {
	const char *s = "Content-Length";

	char *istr = strstr(response, s);
	if (istr != NULL) {
		istr += strlen(s) + 1;

		return strtol(istr, NULL, 10);
	}

	return 0;
}

static size_t get_header_size(const char *buf) {
    char const *sign_end_of_header = "\r\n\r\n";
    char *end_of_header = strstr((char*)buf, sign_end_of_header);
    size_t size_of_header = end_of_header - buf + strlen(sign_end_of_header);

    return size_of_header;
}

static void print_file(const char *data, size_t size) {

    for (int i = 0; i < size; i++) {
        printf("%02X", data[i]);
    }
}

static void https_get_task(void *pvParameters) {
    char buf[BUF_SIZE];
    int ret, flags, len;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {

        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ESP_LOGI(TAG, "Attaching the certificate bundle...");

    ret = esp_crt_bundle_attach(&conf);

    if(ret < 0)
    {
        ESP_LOGE(TAG, "esp_crt_bundle_attach returned -0x%x\n\n", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

     /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&ssl, WEB_SERVER)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    if((ret = mbedtls_ssl_config_defaults(&conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.

       You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
    */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&conf, CONFIG_MBEDTLS_DEBUG_LEVEL);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    while(1) {
    	xSemaphoreTake(btnSemHandle, portMAX_DELAY);

        mbedtls_net_init(&server_fd);

        ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER,
                                      WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

        ESP_LOGI(TAG, "Connected.");

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                goto exit;
            }
        }

        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
        {
            /* In real life, we probably want to close connection if ret != 0 */
            ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            ESP_LOGW(TAG, "verification info: %s", buf);
        }
        else {
            ESP_LOGI(TAG, "Certificate verified.");
        }

        ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ssl));

        ESP_LOGI(TAG, "Writing HTTP request...");

        size_t written_bytes = 0;
        do {
            ret = mbedtls_ssl_write(&ssl,
                                    (const unsigned char *)REQUEST + written_bytes,
                                    strlen(REQUEST) - written_bytes);
            if (ret >= 0) {
                ESP_LOGI(TAG, "%d bytes written", ret);
                written_bytes += ret;
            } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
                ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
                goto exit;
            }
        } while(written_bytes < strlen(REQUEST));

        ESP_LOGI(TAG, "Reading HTTP response...");

        // Read http response
        ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, HTTP_RESPONSE_LEN);

        size_t header_size = get_header_size(buf);
        char *header = malloc(header_size);
        strncpy(header, buf, header_size);
        for (int i = 0; i < header_size; i++) {
            putchar(header[i]);
		}

        print_file(buf + header_size, strlen(buf) - header_size);

        int file_size = get_file_size(header);
        char *c_file_size = malloc((int)((ceil(log10(file_size))+1)*sizeof(char)));
        sprintf(c_file_size, "%d", file_size);

		char *data = malloc(strlen(c_file_size) * 2 + 1);
		
        size_t bytes_read = strlen(buf) - header_size - 1;
        // Read file
        do {

            len = sizeof(buf) - 1;
            bzero(buf, sizeof(buf));
            ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);
            if (ret > 0) {
            	bytes_read += ret;
                prep_data_for_publish(data, bytes_read, c_file_size);
            	mqtt_publish("test/client-1/progress", data);
            }

            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)

                continue;

            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {

                ret = 0;
                break;
            }

            if (ret < 0) {

                ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
                break;
            }

            if(ret == 0)
            {
                ESP_LOGI(TAG, "connection closed");
                break;
            }

            len = ret;
            ESP_LOGD(TAG, "%d bytes read", len);
            /* Print response directly to stdout as it is read */
            print_file(buf, len);
        } while(1);

        free(c_file_size);
        free(data);
        free(header);

        mbedtls_ssl_close_notify(&ssl);

    exit:
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if(ret != 0)
        {
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        }

        putchar('\n'); // JSON output doesn't have a newline at end

        static int request_count;
        ESP_LOGI(TAG, "Completed %d requests", ++request_count);

        ESP_LOGI(TAG, "Press key to continue...");
    }
}

static void gpio_btn_init() {

	gpio_reset_pin(GPIO_INPUT_USER_BUTTON);
	gpio_set_direction(GPIO_INPUT_USER_BUTTON, GPIO_MODE_INPUT);

	gpio_set_intr_type(GPIO_INPUT_USER_BUTTON, GPIO_INTR_NEGEDGE);
	gpio_install_isr_service(0);
	gpio_isr_handler_add(GPIO_INPUT_USER_BUTTON, gpioIsrHandler, NULL);
}

void app_main(void) {

    ESP_ERROR_CHECK( nvs_flash_init() );
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init();
    gpio_btn_init();
    mqtt_start();

    btnSemHandle = xSemaphoreCreateBinary();
    xTaskCreate(&https_get_task, "https_get_task", 8192, NULL, 5, NULL);
}
