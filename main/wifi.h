#ifndef MAIN_WIFI_H_
#define MAIN_WIFI_H_

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_log.h"

void wifi_init(void);

#define WIFI_SSID      		"wifi name"
#define WIFI_PASSWORD      	"password"
#define WIFI_MAXIMUM_RETRY  5

#define WIFI_CONNECTED_BIT 	BIT0
#define WIFI_FAIL_BIT      	BIT1

void wifi_init(void);

#endif /* MAIN_WIFI_H_ */
