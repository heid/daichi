#ifndef MAIN_MQTT_H_
#define MAIN_MQTT_H_

#include "esp_log.h"
#include "mqtt_client.h"

#define MQTT_URI		"mqtts://89.208.228.82:8883"
#define MQTT_USER		"client-1"
#define MQTT_PASSWORD	"08bdfddac0e5df7991b80aa9abcad622"

void mqtt_start(void);
void mqtt_publish(const char *topic, const char *data);

#endif /* MAIN_MQTT_H_ */
