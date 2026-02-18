/*
 * SPDX-FileCopyrightText: 2024 Volodymyr Shymanskyy for Blynk Technologies Inc.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The software is provided "as is", without any warranties or guarantees (explicit or implied).
 * This includes no assurances about being fit for any specific purpose.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <mosquitto.h>

static int run = 1;

void handle_signal(int s)
{
    run = 0;
}

void sleep_ms(unsigned msec) {
    usleep(msec * 1000);
}

void connect_callback(struct mosquitto *mosq, void *obj, int rc)
{
    if (rc == 0) {
        printf("Connected (secure)\n");
        mosquitto_subscribe(mosq, NULL, "downlink/#", 0);
    } else if (rc == 4) {
        printf("Invalid Auth Token\n");
        exit(1);
    } else {
        printf("Connect failed, rc=%d\n", rc);
        exit(1);
    }
}

void disconnect_callback(struct mosquitto *mosq, void *obj, int rc)
{
    if (rc) {
        printf("Unexpected disconnection\n");
    }
}

void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg)
{
    printf("Got %s, value: %.*s\n",
           msg->topic,
           msg->payloadlen, (char*)msg->payload);

    if (0 == strcmp(msg->topic, "downlink/ds/terminal")) {
        char buff[128];
        int len = snprintf(buff, sizeof(buff),
                           "Your command: %.*s",
                           msg->payloadlen, (char*)msg->payload);
        mosquitto_publish(mosq, NULL, "ds/terminal", len, buff, 0, false);
    }
}

void log_callback(struct mosquitto *mosq, void *userdata, int level, const char *str)
{
    switch(level) {
    //case MOSQ_LOG_DEBUG:
    //case MOSQ_LOG_INFO:
    //case MOSQ_LOG_NOTICE:
    case MOSQ_LOG_WARNING:
    case MOSQ_LOG_ERR:
        printf("%i:%s\n", level, str);
    }
}

int get_mem_total(char *buffer, size_t buffer_size) {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) {
        return -1;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            char *value = line + 9;
            while (*value == ' ' || *value == '\t') value++;
            char *end = strstr(value, " kB");
            if (end) {
                size_t len = end - value;
                if (len < buffer_size) {
                    strncpy(buffer, value, len);
                    buffer[len] = '\0';
                    fclose(fp);
                    return 0;
                }
            }
        }
    }
    fclose(fp);
    return -1;
}

int main(int argc, char *argv[])
{
    uint8_t reconnect = true;
    struct mosquitto *mosq;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    mosquitto_lib_init();

    //memset(clientid, 0, 24);
    //snprintf(clientid, 23, "dev_%d", getpid());
    mosq = mosquitto_new(NULL, true, 0);

    if (mosq) {
        mosquitto_connect_callback_set(mosq, connect_callback);
        mosquitto_disconnect_callback_set(mosq, disconnect_callback);
        mosquitto_message_callback_set(mosq, message_callback);
        mosquitto_log_callback_set(mosq, log_callback);

        mosquitto_username_pw_set(mosq, "device", argv[1]);
        /* ISRG Root X1, expires: Mon, 04 Jun 2035 11:04:38 GMT */
        mosquitto_tls_set(mosq, "ISRG_Root_X1.crt",
                          NULL, NULL, NULL, NULL);
        mosquitto_connect_async(mosq, "blynk.cloud", 8883, 45);
        mosquitto_loop_start(mosq);

        int uptime = 0;
        int counter = 0;
        while (run) {
            sleep_ms(1000);
            uptime++;
            counter++;

            char buff[16];
            int len = snprintf(buff, sizeof(buff), "%d", uptime);
            mosquitto_publish(mosq, NULL, "ds/uptime", len, buff, 0, false);

            if (counter >= 10) {
                counter = 0;
                char mem_buff[32];
                char get_buff[32];
                if (get_mem_total(mem_buff, sizeof(mem_buff)) == 0) {
                    int mem_len = strlen(mem_buff);
                    mosquitto_publish(mosq, NULL, "ds/Total ram", mem_len, mem_buff, 0, false);
                    printf("Published RAM: %s\n", mem_buff);
                    mosquitto_publish(mosq, NULL, "get/ds", mem_len, get_buff, 0, false);
                }
            }
        }
        mosquitto_disconnect(mosq);
        mosquitto_loop_stop(mosq, false);
        printf("Disconnecting...\n");
        mosquitto_destroy(mosq);
    }

    mosquitto_lib_cleanup();

    return 0;
}
