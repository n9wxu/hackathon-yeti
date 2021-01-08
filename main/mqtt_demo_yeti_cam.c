/*
 * FreeRTOS V202011.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://www.FreeRTOS.org
 * http://aws.amazon.com/freertos
 *
 */

/*
 * Demo for showing use of the MQTT API using a mutually authenticated
 * network connection.
 *
 * The Example shown below uses MQTT APIs to create MQTT messages and send them
 * over the mutually authenticated network connection established with the
 * MQTT broker. This example is single threaded and uses statically allocated
 * memory. It uses QoS1 for sending to and receiving messages from the broker.
 *
 * A mutually authenticated TLS connection is used to connect to the
 * MQTT message broker in this example. Define democonfigMQTT_BROKER_ENDPOINT
 * and democonfigROOT_CA_PEM, in mqtt_demo_mutual_auth_config.h, and the client
 * private key and certificate, in aws_clientcredential_keys.h, to establish a
 * mutually authenticated connection.
 */

/**
 * @file mqtt_demo_mutual_auth.c
 * @brief Demonstrates usage of the MQTT library.
 */

/* Standard includes. */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Demo Specific configs. */
#include "mqtt_demo_mutual_auth_config.h"

/* Include common demo header. */
//#include "aws_demo.h"

/* Kernel includes. */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_sleep.h"
#include "esp_wifi.h"
#include "esp_wifi_default.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_tls.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include "esp_netif.h"
#include "esp_camera.h"

#include <sys/unistd.h>
#include <sys/stat.h>
#include "esp_vfs_fat.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"
#include "sdmmc_cmd.h"
#include "sdkconfig.h"

#ifdef CONFIG_IDF_TARGET_ESP32
    #include "driver/sdmmc_host.h"
#endif

#include "driver/rtc_io.h"

/* MQTT library includes. */
#include "core_mqtt.h"

/* Retry utilities include. */
#include "backoff_algorithm.h"

/* Transport interface implementation include header for TLS. */
#include "esp_tls_transport.h"

/* Include header for connection configurations. */
#include "aws_clientcredential.h"

/* Include header for client credentials. */
#include "aws_clientcredential_keys.h"

/* Include header for root CA certificates. */
//#include "iot_default_root_certificates.h"

/*------------- Demo configurations -------------------------*/

/** Note: The device client certificate and private key credentials are
 * obtained by the transport interface implementation (with Secure Sockets)
 * from the demos/include/aws_clientcredential_keys.h file.
 *
 * The following macros SHOULD be defined for this demo which uses both server
 * and client authentications for TLS session:
 *   - keyCLIENT_CERTIFICATE_PEM for client certificate.
 *   - keyCLIENT_PRIVATE_KEY_PEM for client private key.
 */

/**
 * @brief The MQTT broker endpoint used for this demo.
 */
#ifndef democonfigMQTT_BROKER_ENDPOINT
    #define democonfigMQTT_BROKER_ENDPOINT    clientcredentialMQTT_BROKER_ENDPOINT
#endif

static const char tlsATS1_ROOT_CERTIFICATE_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n"
    "ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n"
    "b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n"
    "MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n"
    "b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\n"
    "ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n"
    "9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\n"
    "IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\n"
    "VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n"
    "93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\n"
    "jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n"
    "AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\n"
    "A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\n"
    "U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\n"
    "N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\n"
    "o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n"
    "5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\n"
    "rqXRfboQnoZsG4q5WTP468SQvvG5\n"
    "-----END CERTIFICATE-----\n";

/**
 * @brief The root CA certificate belonging to the broker.
 */
#ifndef democonfigROOT_CA_PEM
    #define democonfigROOT_CA_PEM    tlsATS1_ROOT_CERTIFICATE_PEM
#endif

#ifndef democonfigCLIENT_IDENTIFIER

/**
 * @brief The MQTT client identifier used in this example.  Each client identifier
 * must be unique so edit as required to ensure no two clients connecting to the
 * same broker use the same client identifier.
 */
    #define democonfigCLIENT_IDENTIFIER    clientcredentialIOT_THING_NAME
#endif

#ifndef democonfigMQTT_BROKER_PORT

/**
 * @brief The port to use for the demo.
 */
    #define democonfigMQTT_BROKER_PORT    clientcredentialMQTT_BROKER_PORT
#endif

/**
 * @brief The maximum number of retries for network operation with server.
 */
#define RETRY_MAX_ATTEMPTS                                ( 5U )

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying failed operation
 *  with server.
 */
#define RETRY_MAX_BACKOFF_DELAY_MS                        ( 5000U )

/**
 * @brief The base back-off delay (in milliseconds) to use for network operation retry
 * attempts.
 */
#define RETRY_BACKOFF_BASE_MS                             ( 500U )

/**
 * @brief Timeout for receiving CONNACK packet in milliseconds.
 */
#define mqttexampleCONNACK_RECV_TIMEOUT_MS                ( 1000U )

/**
 * @brief The topic to subscribe and publish to in the example.
 *
 * The topic name starts with the client identifier to ensure that each demo
 * interacts with a unique topic name.
 */
#define mqttexampleTOPIC                      democonfigCLIENT_IDENTIFIER "/yeti/pics"

/**
 * @brief The number of topic filters to subscribe.
 */
#define mqttexampleTOPIC_COUNT                            ( 1 )

/**
 * @brief Time in ticks to wait between each cycle of the demo implemented
 * by RunCoreMqttYetiCamDemo().
 */
#define mqttexampleDELAY_BETWEEN_DEMO_ITERATIONS_TICKS    ( pdMS_TO_TICKS( 5000U ) )

/**
 * @brief Timeout for MQTT_ProcessLoop in milliseconds.
 */
#define mqttexamplePROCESS_LOOP_TIMEOUT_MS                ( 700U )

/**
 * @brief The maximum number of times to call MQTT_ProcessLoop() when polling
 * for a specific packet from the broker.
 */
#define MQTT_PROCESS_LOOP_PACKET_WAIT_COUNT_MAX           ( 30U )

/**
 * @brief Keep alive time reported to the broker while establishing
 * an MQTT connection.
 *
 * It is the responsibility of the Client to ensure that the interval between
 * Control Packets being sent does not exceed the this Keep Alive value. In the
 * absence of sending any other Control Packets, the Client MUST send a
 * PINGREQ Packet.
 */
#define mqttexampleKEEP_ALIVE_TIMEOUT_SECONDS             ( 120U )

/**
 * @brief Delay (in ticks) between consecutive cycles of MQTT publish operations in a
 * demo iteration.
 *
 * Note that the process loop also has a timeout, so the total time between
 * publishes is the sum of the two delays.
 */
#define mqttexampleDELAY_BETWEEN_PUBLISHES_TICKS          ( pdMS_TO_TICKS( 2000U ) )

/**
 * @brief Transport timeout in milliseconds for transport send and receive.
 */
#define mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS         ( 500U )

/**
 * @brief Milliseconds per second.
 */
#define MILLISECONDS_PER_SECOND                           ( 1000U )

/**
 * @brief Milliseconds per FreeRTOS tick.
 */
#define MILLISECONDS_PER_TICK                             ( MILLISECONDS_PER_SECOND / configTICK_RATE_HZ )

#define GOT_IPV4_BIT BIT(0)
#define GOT_IPV6_BIT BIT(1)

#define MOUNT_POINT "/sdcard"
#define SPI_DMA_CHAN    1

#define USE_SPI_MODE 1

#ifdef USE_SPI_MODE
    // Pin mapping when using SPI mode.
    // With this mapping, SD card can be used both in SPI and 1-line SD mode.
    // Note that a pull-up on CS line is required in SD mode.
    #define PIN_NUM_MISO 2
    #define PIN_NUM_MOSI 15
    #define PIN_NUM_CLK  14
    #define PIN_NUM_CS   13
#endif //USE_SPI_MODE

/*-----------------------------------------------------------*/

/**
 * @brief Calculate and perform an exponential backoff with jitter delay for
 * the next retry attempt of a failed network operation with the server.
 *
 * The function generates a random number, calculates the next backoff period
 * with the generated random number, and performs the backoff delay operation if the
 * number of retries have not exhausted.
 *
 * @note The PKCS11 module is used to generate the random number as it allows access
 * to a True Random Number Generator (TRNG) if the vendor platform supports it.
 * It is recommended to seed the random number generator with a device-specific entropy
 * source so that probability of collisions from devices in connection retries is mitigated.
 *
 * @note The backoff period is calculated using the backoffAlgorithm library.
 *
 * @param[in, out] pxRetryAttempts The context to use for backoff period calculation
 * with the backoffAlgorithm library.
 *
 * @return pdPASS if calculating the backoff period was successful; otherwise pdFAIL
 * if there was failure in random number generation OR all retry attempts had exhausted.
 */
static BaseType_t prvBackoffForRetry( BackoffAlgorithmContext_t * pxRetryParams );

/**
 * @brief Connect to MQTT broker with reconnection retries.
 *
 * If connection fails, retry is attempted after a timeout.
 * Timeout value will exponentially increase until maximum
 * timeout value is reached or the number of attempts are exhausted.
 *
 * @param[out] pxNetworkContext The output parameter to return the created network context.
 *
 * @return pdFAIL on failure; pdPASS on successful TLS+TCP network connection.
 */
static BaseType_t prvConnectToServerWithBackoffRetries( NetworkContext_t * pNetworkContext );

/**
 * @brief Sends an MQTT Connect packet over the already connected TLS over TCP connection.
 *
 * @param[in, out] pxMQTTContext MQTT context pointer.
 * @param[in] xNetworkContext Network context.
 *
 * @return pdFAIL on failure; pdPASS on successful MQTT connection.
 */
static BaseType_t prvCreateMQTTConnectionWithBroker( MQTTContext_t * pxMQTTContext,
                                                     NetworkContext_t * pxNetworkContext );

/**
 * @brief Function to update variable #xTopicFilterContext with status
 * information from Subscribe ACK. Called by the event callback after processing
 * an incoming SUBACK packet.
 *
 * @param[in] Server response to the subscription request.
 */
static void prvUpdateSubAckStatus( MQTTPacketInfo_t * pxPacketInfo );

/**
 * @brief Publishes a message mqttexampleMESSAGE on mqttexampleTOPIC topic.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 *
 * @return pdFAIL on failure; pdPASS on successful PUBLISH operation.
 */
static BaseType_t prvMQTTPublishToTopic( MQTTContext_t * pxMQTTContext,
                                         const MQTTPublishInfo_t * pxMQTTPublishInfo );

/**
 * @brief The timer query function provided to the MQTT context.
 *
 * @return Time in milliseconds.
 */
static uint32_t prvGetTimeMs( void );

/**
 * @brief Process a response or ack to an MQTT request (PING, PUBLISH,
 * SUBSCRIBE or UNSUBSCRIBE). This function processes PINGRESP, PUBACK,
 * SUBACK, and UNSUBACK.
 *
 * @param[in] pxIncomingPacket is a pointer to structure containing deserialized
 * MQTT response.
 * @param[in] usPacketId is the packet identifier from the ack received.
 */
static void prvMQTTProcessResponse( MQTTPacketInfo_t * pxIncomingPacket,
                                    uint16_t usPacketId );

/**
 * @brief Process incoming Publish message.
 *
 * @param[in] pxPublishInfo is a pointer to structure containing deserialized
 * Publish message.
 */
static void prvMQTTProcessIncomingPublish( MQTTPublishInfo_t * pxPublishInfo );

/**
 * @brief The application callback function for getting the incoming publishes,
 * incoming acks, and ping responses reported from the MQTT library.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 * @param[in] pxPacketInfo Packet Info pointer for the incoming packet.
 * @param[in] pxDeserializedInfo Deserialized information from the incoming packet.
 */
static void prvEventCallback( MQTTContext_t * pxMQTTContext,
                              MQTTPacketInfo_t * pxPacketInfo,
                              MQTTDeserializedInfo_t * pxDeserializedInfo );

/**
 * @brief Helper function to wait for a specific incoming packet from the
 * broker.
 *
 * @param[in] pxMQTTContext MQTT context pointer.
 * @param[in] usPacketType Packet type to wait for.
 *
 * @return The return status from call to #MQTT_ProcessLoop API.
 */
static MQTTStatus_t prvWaitForPacket( MQTTContext_t * pxMQTTContext,
                                      uint16_t usPacketType );

static void imageProcessLoop();
/*-----------------------------------------------------------*/

/**
 * @brief Static buffer used to hold MQTT messages being sent and received.
 */
static uint8_t ucSharedBuffer[ democonfigNETWORK_BUFFER_SIZE ];

/**
 * @brief Global entry time into the application to use as a reference timestamp
 * in the #prvGetTimeMs function. #prvGetTimeMs will always return the difference
 * between the current time and the global entry time. This will reduce the chances
 * of overflow for the 32 bit unsigned integer used for holding the timestamp.
 */
static uint32_t ulGlobalEntryTimeMs;

/**
 * @brief Packet Identifier generated when Publish request was sent to the broker;
 * it is used to match received Publish ACK to the transmitted Publish packet.
 */
static uint16_t usPublishPacketIdentifier;

/**
 * @brief MQTT packet type received from the MQTT broker.
 *
 * @note Only on receiving incoming PUBLISH, SUBACK, and UNSUBACK, this
 * variable is updated. For MQTT packets PUBACK and PINGRESP, the variable is
 * not updated since there is no need to specifically wait for it in this demo.
 * A single variable suffices as this demo uses single task and requests one operation
 * (of PUBLISH, SUBSCRIBE, UNSUBSCRIBE) at a time before expecting response from
 * the broker. Hence it is not possible to receive multiple packets of type PUBLISH,
 * SUBACK, and UNSUBACK in a single call of #prvWaitForPacket.
 * For a multi task application, consider a different method to wait for the packet, if needed.
 */
static uint16_t usPacketTypeReceived = 0U;

/**
 * @brief A pair containing a topic filter and its SUBACK status.
 */
typedef struct topicFilterContext
{
    const char * pcTopicFilter;
    MQTTSubAckStatus_t xSubAckStatus;
} topicFilterContext_t;

/**
 * @brief An array containing the context of a SUBACK; the SUBACK status
 * of a filter is updated when the event callback processes a SUBACK.
 */
static topicFilterContext_t xTopicFilterContext[ mqttexampleTOPIC_COUNT ] =
{
    { mqttexampleTOPIC, MQTTSubAckFailure }
};


/** @brief Static buffer used to hold MQTT messages being sent and received. */
static MQTTFixedBuffer_t xBuffer =
{
    ucSharedBuffer,
    democonfigNETWORK_BUFFER_SIZE
};

static UBaseType_t motionDetected = pdFALSE;

/*-----------------------------------------------------------*/

#define EEPROM_SIZE 1

#define CAM_PIN_PWDN 32
#define CAM_PIN_RESET -1 //software reset will be performed
#define CAM_PIN_XCLK 0
#define CAM_PIN_SIOD 26
#define CAM_PIN_SIOC 27

#define CAM_PIN_D7 35
#define CAM_PIN_D6 34
#define CAM_PIN_D5 39
#define CAM_PIN_D4 36
#define CAM_PIN_D3 21
#define CAM_PIN_D2 19
#define CAM_PIN_D1 18
#define CAM_PIN_D0 5
#define CAM_PIN_VSYNC 25
#define CAM_PIN_HREF 23
#define CAM_PIN_PCLK 22

static camera_config_t camera_config = {
    .pin_pwdn = CAM_PIN_PWDN,
    .pin_reset = CAM_PIN_RESET,
    .pin_xclk = CAM_PIN_XCLK,
    .pin_sscb_sda = CAM_PIN_SIOD,
    .pin_sscb_scl = CAM_PIN_SIOC,

    .pin_d7 = CAM_PIN_D7,
    .pin_d6 = CAM_PIN_D6,
    .pin_d5 = CAM_PIN_D5,
    .pin_d4 = CAM_PIN_D4,
    .pin_d3 = CAM_PIN_D3,
    .pin_d2 = CAM_PIN_D2,
    .pin_d1 = CAM_PIN_D1,
    .pin_d0 = CAM_PIN_D0,
    .pin_vsync = CAM_PIN_VSYNC,
    .pin_href = CAM_PIN_HREF,
    .pin_pclk = CAM_PIN_PCLK,

    //XCLK 20MHz or 10MHz for OV2640 double FPS (Experimental)
    .xclk_freq_hz = 20000000,
    .ledc_timer = LEDC_TIMER_0,
    .ledc_channel = LEDC_CHANNEL_0,

    .pixel_format = PIXFORMAT_JPEG, //YUV422,GRAYSCALE,RGB565,JPEG
    .frame_size = FRAMESIZE_VGA,    //QQVGA-UXGA Do not use sizes above QVGA when not JPEG

    .jpeg_quality = 12, //0-63 lower number means higher quality
    .fb_count = 1       //if more than one, i2s runs in continuous mode. Use only with JPEG
};

static esp_err_t init_camera()
{
    //initialize the camera

    esp_err_t err = esp_camera_init(&camera_config);
    if (err != ESP_OK)
    {
        LogError(("Camera Init Failed"));
        return err;
    }

    return ESP_OK;
}

static wifi_config_t wifi_config = {
    .sta = {
        .ssid = CONFIG_EXAMPLE_WIFI_SSID,
        .password = CONFIG_EXAMPLE_WIFI_PASSWORD,
    },
};

#define WIFI_TAG "wifi"

static void on_wifi_disconnect(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    ESP_LOGI(WIFI_TAG, "Wi-Fi disconnected...");
}

static void on_wifi_connect(void *esp_netif, esp_event_base_t event_base,
                            int32_t event_id, void *event_data)
{
    esp_netif_create_ip6_linklocal(esp_netif);
}

static EventGroupHandle_t s_connect_event_group;

static void on_got_ip(void *arg, esp_event_base_t event_base,
                      int32_t event_id, void *event_data)
{
    ESP_LOGI(WIFI_TAG, "Got IP event!");
    xEventGroupSetBits(s_connect_event_group, GOT_IPV4_BIT);
}

static void on_got_ipv6(void *arg, esp_event_base_t event_base,
                        int32_t event_id, void *event_data)
{
    ESP_LOGI(WIFI_TAG, "Got IPv6 event!");
    xEventGroupSetBits(s_connect_event_group, GOT_IPV6_BIT);
}

static void connect_wifi()
{
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_netif_config_t netif_config = ESP_NETIF_DEFAULT_WIFI_STA();

    esp_netif_t *netif = esp_netif_new(&netif_config);
    assert(netif);

    esp_netif_attach_wifi_station(netif);
    esp_wifi_set_default_wifi_sta_handlers();

    s_connect_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &on_wifi_disconnect, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &on_got_ip, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, &on_wifi_connect, netif));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, &on_got_ipv6, NULL));

    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_LOGI("wifi", "Connecting to %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_connect());

    xEventGroupWaitBits(s_connect_event_group, (GOT_IPV4_BIT | GOT_IPV6_BIT), true, true, portMAX_DELAY);
}

#define SD_TAG "SD"

static void init_sdcard()
{
    ESP_LOGI(SD_TAG, "Initializing SD card");

#ifndef USE_SPI_MODE
    ESP_LOGI(SD_TAG, "Using SDMMC peripheral");
    sdmmc_host_t host = SDMMC_HOST_DEFAULT();

    // This initializes the slot without card detect (CD) and write protect (WP) signals.
    // Modify slot_config.gpio_cd and slot_config.gpio_wp if your board has these signals.
    sdmmc_slot_config_t slot_config = SDMMC_SLOT_CONFIG_DEFAULT();

    // To use 1-line SD mode, uncomment the following line:
    // slot_config.width = 1;

    // GPIOs 15, 2, 4, 12, 13 should have external 10k pull-ups.
    // Internal pull-ups are not sufficient. However, enabling internal pull-ups
    // does make a difference some boards, so we do that here.
    gpio_set_pull_mode(15, GPIO_PULLUP_ONLY);   // CMD, needed in 4- and 1- line modes
    gpio_set_pull_mode(2, GPIO_PULLUP_ONLY);    // D0, needed in 4- and 1-line modes
    gpio_set_pull_mode(4, GPIO_PULLUP_ONLY);    // D1, needed in 4-line mode only
    gpio_set_pull_mode(12, GPIO_PULLUP_ONLY);   // D2, needed in 4-line mode only
    gpio_set_pull_mode(13, GPIO_PULLUP_ONLY);   // D3, needed in 4- and 1-line modes

#else
    ESP_LOGI(SD_TAG, "Using SPI peripheral");

    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    sdspi_slot_config_t slot_config = SDSPI_SLOT_CONFIG_DEFAULT();
    slot_config.gpio_miso = PIN_NUM_MISO;
    slot_config.gpio_mosi = PIN_NUM_MOSI;
    slot_config.gpio_sck  = PIN_NUM_CLK;
    slot_config.gpio_cs   = PIN_NUM_CS;
    // This initializes the slot without card detect (CD) and write protect (WP) signals.
    // Modify slot_config.gpio_cd and slot_config.gpio_wp if your board has these signals.
#endif //USE_SPI_MODE

    // Options for mounting the filesystem.
    // If format_if_mount_failed is set to true, SD card will be partitioned and
    // formatted in case when mounting fails.
    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = false,
        .max_files = 5,
        .allocation_unit_size = 16 * 1024
    };

    // Use settings defined above to initialize SD card and mount FAT filesystem.
    // Note: esp_vfs_fat_sdmmc_mount is an all-in-one convenience function.
    // Please check its source code and implement error recovery when developing
    // production applications.
    sdmmc_card_t* card;
    esp_err_t ret = esp_vfs_fat_sdmmc_mount("/sdcard", &host, &slot_config, &mount_config, &card);

    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(SD_TAG, "Failed to mount filesystem. "
                "If you want the card to be formatted, set format_if_mount_failed = true.");
        } else {
            ESP_LOGE(SD_TAG, "Failed to initialize the card (%s). "
                "Make sure SD card lines have pull-up resistors in place.", esp_err_to_name(ret));
        }
        return;
    }

    // Card has been initialized, print its properties
    sdmmc_card_print_info(stdout, card);
}

static void IRAM_ATTR gpio_isr_handler(void* arg)
{
    motionDetected = pdFALSE;
}

#define PIR_SENSOR_PORT 13

void register_gpio_negedge_event( void )
{
    gpio_config_t io_conf;

    /* Setup GPIO to read input from the PIR sensor. */
    io_conf.pin_bit_mask = (1ULL << PIR_SENSOR_PORT);
    io_conf.mode = GPIO_MODE_INPUT;
    io_conf.pull_up_en = GPIO_PULLUP_ENABLE;
    io_conf.intr_type = GPIO_INTR_NEGEDGE;
    gpio_config(&io_conf);
    gpio_isr_handler_add(PIR_SENSOR_PORT, gpio_isr_handler, (void*) PIR_SENSOR_PORT);
}

void wakeUpFromMotionDetection( void )
{
    /* Initialize the camera before configuring GPIO because
       the camera installs the GPIO service first. */
    if(init_camera() != ESP_OK)
    {
        LogError(("Camera init failed"));
        return;
    }
    register_gpio_negedge_event();
    connect_wifi();
    imageProcessLoop();
}

void app_main( void )
{
    ESP_ERROR_CHECK( nvs_flash_init() );
    ESP_ERROR_CHECK( esp_netif_init() );
    ESP_ERROR_CHECK( esp_event_loop_create_default() );

    switch (esp_sleep_get_wakeup_cause()) {
        case ESP_SLEEP_WAKEUP_EXT0:
            LogInfo(("Detected motion."));
            motionDetected = pdTRUE;
            wakeUpFromMotionDetection();
            break;
        case ESP_SLEEP_WAKEUP_TIMER:
            // TODO: A timer could be used to send uploads that were previously saved to SD card.
            break;
        case ESP_SLEEP_WAKEUP_UNDEFINED:
        default:
            LogInfo(("Just booted..."));
            break;
    }

    /* Set GPIO13 to wake up the ESP when input is high */
    rtc_gpio_init(PIR_SENSOR_PORT);
    rtc_gpio_set_direction(PIR_SENSOR_PORT, RTC_GPIO_MODE_INPUT_ONLY);
    rtc_gpio_pulldown_en(PIR_SENSOR_PORT);
    rtc_gpio_wakeup_enable(PIR_SENSOR_PORT, GPIO_INTR_HIGH_LEVEL);
    rtc_gpio_isolate(GPIO_NUM_12);
    esp_sleep_enable_ext0_wakeup(PIR_SENSOR_PORT, 1);

    LogInfo(("Entering deep sleep."));
    esp_wifi_stop();
    esp_deep_sleep_start();
}
/*-----------------------------------------------------------*/

typedef struct imageBuffer {
    uint8_t* buf;
    size_t len;
} imageFrame_t;

#define NUM_IMAGE_FRAMES 1

static QueueHandle_t xImageFramesQueue = NULL;

static void publishImagesRoutine( void * pParameters )
{
    NetworkContext_t xNetworkContext = { 0 };
    MQTTContext_t xMQTTContext = { 0 };
    MQTTPublishInfo_t xMQTTPublishInfo = { 0 };
    MQTTStatus_t xMQTTStatus;
    BaseType_t xIsConnectionEstablished = pdFALSE;
    /* Upon return, pdPASS will indicate a successful demo execution.
    * pdFAIL will indicate some failures occurred during execution. The
    * user of this demo must check the logs for any failure codes. */
    BaseType_t xStatus = pdFAIL;

    ( void ) pParameters;

    imageFrame_t imageFrame;

    /* QoS1 should be sufficient because we don't care if subscribers of the topic receive the image. */
    xMQTTPublishInfo.qos = MQTTQoS1;
    xMQTTPublishInfo.retain = false;
    xMQTTPublishInfo.pTopicName = mqttexampleTOPIC;
    xMQTTPublishInfo.topicNameLength = ( uint16_t ) strlen( mqttexampleTOPIC );

    for( ; ; )
    {
        /********************************** Connect. *****************************************/
        if(!xIsConnectionEstablished) {
            /* Attempt to establish TLS session with MQTT broker. If connection fails,
            * retry after a timeout. Timeout value will be exponentially increased until
            * the maximum number of attempts are reached or the maximum timeout value is reached.
            * The function returns a failure status if the TLS over TCP connection cannot be established
            * to the broker after the configured number of attempts. */
            xStatus = prvConnectToServerWithBackoffRetries( &xNetworkContext );

            if( xStatus == pdPASS )
            {
                /* Set a flag indicating a TLS connection exists. This is done to
                * disconnect if the loop exits before disconnection happens. */
                xIsConnectionEstablished = pdTRUE;

                /* Sends an MQTT Connect packet over the already established TLS connection,
                * and waits for connection acknowledgment (CONNACK) packet. */
                LogInfo( ( "Creating an MQTT connection to %s.", democonfigMQTT_BROKER_ENDPOINT ) );
                xStatus = prvCreateMQTTConnectionWithBroker( &xMQTTContext, &xNetworkContext );
            }

            if( xStatus == pdFAIL )
            {
                esp_tls_conn_delete( xNetworkContext.pTlsContext );
                xIsConnectionEstablished = pdFALSE;
            }
        }

        /************************* Send image over MQTT. ***************************************/
        /* If there are no requests in the dispatch queue, try again. */
        if( xQueueReceive( xImageFramesQueue,
                           &imageFrame,
                           portMAX_DELAY ) == pdFALSE )
        {
            if( motionDetected ) {
                /* The camera is still reading images. */ 
                continue;
            } else {
                break;
            }
        }

        /* Set the entry time of the demo application. This entry time will be used
        * to calculate relative time elapsed in the execution of the demo application,
        * by the timer utility function that is provided to the MQTT library.
        */
        ulGlobalEntryTimeMs = prvGetTimeMs();

        if(xIsConnectionEstablished) {
            LogInfo( ( "Publish %d byte jpeg image to the MQTT topic %s.", imageFrame.len, mqttexampleTOPIC ) );
            xMQTTPublishInfo.pPayload = imageFrame.buf;
            xMQTTPublishInfo.payloadLength = imageFrame.len;

            xStatus = prvMQTTPublishToTopic( &xMQTTContext, &xMQTTPublishInfo );

            if( xStatus == pdPASS )
            {
                /* The PUBACK for the outgoing PUBLISH will be received here. */
                xMQTTStatus = prvWaitForPacket( &xMQTTContext, MQTT_PACKET_TYPE_PUBLISH );

                if( xMQTTStatus != MQTTSuccess )
                {
                    xStatus = pdFAIL;
                }
            }

            if(xStatus == pdFAIL) {
                esp_tls_conn_delete( xNetworkContext.pTlsContext );
                xIsConnectionEstablished = pdFALSE;
            }
        } else {
            /* TODO: Save to SD card whenever the connection is no longer established. */
        }

        free(imageFrame.buf);
    }

    /* Terminating condition is when no more motion has been detected and
     * all images have been sent. Although, it is possible that sends take
     * a very long time, then the Yeti comes while the sends are happening.
     * This assumes that sends happen very quickly (for now). */

    /**************************** Disconnect. ******************************/

    if( xStatus == pdPASS )
    {
        /* Send an MQTT Disconnect packet over the already connected TLS over TCP connection.
         * There is no corresponding response for the disconnect packet. After sending
         * disconnect, client must close the network connection. */
        LogInfo( ( "Disconnecting the MQTT connection with %s.", democonfigMQTT_BROKER_ENDPOINT ) );
        xMQTTStatus = MQTT_Disconnect( &xMQTTContext );
    }

    /* We will always close the network connection, even if an error may have occurred during
     * demo execution, to clean up the system resources that it may have consumed. */
    if( xIsConnectionEstablished == pdTRUE )
    {
        /* Close the network connection.  */
        esp_tls_conn_delete( xNetworkContext.pTlsContext );
    }

    vTaskDelete(NULL);
}

static TaskHandle_t xSendImagesTaskHandle = NULL;

static void imageProcessLoop()
{
    /* Upon return, pdPASS will indicate a successful demo execution.
    * pdFAIL will indicate some failures occurred during execution. The
    * user of this demo must check the logs for any failure codes. */
    BaseType_t xStatus = pdFAIL;

    //init_sdcard();

    xImageFramesQueue = xQueueCreate( NUM_IMAGE_FRAMES, sizeof( imageFrame_t ) );
    xStatus = xTaskCreatePinnedToCore( publishImagesRoutine,
                            "publishImagesRoutine",
                            8192,
                            NULL,
                            3,
                            &xSendImagesTaskHandle,
                            0 );

    if(xStatus == pdFAIL)
    {
        LogError(("Failed to allocate publishImagesRoutine task."));
        return;
    }

    while( motionDetected )
    {
        /************************ Save and queue jpeg frames. ******************************/

        /* Save jpeg frames to a buffer while motion is detected. If buffer space is fully consumed,
         * try to publish images over MQTT first until buffer space is available again (in a separate task). */
        camera_fb_t *fb = esp_camera_fb_get();
        imageFrame_t imageFrame;
        uint8_t* buffer = NULL;

        if(fb)
        {
            buffer = (uint8_t*)malloc(fb->len);
            if(buffer == NULL) {
                vTaskDelay(pdMS_TO_TICKS(250U));
            } else {
                imageFrame.buf = buffer;
                memcpy(imageFrame.buf, fb->buf, fb->len);
                imageFrame.len = fb->len;
                /* Return the frame for the camera library to reuse. */
                esp_camera_fb_return(fb);
                xQueueSendToBack(xImageFramesQueue, &imageFrame, pdMS_TO_TICKS(200));
            }
        }
        else
        {
            LogError(("Failed to take picture."));
        }

        /* I guess a Yeti isn't that fast :) */
        vTaskDelay(pdMS_TO_TICKS( 250U ));
    }
}
/*-----------------------------------------------------------*/

static BaseType_t prvBackoffForRetry( BackoffAlgorithmContext_t * pxRetryParams )
{
    BaseType_t xReturnStatus = pdFAIL;
    uint16_t usNextRetryBackOff = 0U;
    BackoffAlgorithmStatus_t xBackoffAlgStatus = BackoffAlgorithmSuccess;

    /**
     * To calculate the backoff period for the next retry attempt, we will
     * generate a random number to provide to the backoffAlgorithm library.
     */
    uint32_t ulRandomNum = 0;

    ulRandomNum = esp_random();

    /* Get back-off value (in milliseconds) for the next retry attempt. */
    xBackoffAlgStatus = BackoffAlgorithm_GetNextBackoff( pxRetryParams, ulRandomNum, &usNextRetryBackOff );

    if( xBackoffAlgStatus == BackoffAlgorithmRetriesExhausted )
    {
        LogError( ( "All retry attempts have exhausted. Operation will not be retried" ) );
    }
    else if( xBackoffAlgStatus == BackoffAlgorithmSuccess )
    {
        /* Perform the backoff delay. */
        vTaskDelay( pdMS_TO_TICKS( usNextRetryBackOff ) );

        xReturnStatus = pdPASS;

        LogInfo( ( "Retry attempt %u out of maximum retry attempts %u.",
                    ( pxRetryParams->attemptsDone + 1 ),
                    pxRetryParams->maxRetryAttempts ) );
    }

    return xReturnStatus;
}

/*-----------------------------------------------------------*/

static BaseType_t prvConnectToServerWithBackoffRetries( NetworkContext_t * pxNetworkContext )
{
    BaseType_t xStatus = pdPASS;
    int xNetworkStatus = -1;
    BackoffAlgorithmContext_t xReconnectParams;
    BaseType_t xBackoffStatus = pdFALSE;
    esp_tls_t *tls_conn;

    esp_tls_cfg_t tls_cfg = {
            .cacert_buf  = ( const unsigned char * )democonfigROOT_CA_PEM,
            .cacert_bytes = sizeof( democonfigROOT_CA_PEM ),
            .clientcert_buf = ( const unsigned char * )keyCLIENT_CERTIFICATE_PEM,
            .clientcert_bytes = sizeof( keyCLIENT_CERTIFICATE_PEM ),
            .clientkey_buf = ( const unsigned char * )keyCLIENT_PRIVATE_KEY_PEM,
            .clientkey_bytes = sizeof( keyCLIENT_PRIVATE_KEY_PEM ),
            .timeout_ms = mqttexampleTRANSPORT_SEND_RECV_TIMEOUT_MS,
        };

    /* Initialize reconnect attempts and interval. */
    BackoffAlgorithm_InitializeParams( &xReconnectParams,
                                       RETRY_BACKOFF_BASE_MS,
                                       RETRY_MAX_BACKOFF_DELAY_MS,
                                       RETRY_MAX_ATTEMPTS );

    tls_conn = esp_tls_init();
    /* Attempt to connect to MQTT broker. If connection fails, retry after
     * a timeout. Timeout value will exponentially increase till maximum
     * attempts are reached.
     */
    do
    {
        /* Establish a TLS session with the MQTT broker. This example connects to
         * the MQTT broker as specified in democonfigMQTT_BROKER_ENDPOINT and
         * democonfigMQTT_BROKER_PORT at the top of this file. */
        LogInfo( ( "Creating a TLS connection to %s:%u.",
                   democonfigMQTT_BROKER_ENDPOINT,
                   democonfigMQTT_BROKER_PORT ) );
        /* Attempt to create a mutually authenticated TLS connection. */
        xNetworkStatus = esp_tls_conn_new_sync( democonfigMQTT_BROKER_ENDPOINT,
                                                strlen( democonfigMQTT_BROKER_ENDPOINT ),
                                                democonfigMQTT_BROKER_PORT,
                                                &( tls_cfg ),
                                                tls_conn );

        if( xNetworkStatus != 1 )
        {
            LogWarn( ( "Connection to the broker failed with error %d. Attempting connection retry after backoff delay.", xNetworkStatus ) );

            /* As the connection attempt failed, we will retry the connection after an
             * exponential backoff with jitter delay. */

            /* Calculate the backoff period for the next retry attempt and perform the wait operation. */
            xBackoffStatus = prvBackoffForRetry( &xReconnectParams );
        }
        else
        {
            pxNetworkContext->pTlsContext = tls_conn;
        }
        
    } while( ( xNetworkStatus != 1 ) && ( xBackoffStatus == pdPASS ) );

    return xStatus;
}
/*-----------------------------------------------------------*/

static BaseType_t prvCreateMQTTConnectionWithBroker( MQTTContext_t * pxMQTTContext,
                                                     NetworkContext_t * pxNetworkContext )
{
    MQTTStatus_t xResult;
    MQTTConnectInfo_t xConnectInfo;
    bool xSessionPresent;
    TransportInterface_t xTransport;
    BaseType_t xStatus = pdFAIL;

    /* Fill in Transport Interface send and receive function pointers. */
    xTransport.pNetworkContext = pxNetworkContext;
    xTransport.send = EspTls_Send;
    xTransport.recv = EspTls_Recv;

    /* Initialize MQTT library. */
    xResult = MQTT_Init( pxMQTTContext, &xTransport, prvGetTimeMs, prvEventCallback, &xBuffer );
    configASSERT( xResult == MQTTSuccess );

    /* Some fields are not used in this demo so start with everything at 0. */
    ( void ) memset( ( void * ) &xConnectInfo, 0x00, sizeof( xConnectInfo ) );

    /* Start with a clean session i.e. direct the MQTT broker to discard any
     * previous session data. Also, establishing a connection with clean session
     * will ensure that the broker does not store any data when this client
     * gets disconnected. */
    xConnectInfo.cleanSession = true;

    /* The client identifier is used to uniquely identify this MQTT client to
     * the MQTT broker. In a production device the identifier can be something
     * unique, such as a device serial number. */
    xConnectInfo.pClientIdentifier = democonfigCLIENT_IDENTIFIER;
    xConnectInfo.clientIdentifierLength = ( uint16_t ) strlen( democonfigCLIENT_IDENTIFIER );

    /* Set MQTT keep-alive period. If the application does not send packets at an interval less than
     * the keep-alive period, the MQTT library will send PINGREQ packets. */
    xConnectInfo.keepAliveSeconds = mqttexampleKEEP_ALIVE_TIMEOUT_SECONDS;

    /* Send MQTT CONNECT packet to broker. LWT is not used in this demo, so it
     * is passed as NULL. */
    xResult = MQTT_Connect( pxMQTTContext,
                            &xConnectInfo,
                            NULL,
                            mqttexampleCONNACK_RECV_TIMEOUT_MS,
                            &xSessionPresent );

    if( xResult != MQTTSuccess )
    {
        LogError( ( "Failed to establish MQTT connection: Server=%s, MQTTStatus=%s",
                    democonfigMQTT_BROKER_ENDPOINT, MQTT_Status_strerror( xResult ) ) );
    }
    else
    {
        /* Successfully established and MQTT connection with the broker. */
        LogInfo( ( "An MQTT connection is established with %s.", democonfigMQTT_BROKER_ENDPOINT ) );
        xStatus = pdPASS;
    }

    return xStatus;
}
/*-----------------------------------------------------------*/

static void prvUpdateSubAckStatus( MQTTPacketInfo_t * pxPacketInfo )
{
    MQTTStatus_t xResult = MQTTSuccess;
    uint8_t * pucPayload = NULL;
    size_t ulSize = 0;
    uint32_t ulTopicCount = 0U;

    xResult = MQTT_GetSubAckStatusCodes( pxPacketInfo, &pucPayload, &ulSize );

    /* MQTT_GetSubAckStatusCodes always returns success if called with packet info
     * from the event callback and non-NULL parameters. */
    configASSERT( xResult == MQTTSuccess );

    for( ulTopicCount = 0; ulTopicCount < ulSize; ulTopicCount++ )
    {
        xTopicFilterContext[ ulTopicCount ].xSubAckStatus = pucPayload[ ulTopicCount ];
    }
}
/*-----------------------------------------------------------*/

static BaseType_t prvMQTTPublishToTopic( MQTTContext_t * pxMQTTContext,
                                         const MQTTPublishInfo_t * pxMQTTPublishInfo )
{
    MQTTStatus_t xResult;

    BaseType_t xStatus = pdPASS;

    /* Get a unique packet id. */
    usPublishPacketIdentifier = MQTT_GetPacketId( pxMQTTContext );

    /* Send PUBLISH packet. Packet ID is not used for a QoS1 publish. */
    xResult = MQTT_Publish( pxMQTTContext, pxMQTTPublishInfo, usPublishPacketIdentifier );

    if( xResult != MQTTSuccess )
    {
        xStatus = pdFAIL;
        LogError( ( "Failed to send PUBLISH message to broker: Topic=%s, Error=%s",
                    mqttexampleTOPIC,
                    MQTT_Status_strerror( xResult ) ) );
    }

    return xStatus;
}
/*-----------------------------------------------------------*/

static void prvMQTTProcessResponse( MQTTPacketInfo_t * pxIncomingPacket,
                                    uint16_t usPacketId )
{
    uint32_t ulTopicCount = 0U;

    switch( pxIncomingPacket->type )
    {
        case MQTT_PACKET_TYPE_PUBACK:
            LogInfo( ( "PUBACK received for packet Id %u.", usPacketId ) );
            break;

        case MQTT_PACKET_TYPE_SUBACK:

            /* Update the packet type received to SUBACK. */
            usPacketTypeReceived = MQTT_PACKET_TYPE_SUBACK;

            /* A SUBACK from the broker, containing the server response to our subscription request, has been received.
             * It contains the status code indicating server approval/rejection for the subscription to the single topic
             * requested. The SUBACK will be parsed to obtain the status code, and this status code will be stored in global
             * variable #xTopicFilterContext. */
            prvUpdateSubAckStatus( pxIncomingPacket );

            for( ulTopicCount = 0; ulTopicCount < mqttexampleTOPIC_COUNT; ulTopicCount++ )
            {
                if( xTopicFilterContext[ ulTopicCount ].xSubAckStatus != MQTTSubAckFailure )
                {
                    LogInfo( ( "Subscribed to the topic %s with maximum QoS %u.",
                               xTopicFilterContext[ ulTopicCount ].pcTopicFilter,
                               xTopicFilterContext[ ulTopicCount ].xSubAckStatus ) );
                }
            }
            break;

        case MQTT_PACKET_TYPE_UNSUBACK:
            LogInfo( ( "Unsubscribed from the topic %s.", mqttexampleTOPIC ) );

            /* Update the packet type received to UNSUBACK. */
            usPacketTypeReceived = MQTT_PACKET_TYPE_UNSUBACK;
            break;

        case MQTT_PACKET_TYPE_PINGRESP:
            LogInfo( ( "Ping Response successfully received." ) );
            break;

        /* Any other packet type is invalid. */
        default:
            LogWarn( ( "prvMQTTProcessResponse() called with unknown packet type:(%02X).",
                       pxIncomingPacket->type ) );
    }
}

/*-----------------------------------------------------------*/

static void prvMQTTProcessIncomingPublish( MQTTPublishInfo_t * pxPublishInfo )
{
    configASSERT( pxPublishInfo != NULL );

    /* Set the global for indicating that an incoming publish is received. */
    usPacketTypeReceived = MQTT_PACKET_TYPE_PUBLISH;

    /* Process incoming Publish. */
    LogInfo( ( "Incoming QoS: %d", pxPublishInfo->qos ) );

    /* Verify the received publish is for the we have subscribed to. */
    if( ( pxPublishInfo->topicNameLength == strlen( mqttexampleTOPIC ) ) &&
        ( 0 == strncmp( mqttexampleTOPIC, pxPublishInfo->pTopicName, pxPublishInfo->topicNameLength ) ) )
    {
        LogInfo( ( "Incoming Publish Topic Name: %.*s matches subscribed topic."
                   "Incoming Publish Message: %.*s",
                   pxPublishInfo->topicNameLength,
                   pxPublishInfo->pTopicName,
                   pxPublishInfo->payloadLength,
                   ( const char * )pxPublishInfo->pPayload ) );
    }
    else
    {
        LogInfo( ( "Incoming Publish Topic Name: %.*s does not match subscribed topic.",
                   pxPublishInfo->topicNameLength,
                   pxPublishInfo->pTopicName ) );
    }
}

/*-----------------------------------------------------------*/

static void prvEventCallback( MQTTContext_t * pxMQTTContext,
                              MQTTPacketInfo_t * pxPacketInfo,
                              MQTTDeserializedInfo_t * pxDeserializedInfo )
{
    /* The MQTT context is not used for this demo. */
    ( void ) pxMQTTContext;

    if( ( pxPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
        prvMQTTProcessIncomingPublish( pxDeserializedInfo->pPublishInfo );
    }
    else
    {
        prvMQTTProcessResponse( pxPacketInfo, pxDeserializedInfo->packetIdentifier );
    }
}

/*-----------------------------------------------------------*/

static uint32_t prvGetTimeMs( void )
{
    TickType_t xTickCount = 0;
    uint32_t ulTimeMs = 0UL;

    /* Get the current tick count. */
    xTickCount = xTaskGetTickCount();

    /* Convert the ticks to milliseconds. */
    ulTimeMs = ( uint32_t ) xTickCount * MILLISECONDS_PER_TICK;

    /* Reduce ulGlobalEntryTimeMs from obtained time so as to always return the
     * elapsed time in the application. */
    ulTimeMs = ( uint32_t ) ( ulTimeMs - ulGlobalEntryTimeMs );

    return ulTimeMs;
}

/*-----------------------------------------------------------*/

static MQTTStatus_t prvWaitForPacket( MQTTContext_t * pxMQTTContext,
                                      uint16_t usPacketType )
{
    MQTTStatus_t xMQTTStatus = MQTTSuccess;

    /* Reset the packet type received. */
    usPacketTypeReceived = 0U;

    /* Event callback will set #usPacketTypeReceived when receiving appropriate packet. This
     * will wait for at most mqttexamplePROCESS_LOOP_TIMEOUT_MS. */
    xMQTTStatus = MQTT_ProcessLoop( pxMQTTContext, mqttexamplePROCESS_LOOP_TIMEOUT_MS );

    if( xMQTTStatus != MQTTSuccess )
    {
        LogError( ( "MQTT_ProcessLoop failed to receive acknowledgement." ) );
    }

    return xMQTTStatus;
}

/*-----------------------------------------------------------*/
