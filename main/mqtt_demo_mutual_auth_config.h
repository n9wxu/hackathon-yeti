/*
 * FreeRTOS V202010.00
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

#ifndef MQTT_DEMO_MUTUAL_AUTH_CONFIG_H
#define MQTT_DEMO_MUTUAL_AUTH_CONFIG_H

#include "esp_log.h"

#define EXTRACT_ARGS( ... ) __VA_ARGS__
#define STRIP_PARENS( X )   X
#define REMOVE_PARENS( X )  STRIP_PARENS( EXTRACT_ARGS X )

/* Logging configuration. */
#ifndef LogError
    #define LogError( message ) ESP_LOGE( "coreMQTT Demo", REMOVE_PARENS( message ) )
#endif

#ifndef LogWarn
    #define LogWarn( message )  ESP_LOGW( "coreMQTT Demo", REMOVE_PARENS( message ) )
#endif

#ifndef LogInfo
    #define LogInfo( message )  ESP_LOGI( "coreMQTT Demo", REMOVE_PARENS( message ) )
#endif

#ifndef LogDebug
    #define LogDebug( message ) ESP_LOGD( "coreMQTT Demo", REMOVE_PARENS( message ) )
#endif

/**
 * To use this demo, please configure the client's certificate and private key
 * in demos/include/aws_clientcredential_keys.h.
 * 
 * For the AWS IoT MQTT broker, refer to the AWS documentation below for details
 * regarding client authentication.
 * https://docs.aws.amazon.com/iot/latest/developerguide/client-authentication.html
 */

/**
 * @brief The MQTT client identifier used in this example.  Each client identifier
 * must be unique; so edit as required to ensure that no two clients connecting to
 * the same broker use the same client identifier.
 *
 * #define democonfigCLIENT_IDENTIFIER    "insert here."
 */

/**
 * @brief Endpoint of the MQTT broker to connect to.
 *
 * This demo application can be run with any MQTT broker, that supports mutual
 * authentication.
 *
 * For AWS IoT MQTT broker, this is the Thing's REST API Endpoint.
 *
 * @note Your AWS IoT Core endpoint can be found in the AWS IoT console under
 * Settings/Custom Endpoint, or using the describe-endpoint REST API (with
 * AWS CLI command line tool).
 *
 * #define democonfigMQTT_BROKER_ENDPOINT    "...insert here..."
 */

/**
 * @brief The port to use for the demo.
 *
 * In general, port 8883 is for secured MQTT connections.
 *
 * @note Port 443 requires use of the ALPN TLS extension with the ALPN protocol
 * name. When using port 8883, ALPN is not required.
 *
 * #define democonfigMQTT_BROKER_PORT    "...insert here..."
 */

/**
 * @brief Server's root CA certificate.
 *
 * For AWS IoT MQTT broker, this certificate is used to identify the AWS IoT
 * server and is publicly available. Refer to the AWS documentation available
 * in the link below.
 * https://docs.aws.amazon.com/iot/latest/developerguide/server-authentication.html#server-authentication-certs
 *
 * @note This certificate should be PEM-encoded.
 *
 * Must include the PEM header and footer:
 * "-----BEGIN CERTIFICATE-----\n"\
 * "...base64 data...\n"\
 * "-----END CERTIFICATE-----\n"
 *
 * #define democonfigROOT_CA_PEM    "...insert here..."
 */

/**
 * @brief Size of the network buffer for MQTT packets.
 */
#define democonfigNETWORK_BUFFER_SIZE    ( 1024U )

/**
 * @brief The maximum number of times to run the subscribe publish loop in the
 * demo.
 *
 * #define democonfigMQTT_MAX_DEMO_COUNT    ( insert here )
 */

#endif /* MQTT_DEMO_MUTUAL_AUTH_CONFIG_H */
