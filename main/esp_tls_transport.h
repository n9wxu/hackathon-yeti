#ifndef ESP_TLS_TRANSPORT_H_
#define ESP_TLS_TRANSPORT_H_

#include "transport_interface.h"
#include "esp_tls.h"

struct NetworkContext
{
    esp_tls_t *pTlsContext;
};

int32_t EspTls_Recv( NetworkContext_t * pNetworkContext,
                     void * pBuffer,
                     size_t bytesToRecv );

int32_t EspTls_Send( NetworkContext_t * pNetworkContext,
                     const void * pBuffer,
                     size_t bytesToSend );

#endif /* ESP_TLS_TRANSPORT_H_ */
