#include "esp_tls_transport.h"

int32_t EspTls_Recv( NetworkContext_t * pNetworkContext,
                     void * pBuffer,
                     size_t bytesToRecv )
{
    ssize_t tlsStatus;

    tlsStatus = esp_tls_conn_read( pNetworkContext->pTlsContext,
                                   pBuffer,
                                   bytesToRecv );

    /* Mark these set of errors as a timeout. The libraries may retry read
     * on these errors. */
    if( ( tlsStatus == MBEDTLS_ERR_SSL_TIMEOUT ) ||
        ( tlsStatus == MBEDTLS_ERR_SSL_WANT_READ ) ||
        ( tlsStatus == MBEDTLS_ERR_SSL_WANT_WRITE ) )
    {
        tlsStatus = 0;
    }

    return tlsStatus;
}
/*-----------------------------------------------------------*/

int32_t EspTls_Send( NetworkContext_t * pNetworkContext,
                     const void * pBuffer,
                     size_t bytesToSend )
{
    ssize_t tlsStatus;

    tlsStatus = esp_tls_conn_write( pNetworkContext->pTlsContext,
                                    pBuffer,
                                    bytesToSend );


    /* Mark these set of errors as a timeout. The libraries may retry read
     * on these errors. */
    if( ( tlsStatus == MBEDTLS_ERR_SSL_TIMEOUT ) ||
        ( tlsStatus == MBEDTLS_ERR_SSL_WANT_READ ) ||
        ( tlsStatus == MBEDTLS_ERR_SSL_WANT_WRITE ) )
    {
        tlsStatus = 0;
    }

    return tlsStatus;
}
/*-----------------------------------------------------------*/
