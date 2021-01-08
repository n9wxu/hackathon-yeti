# Embed the server root certificate into the final binary
#
# (If this was a component, we would set COMPONENT_EMBED_TXTFILES here.)
idf_component_register( SRCS "mqtt_demo_yeti_cam.c"
                             "esp_tls_transport.c"
                             "../coreMQTT/source/core_mqtt.c"
                             "../coreMQTT/source/core_mqtt_state.c"
                             "../coreMQTT/source/core_mqtt_serializer.c"
                             "../backoffAlgorithm/source/backoff_algorithm.c"
                        INCLUDE_DIRS "."
                                     "../coreMQTT/source/include"
                                     "../coreMQTT/source/interface"
                                     "../backoffAlgorithm/source/include" )