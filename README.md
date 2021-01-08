# The Yeti Cam

## Searching for the 8th wonder of the world

This demo uses a PIR sensor to detect motion and once detected, an ESP32
will wake up to take a jpeg-encoded image that is sent over an MQTT topic that
forwards the data to upload that image to S3.
