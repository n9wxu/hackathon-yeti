# The Yeti Cam

![Yeti Cam Circuit Diagram](assets/circuit.jpg)

## Searching for the 8th wonder of the world

This demo uses a PIR sensor so that when motion is detected, an ESP32 CAM
will wake up from deep-sleep mode. When awoken, jpeg-encoded images are taken
while motion is detected or the maximum buffer size is consumed. After which,
the images are published to an MQTT topic in AWS IoT with a rule set to
upload those images to S3.

### Build Instructions

Install [esp-idf](https://github.com/espressif/esp-idf) and run the usual command
for flashing and monitoring an ESP board in the root directory
```
idf.py flash monitor -p$USB_PORT
```
