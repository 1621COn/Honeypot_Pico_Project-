#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "hardware/gpio.h"
#include "hardware/pio.h"
#include "hardware/i2c.h"
#include "alarm.pio.h"
#define LED_PIN 13U
#define ON 1U
#define OFF 0U
#define PORT 80U
#define DHCP_PORT_SERVER 67U
#define DHCP_PORT_CLIENT 68U
#define WIFI_SSID     "WIFI_SSID"
#define WIFI_PASSWORD "WIFI_PASSWORD"
#define BUFFER_SIZE 128U
#define IP_ADDRESS_BUFFER 16U
#define FLASH_TARGET_OFFSET (1984U * 1024U)
#define SECTOR_PAYLOAD_SIZE FLASH_SECTOR_SIZE 
#define I2C_PORT i2c0
#define PIN_SDA 0U
#define PIN_SCL 1U
#define LCD_ADDR 0x27U
#define LCD_BACKLIGHT 0x08U
#define ENABLE_BIT    0x04U
#define LCD_RS_BIT      0x01U 
#define LCD_RW_BIT      0x02U
#define LCD_EN_BIT      0x04U
#define LCD_BL_BIT      0x08U  
