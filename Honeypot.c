#include "configuration.h"
static char volatile json_username[BUFFER_SIZE] = "no data";
static char volatile json_password[BUFFER_SIZE] = "no data";
static char volatile json_IP[BUFFER_SIZE] = "no data"; 
static PIO alarm_pio = pio0;
static uint32_t alarm_sm = 0U;

typedef struct 
{
    char flashmem_user[BUFFER_SIZE];
    char flashmem_pass[BUFFER_SIZE];
     char flashmem_ip[IP_ADDRESS_BUFFER];

} flashmem_log_t;

typedef struct dhcp_server_t_ {
    struct udp_pcb *udp;
    ip4_addr_t ipaddr;
    ip4_addr_t netmask;
} dhcp_server_t;

static dhcp_server_t dhcp_server;

static const char FAKE_LOGIN_PAGE[] =
"HTTP/1.1 200 OK\r\n"
"Content-Type: text/html\r\n"
"Connection: close\r\n\r\n"
"<!DOCTYPE html><html><head><title>Router Admin Panel</title></head>"
"<body style='font-family:sans-serif; text-align:center; margin-top:100px; background:#222; color:#fff;'>"
"<h2>Firmware Update Tool v1.0.4</h2>"
"<p style='color:red;'>Warning: Unauthorized Access Prohibited</p>"
"<form method='GET' action='/'>" 
"Username: <input type='text' name='user'><br><br>"
"Password: <input type='password' name='pass'><br><br>"
"<input type='submit' value='Login'>"
"</form></body></html>";

static const char LOG_RESPONSE_HEADER[] = 
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n\r\n";

// forward declarations MISRA C Guidelines 8.2 
static err_t receive_honeypot(void *arg, struct tcp_pcb *tcpb, struct pbuf *p, err_t error);
static err_t accept_honeypot(void *arg, struct tcp_pcb *new_tcpb, err_t error);
static err_t sent_honeypot(void *arg, struct tcp_pcb *tcpb, u16_t len);
static void dhcp_server_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
bool dhcp_server_init(dhcp_server_t *d, ip4_addr_t *ipaddr, ip4_addr_t *netmask);
void start_honeypot(void);
void lcd_clear(void);
void lcd_init(void);
void lcd_print(const char *s);
void lcd_toggle_enable(uint8_t val);
void lcd_set_cursor(uint8_t row, uint8_t col);
void lcd_send_byte(uint8_t val, uint8_t mode);
// forward declarations MISRA C Guidelines 8.2 
static bool is_data_identical(const flashmem_log_t *const current, const char *const user_src, 
                                   const char *const pass_src, 
                                   const char *const ip_src);
void save_log_to_flash(const char *user_src, const char *pass_src, const char *ip_src);
void load_log_from_flash(void);


// buffer to prevent SYN flood attacks 
static bool is_data_identical(const flashmem_log_t *const current, const char *const user_src, 
                                   const char *const pass_src, 
                                   const char *const ip_src)
{

    bool match = true;
    for (uint16_t i = 0U; i < BUFFER_SIZE; i++)
    {
        if (current->flashmem_user[i] != user_src[i])
        {
            match = false;
            break;
        }
        
    }
    if (match)
    {
         for (uint16_t i = 0U; i < BUFFER_SIZE; ++i)
         {
            if (current->flashmem_pass[i] != pass_src[i] )
            {
                match = false;
                break;
            }
            
         }
    }
     if (match)
    {
         for (uint16_t i = 0U; i < IP_ADDRESS_BUFFER; ++i)
         {
            if (current->flashmem_ip[i] != ip_src[i] )
            {
                match = false;
                break;
            }
            
         }
    }
    return match;

}
 
void lcd_init(void) {
    sleep_ms(50U);

    
    lcd_toggle_enable(0x30U); 
    sleep_ms(5U); 

    lcd_toggle_enable(0x30U);
    sleep_us(150U); 

    lcd_toggle_enable(0x30U);
    sleep_us(150U);

    
    lcd_toggle_enable(0x20U); 
    sleep_ms(2U);

    
    lcd_send_byte(0x28U, 0U); 
    sleep_us(50U);
    
    lcd_send_byte(0x0CU, 0U); 
    sleep_us(50U);
    
    lcd_send_byte(0x06U, 0U); 
    sleep_us(50U);

    lcd_clear();
    sleep_ms(2U); 
}

void lcd_toggle_enable(uint8_t val) {
    const uint32_t timeout_us = 100000U;
    
    
    uint8_t high_val = val | ENABLE_BIT | LCD_BACKLIGHT;
    i2c_write_timeout_us(I2C_PORT, LCD_ADDR, &high_val, 1U, false, timeout_us);
    sleep_us(500U); 

    
    uint8_t low_val = val | LCD_BACKLIGHT; 
    i2c_write_timeout_us(I2C_PORT, LCD_ADDR, &low_val, 1U, false, timeout_us);
    sleep_us(500U); 
}

void lcd_send_byte(uint8_t val, uint8_t mode) {
    
    uint8_t rs_mask = (mode == 1U) ? 0x01U : 0x00U;

    
    uint8_t high_nibble = (val & 0xF0U) | rs_mask;
    uint8_t low_nibble  = ((val << 4U) & 0xF0U) | rs_mask;

    
    lcd_toggle_enable(high_nibble);
    lcd_toggle_enable(low_nibble);
}
void lcd_clear(void) {
    lcd_send_byte(0x01U, 0U); 
}
void lcd_print(const char *s) {
    while (*s) {
        lcd_send_byte((uint8_t)*s++, 1U); 
    }
}
void lcd_set_cursor(uint8_t row, uint8_t col) { 
    uint8_t val = (row == 0U) ? (0x80U + col) : (0xC0U + col);
    lcd_send_byte(val, 0U);
}

static void dhcp_server_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr, u16_t port) {
    dhcp_server_t *d = (dhcp_server_t *)arg;
    (void)addr; 
    
    if ((p == NULL) || (port != DHCP_PORT_CLIENT)) {
        if (p != NULL) {
            (void)pbuf_free(p);
        }
        return;
    }
    
    uint8_t *msg = (uint8_t *)p->payload;
    if ((p->len >= 241U) && (msg[0U] == 1U) && (msg[240U] == 0x35U)) { 
        uint8_t type = msg[242U];
        struct pbuf *r = pbuf_alloc(PBUF_TRANSPORT, 300U, PBUF_RAM);
        if (r != NULL) {
            uint8_t *reply = (uint8_t *)r->payload;
            (void)memset(reply, 0, 300U);
            
            reply[0U] = 2U; reply[1U] = 1U; reply[2U] = 6U; 
            (void)memcpy(&reply[4U], &msg[4U], 4U); 
            (void)memcpy(&reply[28U], &msg[28U], 6U); 
            
            
            reply[16U] = 192U; reply[17U] = 168U; reply[18U] = 4U; reply[19U] = 2U;
            
            
            reply[236U] = 99U; reply[237U] = 130U; reply[238U] = 83U; reply[239U] = 99U;
            reply[240U] = 0x35U; reply[241U] = 1U; reply[242U] = (type == 1U) ? 2U : 5U;
            
            
            reply[243U] = 1U; reply[244U] = 4U; reply[245U] = 255U; reply[246U] = 255U; reply[247U] = 255U; reply[248U] = 0U;
            
            // Router / Gateway Option (192.168.4.1)
            reply[249U] = 3U; reply[250U] = 4U; reply[251U] = 192U; reply[252U] = 168U; reply[253U] = 4U; reply[254U] = 1U;
            reply[255U] = 0xFFU;
            
            ip_addr_t dest;
            ip4_addr_set_u32(&dest, IPADDR_BROADCAST);
            (void)udp_sendto(pcb, r, &dest, DHCP_PORT_CLIENT);
            (void)pbuf_free(r);
        }
    }
    (void)pbuf_free(p);
}
bool dhcp_server_init(dhcp_server_t *d, ip4_addr_t *ipaddr, ip4_addr_t *netmask) {
    (void)memset(d, 0, sizeof(*d));
    d->ipaddr = *ipaddr;
    d->netmask = *netmask;
    d->udp = udp_new();
    if (d->udp == NULL) {
        return false;
    }
    
    (void)udp_bind(d->udp, IP_ADDR_ANY, DHCP_PORT_SERVER);
    udp_recv(d->udp, dhcp_server_recv, d);
    return true;
}

void save_log_to_flash(const char *user_src, const char *pass_src, const char *ip_src)
{
    static flashmem_log_t snapshot;
     const flashmem_log_t *const live_flash = (const flashmem_log_t *)(XIP_BASE + FLASH_TARGET_OFFSET);
    for (uint16_t i = 0U; i < BUFFER_SIZE; ++i) 
      {
        snapshot.flashmem_user[i] = user_src[i];
        snapshot.flashmem_pass[i] = pass_src[i];
      }
    for (uint16_t i = 0U; i < IP_ADDRESS_BUFFER; ++i)
    {
        snapshot.flashmem_ip[i] = ip_src[i];
    }
     if (is_data_identical(live_flash, user_src, pass_src, ip_src))
    {
        return; 
    }
     uint32_t saved_interrupts = save_and_disable_interrupts();
     flash_range_erase(FLASH_TARGET_OFFSET, FLASH_SECTOR_SIZE);
     flash_range_program(FLASH_TARGET_OFFSET, (const uint8_t *)&snapshot, sizeof(snapshot));
     restore_interrupts(saved_interrupts);


}

void load_log_from_flash(void)
{
    const flashmem_log_t *const flashmempointer = (const flashmem_log_t *)(XIP_BASE + FLASH_TARGET_OFFSET);
    if ((uint8_t)flashmempointer->flashmem_user[0] != 0xFFU)
    {
        cyw43_arch_lwip_begin();
        for (uint16_t i = 0U; i < BUFFER_SIZE; ++i) 
        {
            json_username[i] = flashmempointer->flashmem_user[i];
            json_password[i] = flashmempointer->flashmem_pass[i];

    }
        for (uint16_t i = 0U; i < IP_ADDRESS_BUFFER; ++i)
        {
            json_IP[i] = flashmempointer->flashmem_ip[i];

        }
        
         cyw43_arch_lwip_end();
}
}


static err_t receive_honeypot(void *arg, struct tcp_pcb *tcpb, struct pbuf *p, err_t error)
{
    err_t ret_val = ERR_OK;
    (void)arg;
    
    if ((p != NULL) && (error == ERR_OK) && (tcpb != NULL))
    {
        const char *const payload_ptr = (const char *)p->payload;
        const uint16_t payload_len = p->len;
        bool is_secret_log_request = false;
        
        // 1. Explicit Endpoint Routing Scan (MISRA Bounded Loop)
        if (payload_len >= 12U)
        {
            for (uint16_t i = 0U; i <= (payload_len - 12U); ++i)
            {
                if ((payload_ptr[i] == '/') &&
                    (payload_ptr[i + 1U] == 's') &&
                    (payload_ptr[i + 2U] == 'e') &&
                    (payload_ptr[i + 3U] == 'c') &&
                    (payload_ptr[i + 4U] == 'r') &&
                    (payload_ptr[i + 5U] == 'e') &&
                    (payload_ptr[i + 6U] == 't') &&
                    (payload_ptr[i + 7U] == '-') &&
                    (payload_ptr[i + 8U] == 'l') &&
                    (payload_ptr[i + 9U] == 'o') &&
                    (payload_ptr[i + 10U] == 'g') &&
                    (payload_ptr[i + 11U] == 's'))
                {
                    is_secret_log_request = true;
                    break;
                }
            }
        }
        
        
        if (is_secret_log_request)
        {
            char json_output[BUFFER_SIZE * 3U];
            uint16_t jdx = 0U;
            
            (void)tcp_write(tcpb, LOG_RESPONSE_HEADER, (uint16_t)(sizeof(LOG_RESPONSE_HEADER) - 1U), TCP_WRITE_FLAG_COPY);
            
            cyw43_arch_lwip_begin();
            const char json_start[] = "{\n \"username\": \"";
            const char json_middle[] = "\",\n \"password\": \"";
            const char json_ip_label[] = "\",\n \"ip_address\": \"";
            const char json_end[] = "\"\n}\n";
            
            for (uint16_t x = 0U; (json_start[x] != '\0') && (jdx < (sizeof(json_output) - 1U)); ++x) {
                json_output[jdx] = json_start[x]; jdx++;
            }
            for (uint16_t x = 0U; (json_username[x] != '\0') && (jdx < (sizeof(json_output) - 1U)); ++x) {
                json_output[jdx] = json_username[x]; jdx++;
            }
            for (uint16_t x = 0U; (json_middle[x] != '\0') && (jdx < (sizeof(json_output) - 1U)); ++x) {
                json_output[jdx] = json_middle[x]; jdx++;
            }
            for (uint16_t x = 0U; (json_password[x] != '\0') && (jdx < (sizeof(json_output) - 1U)); ++x) {
                json_output[jdx] = json_password[x]; jdx++;
            }
            for (uint16_t x = 0U; (json_ip_label[x] != '\0') && (jdx < (sizeof(json_output) - 1U)); ++x) {
                json_output[jdx] = json_ip_label[x]; jdx++;
            }
            for (uint16_t x = 0U; (json_IP[x] != '\0') && (jdx < (sizeof(json_output) - 1U)); ++x) {
                json_output[jdx] = json_IP[x]; jdx++;
            }
            for (uint16_t x = 0U; (json_end[x] != '\0') && (jdx < (sizeof(json_output) - 1U)); ++x) {
                json_output[jdx] = json_end[x]; jdx++;
            }
            json_output[jdx] = '\0';
            cyw43_arch_lwip_end();
            
            (void)tcp_write(tcpb, (const void *)json_output, jdx, TCP_WRITE_FLAG_COPY);
            (void)tcp_output(tcpb);
        }
        
        else
        {
            bool credentials_found = false;
            uint16_t user_start_idx = 0U;
            uint16_t pass_start_idx = 0U;

            if (payload_len >= 5U) {
                for (uint16_t i = 0U; i <= (payload_len - 5U); ++i) {
                    if ((payload_ptr[i] == 'u') && (payload_ptr[i+1U] == 's') &&
                        (payload_ptr[i+2U] == 'e') && (payload_ptr[i+3U] == 'r') &&
                        (payload_ptr[i+4U] == '=')) {
                        user_start_idx = i + 5U;
                        credentials_found = true;
                    }
                    if ((payload_ptr[i] == 'p') && (payload_ptr[i+1U] == 'a') &&
                        (payload_ptr[i+2U] == 's') && (payload_ptr[i+3U] == 's') &&
                        (payload_ptr[i+4U] == '=')) {
                        pass_start_idx = i + 5U;
                    }
                }
            }

            if (credentials_found && (user_start_idx != 0U) && (pass_start_idx != 0U))
            {
                cyw43_arch_lwip_begin();
                for (uint16_t i = 0U; i < BUFFER_SIZE; ++i) {
                    json_username[i] = '\0';
                    json_password[i] = '\0';
                }
                for (uint16_t i = 0U; i < IP_ADDRESS_BUFFER; ++i) {
                    json_IP[i] = '\0';
                }
                cyw43_arch_lwip_end();
                
                
                uint16_t u_idx = 0U;
                uint16_t curr_u = user_start_idx;
                while ((curr_u < payload_len) && (payload_ptr[curr_u] != '\0') && 
                       (payload_ptr[curr_u] != '&') && (payload_ptr[curr_u] != ' ') && 
                       (payload_ptr[curr_u] != '\r') && (payload_ptr[curr_u] != '\n') && 
                       (u_idx < (BUFFER_SIZE - 1U))) 
                {
                    char c = payload_ptr[curr_u];
                    if (c == '+') { c = ' '; }
                    
                    cyw43_arch_lwip_begin();
                    json_username[u_idx] = c;
                    cyw43_arch_lwip_end();
                    u_idx++; curr_u++;
                }
                
                
                uint16_t p_idx = 0U;
                uint16_t curr_p = pass_start_idx;
                while ((curr_p < payload_len) && (payload_ptr[curr_p] != '\0') && 
                       (payload_ptr[curr_p] != '&') && (payload_ptr[curr_p] != ' ') && 
                       (payload_ptr[curr_p] != '\r') && (payload_ptr[curr_p] != '\n') && 
                       (p_idx < (BUFFER_SIZE - 1U))) 
                {
                    char c = payload_ptr[curr_p];
                    if (c == '+') { c = ' '; }
                    
                    cyw43_arch_lwip_begin();
                    json_password[p_idx] = c;
                    cyw43_arch_lwip_end();
                    p_idx++; curr_p++;
                }
                
                // Track Attacker Address Parameters
                cyw43_arch_lwip_begin();
                const char *const ip_str = ipaddr_ntoa(&(tcpb->remote_ip));
                if (ip_str != NULL) {
                    uint16_t idx = 0U;
                    while ((ip_str[idx] != '\0') && (idx < (IP_ADDRESS_BUFFER - 1U))) {
                        json_IP[idx] = ip_str[idx];
                        idx++;
                    }
                    json_IP[idx] = '\0';
                }
                cyw43_arch_lwip_end();
                
               
                save_log_to_flash((const char *)json_username, (const char *)json_password, (const char *)json_IP);
                
                lcd_clear();
                lcd_set_cursor(0U, 0U);
                lcd_print("User captured!");
                pio_sm_put_blocking(alarm_pio, alarm_sm, ON);
        
                lcd_set_cursor(1U, 0U);
                lcd_print((const char *)json_username);
                const uint16_t page_len = (uint16_t)(sizeof(FAKE_LOGIN_PAGE) - 1U);
                (void)tcp_write(tcpb, FAKE_LOGIN_PAGE, page_len, TCP_WRITE_FLAG_COPY);
                (void)tcp_output(tcpb);
            }
            else
            {
               
                const uint16_t page_len = (uint16_t)(sizeof(FAKE_LOGIN_PAGE) - 1U);
                (void)tcp_write(tcpb, FAKE_LOGIN_PAGE, page_len, TCP_WRITE_FLAG_COPY);
                (void)tcp_output(tcpb);
            }
        }
        
        tcp_recved(tcpb, p->tot_len);
        tcp_sent(tcpb, sent_honeypot);
        (void)pbuf_free(p);
    }
    else
    {
        if (p != NULL) {
            (void)pbuf_free(p);
        }
        if (tcpb != NULL) {
            tcp_abort(tcpb);
            ret_val = ERR_ABRT;
        }
    }
    return ret_val;
}

static err_t sent_honeypot(void *arg, struct tcp_pcb *tcpb, u16_t len)
{
    (void)arg;
    (void)len;
    if (tcpb != NULL) 
    {
        (void)tcp_close(tcpb);
    }
    return ERR_OK;
}

static err_t accept_honeypot(void *arg, struct tcp_pcb *new_tcpb, err_t error)
{
    err_t ret_val = ERR_OK;
    (void)arg;
    
    if ((error == ERR_OK) && (new_tcpb != NULL)) 
    {
        tcp_recv(new_tcpb, receive_honeypot);
    } 
    else {
        ret_val = ERR_VAL;
    }
    return ret_val;
}

void start_honeypot(void)
{
    struct tcp_pcb *const pcb = tcp_new();
    
    if (pcb != NULL) 
    {
        if (tcp_bind(pcb, IP_ADDR_ANY, PORT) == ERR_OK) 
        {
            struct tcp_pcb *const listen_pcb = tcp_listen(pcb);
            if (listen_pcb != NULL) {
                tcp_accept(listen_pcb, accept_honeypot);
            }
        }
    }
}
// Test code for the LCD connection
bool verify_lcd_hardware(void) {
    uint8_t dummy_rx_byte = 0;
    
   
    int result = i2c_read_blocking(I2C_PORT, LCD_ADDR, &dummy_rx_byte, 1U, false);
    
    return (result >= 0);
}
    
int main(void)
{
   int32_t status = 0;
    
    
    if (cyw43_arch_init() != 0)
    {
        status = -1;
    }
    else
    {
       
        i2c_init(I2C_PORT, 100U * 1000U);
        gpio_set_function(PIN_SDA, GPIO_FUNC_I2C);
        gpio_set_function(PIN_SCL, GPIO_FUNC_I2C);
        
        gpio_set_drive_strength(PIN_SDA, GPIO_DRIVE_STRENGTH_12MA);
        gpio_set_drive_strength(PIN_SCL, GPIO_DRIVE_STRENGTH_12MA);
        
        if (verify_lcd_hardware()) {
           // The Pico found a connection with 0x27
            for (int i = 0; i < 3; i++) {
                cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1U);
                sleep_ms(400);
                cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0U);
                sleep_ms(400);
            }
           cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1U); // Leave it on
        } else {
            
            while (true) {
                cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1U);
                sleep_ms(80);
                cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0U);
                sleep_ms(80);
            }
        }
        lcd_init();
        lcd_clear();
        lcd_print("ALERT!");

        
        ip4_addr_t ipaddr, netmask, gw;
        IP4_ADDR(&ipaddr, 192, 168, 4, 1);
        IP4_ADDR(&netmask, 255, 255, 255, 0);
        IP4_ADDR(&gw, 192, 168, 4, 1);
        
        cyw43_arch_enable_ap_mode(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK);
        
        cyw43_arch_lwip_begin();
        netif_set_addr(netif_default, &ipaddr, &netmask, &gw);
        //cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, ON);
        cyw43_arch_lwip_end();
        
        netif_set_up(netif_default);
        netif_set_link_up(netif_default);
        
       
        cyw43_arch_lwip_begin();
        (void)dhcp_server_init(&dhcp_server, &ipaddr, &netmask);
        cyw43_arch_lwip_end();
        
        // 6. Configure Programmable I/O (PIO) Alarm Infrastructure
        if (pio_can_add_program(pio0, &alarm_program)) 
        {
            alarm_pio = pio0;
        } 
        else 
        {
            alarm_pio = pio1;
        }
        
        const uint32_t offset = pio_add_program(alarm_pio, &alarm_program);
        alarm_sm = (uint32_t)pio_claim_unused_sm(alarm_pio, true);
        alarm_program_init(alarm_pio, (uint)alarm_sm, (uint)offset, LED_PIN);
       
        load_log_from_flash();
        
        
        cyw43_arch_lwip_begin();
        start_honeypot();
        cyw43_arch_lwip_end();
        
        
        for (;;) 
        {
            cyw43_arch_poll();
            sleep_ms(10U);
        }
    }
    
    return (int)status;
}
