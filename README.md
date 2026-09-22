# PicoW-Honeypot-Captive-Portal

A secure, bare-metal **Wi-Fi Honeypot and Captive Portal** built explicitly for the **Raspberry Pi Pico W (RP2040)** using the `lwIP` stack and `cyw43_arch`. 

This project simulates a router firmware update page to capture unauthorized access attempts. It safely traps attackers in an isolated Access Point environment, logs credentials directly to onboard flash memory, and triggers physical alert systems.

##  Features

* **Isolated Access Point:** Spawns a custom Wi-Fi Access Point (AP) and acts as a local **DHCP Server** to route all client traffic to its hosted server.
* **Deceptive Captive Portal:** Presents a faux "Router Admin Panel - Firmware Update Tool v1.0.4" HTML login page to incoming connections.
* **Persistent Flash Logging:** Extracts submitted usernames, passwords, and attacker IP addresses, persistently writing them to the RP2040's onboard flash memory (`XIP_BASE`) after checking for duplicate entries.
* **Hardware Alert System:** 
  * Drives an **I2C LCD display** (e.g., standard 16x2 over 0x27) to print "ALERT!" and reveal captured credentials in real-time.
  * Utilizes the **RP2040 Programmable I/O (PIO)** state machines to trigger an hardware alarm or blinking sequence.
* **Built for Reliability:** Developed following strict **MISRA C Guidelines** to ensure memory safety, defensive loops, and deterministic embedded runtime execution.
* **Exposed REST API:** Features a hidden background endpoint (`/secret-logs`) that dynamically structures saved flash data into a neat JSON payload stream.
**Compile:**

   cmake -DPICO_BOARD=pico_w ..
   make


##  Hardware Requirements
* **Raspberry Pi Pico W**
* I2C LCD Display (LiquidCrystal 16x2 / 20x4 via I2C PCF8574 interface)
* External Piezo Buzzer / LED (Optional, driven by PIO block)
