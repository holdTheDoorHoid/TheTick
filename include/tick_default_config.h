// Copyright (C) 2024, 2025 Jakub "lenwe" Kramarz
// This file is part of The Tick.
//
// The Tick is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Tick is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License

#ifndef TICK_DEFAULT_CONFIG_H
#define TICK_DEFAULT_CONFIG_H

#include <HardwareSerial.h>
#include <IPAddress.h>

#include <cstddef>

#ifdef GIT_VERSION
#define VERSION GIT_VERSION
#else
#define VERSION "unknown"
#endif

#define HOSTNAME "TheTick-" // Hostname prefix for DHCP/OTA
#define CONFIG_FILE "/config.txt"
#define DEFAULT_CONFIG_FILE "/config.default"
#define LOG_FILE "/log.txt"
#define DBG_OUTPUT_PORT Serial       // This could be a file with some hacking
#define CARD_LEN 4                   // minimum card length in bits

#define LOG_NAME "TheTick"
#define MDNSHOST "TheTick"

#define SCREEN_WIDTH 128  // OLED display width, in pixels
#define SCREEN_HEIGHT 32  // OLED display height, in pixels
///< See datasheet for address; 0x3D for 128x64, 0x3C for 128x32
#define SCREEN_ADDRESS  0x3C

// ---------------------------------------------------------------

#define CONFIG_VAR_LENGTH 20
#define CONFIG_PASSWORD_LENGTH 64
#define CONFIG_UUID_LENGTH 37
#define CONFIG_SSID_LENGTH 33

#define OSDP_BAUDRATE 115200

// Physical reader interface.
//
// These four are shared: D0/D1 are the two data wires on the reader connector,
// used by Wiegand, by clock&data, and parked by OSDP, so they belong to the
// device rather than to any one protocol. Everything protocol-specific lives
// in the module that uses it, which is what stops one shared header and one
// shared loader from being edited by every fork at once.
struct tick_pins {
  int d0;
  int d1;
  int aux;
  int reset;
  int vsense;
};

extern struct tick_pins tick_pin;
extern float vsense_factor;

extern char log_name[CONFIG_VAR_LENGTH];
extern char DoS_id[CONFIG_PASSWORD_LENGTH];

#ifdef USE_BLE
extern char ble_uuid_wiegand_service[CONFIG_UUID_LENGTH];
extern char ble_uuid_wiegand_characteristic[CONFIG_UUID_LENGTH];
extern uint32_t ble_passkey;
#endif

#ifdef USE_WIFI
extern bool ap_enable;
extern bool ap_hidden;
extern char ap_ssid[CONFIG_SSID_LENGTH];
extern IPAddress ap_ip;
extern char ap_psk[CONFIG_PASSWORD_LENGTH];
extern char station_ssid[CONFIG_SSID_LENGTH];
extern char station_psk[CONFIG_PASSWORD_LENGTH];
#endif

#ifdef USE_MDNS_RESPONDER
extern char mDNShost[CONFIG_VAR_LENGTH];
#endif

#ifdef USE_OTA
extern char ota_password[CONFIG_PASSWORD_LENGTH];
#endif

#ifdef USE_HTTP
extern char www_username[CONFIG_VAR_LENGTH];
extern char www_password[CONFIG_PASSWORD_LENGTH];
// True when the web interface is running with no password set. The UI shows a
// warning; nothing else depends on it.
extern bool www_auth_disabled;
#endif

#ifdef USE_SYSLOG
extern IPAddress syslog_server;
extern unsigned int syslog_port;
extern char syslog_service_name[CONFIG_VAR_LENGTH];
extern char syslog_host[CONFIG_VAR_LENGTH];
extern byte syslog_priority;
#endif

// Load a config file over the top of whatever is already set. Returns false if
// the file is missing or does not parse.
bool loadConfig(const char *filename);

// Apply board defaults, then the shipped defaults file, then the operator's
// config, then validate every pin. Returns false only when the device has no
// usable configuration at all.
bool loadAllConfig(void);

#endif
