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

#include <Arduino.h>
#include <IPAddress.h>
#include <SPIFFSIniFile.h>

#include <cstddef>

#include "HardwareSerial.h"
#include "tick_board.h"
#include "tick_heartbeat.h"
#include "tick_default_config.h"
#include "tick_osdp.h"
#include "tick_protocol.h"
#include "tick_utils.h"

char log_name[CONFIG_VAR_LENGTH] = LOG_NAME;

struct tick_pins tick_pin = {
    .d0 = TICK_PIN_NONE,
    .d1 = TICK_PIN_NONE,
    .aux = TICK_PIN_NONE,
    .reset = TICK_PIN_NONE,
    .vsense = TICK_PIN_NONE,
};
float vsense_factor = 1.0f;

char DoS_id[CONFIG_PASSWORD_LENGTH] = {0};

char ble_uuid_wiegand_service[CONFIG_UUID_LENGTH] = {0};
char ble_uuid_wiegand_characteristic[CONFIG_UUID_LENGTH] = {0};
uint32_t ble_passkey = 0;

bool ap_enable = true, ap_hidden = false;
char ap_ssid[CONFIG_SSID_LENGTH] = {0}, ap_psk[CONFIG_PASSWORD_LENGTH] = {0};
IPAddress ap_ip(192, 168, 4, 1);
char station_ssid[CONFIG_SSID_LENGTH] = {0};
char station_psk[CONFIG_PASSWORD_LENGTH] = {0};

char mDNShost[CONFIG_VAR_LENGTH] = MDNSHOST;

char ota_password[CONFIG_PASSWORD_LENGTH] = {0};

char www_username[CONFIG_VAR_LENGTH] = {0};
char www_password[CONFIG_PASSWORD_LENGTH] = {0};
bool www_auth_disabled = true;

IPAddress syslog_server;
unsigned int syslog_port = 514;
char syslog_service_name[CONFIG_VAR_LENGTH] = {0};
char syslog_host[CONFIG_VAR_LENGTH] = {0};
byte syslog_priority = 36;

// Name of the mode requested by the config file, so that a mode which is
// spelled correctly but not compiled into this build can be reported as such
// rather than silently becoming "disabled".
static char requested_mode[CONFIG_VAR_LENGTH] = {0};

// Apply the board table. Called before any config file is read, so that a
// missing key leaves a sane board default rather than zero - and zero is
// GPIO 0, which on these boards is both a strapping pin and the default D0.
static void applyBoardDefaults(void) {
  tick_pin.d0 = TICK_BOARD.pin_d0;
  tick_pin.d1 = TICK_BOARD.pin_d1;
  tick_pin.aux = TICK_BOARD.pin_aux;
  tick_pin.reset = TICK_BOARD.pin_reset;
  tick_pin.vsense = TICK_BOARD.pin_vsense;
  vsense_factor = TICK_BOARD.vsense_factor;
  osdp_pins_defaults();
}

bool loadConfig(const char* filename) {
  const size_t bufferLen = 80;
  char buffer[bufferLen];

  output_debug_string(String("Reading config ") + filename + " START");

  SPIFFSIniFile ini(filename);
  if (!ini.open()) {
    output_debug_string("Config file not present");
    return false;
  }

  if (!ini.validate(buffer, bufferLen)) {
    ini.close();
    output_debug_string("Config file invalid");
    return false;
  }

  int value = 0;

  // Every getValue result is checked. Previously they were all discarded, so
  // a missing key left the target at whatever it happened to hold - and in
  // the case of the mode string, that was uninitialised stack.
  ini.getValue("tick", "mode", buffer, bufferLen, requested_mode,
               CONFIG_VAR_LENGTH);
  ini.getValue("tick", "name", buffer, bufferLen, log_name, CONFIG_VAR_LENGTH);
  ini.getValue("tick", "dos_id", buffer, bufferLen, DoS_id,
               CONFIG_PASSWORD_LENGTH);

  if (ini.getValue("tick", "pin_vsense", buffer, bufferLen, value)) {
    tick_pin.vsense = value;
  }
  {
    float f = 0.0f;
    if (ini.getValue("tick", "vsense_factor", buffer, bufferLen, f)) {
      vsense_factor = f;
    }
  }
  if (ini.getValue("tick", "pin_reset", buffer, bufferLen, value)) {
    tick_pin.reset = value;
  }
  if (ini.getValue("tick", "pin_aux", buffer, bufferLen, value)) {
    tick_pin.aux = value;
  }
  {
    bool flag = false;
    if (ini.getValue("tick", "heartbeat", buffer, bufferLen, flag)) {
      heartbeat_enabled = flag;
    }
  }

  // The two reader data lines are shared by every wire protocol, so they are
  // read here; the [wiegand] section keeps them for backwards compatibility
  // with existing config files.
  if (ini.getValue("wiegand", "pin_d0", buffer, bufferLen, value)) {
    tick_pin.d0 = value;
  }
  if (ini.getValue("wiegand", "pin_d1", buffer, bufferLen, value)) {
    tick_pin.d1 = value;
  }
  if (ini.getValue("clockanddata", "pin_clock", buffer, bufferLen, value)) {
    tick_pin.d0 = value;
  }
  if (ini.getValue("clockanddata", "pin_data", buffer, bufferLen, value)) {
    tick_pin.d1 = value;
  }

  // The transceiver pins are needed even in builds without OSDP, so that the
  // driver can be parked on boot.
  osdp_pins_configure(ini, buffer, bufferLen);

  // Hand the file to every registered protocol driver so it can pick up its
  // own settings. This is the hook that keeps this function from having to
  // know what a protocol module contains.
  for (size_t i = 0; i < tick_protocol_registry_count; i++) {
    const tick_protocol *proto = tick_protocol_registry[i];
    if (proto->configure) proto->configure(ini, buffer, bufferLen);
  }

#ifdef USE_WIFI
  ini.getValue("wifi_hotspot", "enable", buffer, bufferLen, ap_enable);
  ini.getValue("wifi_hotspot", "hidden", buffer, bufferLen, ap_hidden);
  ini.getValue("wifi_hotspot", "ssid", buffer, bufferLen, ap_ssid,
               CONFIG_SSID_LENGTH);
  ini.getValue("wifi_hotspot", "psk", buffer, bufferLen, ap_psk,
               CONFIG_PASSWORD_LENGTH);
  ini.getIPAddress("wifi_hotspot", "ip", buffer, bufferLen, ap_ip);
  ini.getValue("wifi_client", "ssid", buffer, bufferLen, station_ssid,
               CONFIG_SSID_LENGTH);
  ini.getValue("wifi_client", "psk", buffer, bufferLen, station_psk,
               CONFIG_PASSWORD_LENGTH);
#endif

#ifdef USE_MDNS_RESPONDER
  ini.getValue("mdns", "host", buffer, bufferLen, mDNShost, CONFIG_VAR_LENGTH);
#endif

#ifdef USE_SYSLOG
  ini.getIPAddress("syslog", "server", buffer, bufferLen, syslog_server);
  ini.getValue("syslog", "port", buffer, bufferLen, syslog_port);
  ini.getValue("syslog", "priority", buffer, bufferLen, syslog_priority);
  ini.getValue("syslog", "service", buffer, bufferLen, syslog_service_name,
               CONFIG_VAR_LENGTH);
  ini.getValue("syslog", "host", buffer, bufferLen, syslog_host,
               CONFIG_VAR_LENGTH);
#endif

#ifdef USE_OTA
  ini.getValue("ota", "password", buffer, bufferLen, ota_password,
               CONFIG_PASSWORD_LENGTH);
#endif

#ifdef USE_HTTP
  ini.getValue("http", "username", buffer, bufferLen, www_username,
               CONFIG_VAR_LENGTH);
  ini.getValue("http", "password", buffer, bufferLen, www_password,
               CONFIG_PASSWORD_LENGTH);
#endif

#ifdef USE_BLE
  ini.getValue("ble", "service", buffer, bufferLen, ble_uuid_wiegand_service,
               CONFIG_UUID_LENGTH);
  ini.getValue("ble", "characteristic", buffer, bufferLen,
               ble_uuid_wiegand_characteristic, CONFIG_UUID_LENGTH);
  {
    // Read through an explicit unsigned long rather than passing the uint32_t
    // straight in. SPIFFSIniFile overloads on the underlying types, and
    // uint32_t is "unsigned long" on the RISC-V targets but "unsigned int" on
    // Xtensa - so passing it directly compiles for the C3 and C5 and fails to
    // resolve for the S3.
    unsigned long passkey = 0;
    if (ini.getValue("ble", "passkey", buffer, bufferLen, passkey)) {
      ble_passkey = (uint32_t)passkey;
    }
  }
#endif

  ini.close();

  output_debug_string("Reading config END");
  return true;
}

// Reject pins the chip cannot actually offer, before anything tries to use
// them. A config written for one chip and flashed onto another is the normal
// way this goes wrong.
static void validatePins(void) {
  tick_pin.d0 =
      tick_pin_checked("pin_d0", tick_pin.d0, TICK_BOARD.pin_d0, true);
  tick_pin.d1 =
      tick_pin_checked("pin_d1", tick_pin.d1, TICK_BOARD.pin_d1, true);
  tick_pin.aux =
      tick_pin_checked("pin_aux", tick_pin.aux, TICK_BOARD.pin_aux, false);
  tick_pin.reset =
      tick_pin_checked("pin_reset", tick_pin.reset, TICK_BOARD.pin_reset, false);
  tick_pin.vsense = tick_pin_checked("pin_vsense", tick_pin.vsense,
                                     TICK_BOARD.pin_vsense, false);

  if (tick_pin.d0 == tick_pin.d1) {
    output_debug_string(F("pin_d0 and pin_d1 are the same pin"));
  }

  // ADC2 cannot be read while WiFi is up, so a vsense pin on ADC2 reports
  // nonsense in the only state the device is ever actually in.
  if (tick_pin.vsense != TICK_PIN_NONE && !tick_pin_is_adc1(tick_pin.vsense)) {
    output_debug_string(String("pin_vsense ") + tick_pin.vsense +
                        " is not on ADC1, readings will be unreliable");
  }
}

bool loadAllConfig(void) {
  applyBoardDefaults();

  bool have_defaults = loadConfig(DEFAULT_CONFIG_FILE);
  if (!have_defaults) {
    // Not fatal any more: the board table already supplied working pins, so
    // the device can still come up, serve its interface and be recovered.
    output_debug_string(F("No default configuration, using board defaults."));
  }

  if (!loadConfig(CONFIG_FILE)) {
    output_debug_string(F("No configuration. Using defaults."));
  }

  validatePins();

#ifdef USE_HTTP
  www_auth_disabled =
      (strlen(www_username) == 0 || strlen(www_password) == 0);
#endif

#ifdef USE_WIFI
  // An access point with no usable PSK would come up open. Refusing to start
  // it is the safer failure for a device whose whole job is to be discreet.
  if (ap_enable && strlen(ap_psk) > 0 && strlen(ap_psk) < 8) {
    output_debug_string(F("AP passphrase under 8 characters, disabling AP"));
    ap_enable = false;
  }
#endif

  // Select the wire protocol. An unknown name is reported rather than
  // silently falling through to disabled, because "typo in config.txt" and
  // "this build has no OSDP" look identical from the outside otherwise.
  const tick_protocol *proto = tick_protocol_find(requested_mode);
  if (proto == NULL) {
    if (strlen(requested_mode) > 0 && strcasecmp(requested_mode, "NONE") != 0) {
      output_debug_string(String("Unknown or unavailable mode: ") +
                          requested_mode);
      append_log("config", String("unknown mode ") + requested_mode);
    }
    proto = &tick_protocol_disabled;
  }
  tick_protocol_select(proto);

  return have_defaults;
}
