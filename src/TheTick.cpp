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
#include <FS.h>
#include <SPIFFS.h>
#include <WiFi.h>

#include "tick_ble.h"
#include "tick_board.h"
#include "tick_capture.h"
#include "tick_default_config.h"
#include "tick_heartbeat.h"
#include "tick_http.h"
#include "tick_lcd.h"
#include "tick_mdns_responder.h"
#include "tick_osdp.h"
#include "tick_ota.h"
#include "tick_protocol.h"
#include "tick_reset.h"
#include "tick_syslog.h"
#include "tick_utils.h"
#include "tick_wifi.h"

// Set when the device came up without a usable filesystem or config. The web
// interface still runs so the operator can recover it; the wire protocols do
// not, because their pin assignments cannot be trusted.
static bool degraded = false;

void output_debug_string(String s) {
  DBG_OUTPUT_PORT.println(s);
  display_temporary_message(s, 5000);
}

void jamming_enable(void) { tick_proto_jam_on(); }

void jamming_disable(void) { tick_proto_jam_off(); }

// Strip anything that would let a log entry forge a second entry, or break
// out of the HTML the browser renders it into. /version?epoch= writes an
// operator-supplied value through here, so this is a trust boundary.
static String sanitize_log_field(const String &in) {
  const size_t max_len = 96;
  String out;
  out.reserve(in.length() < max_len ? in.length() : max_len);

  for (size_t i = 0; i < in.length() && out.length() < max_len; i++) {
    char c = in[i];
    if (c == '\r' || c == '\n' || c == ';') {
      out += ' ';
    } else if ((unsigned char)c < 0x20 || (unsigned char)c == 0x7F) {
      continue;
    } else if (c == '<' || c == '>' || c == '"' || c == '\'' || c == '\\' ||
               c == '&') {
      continue;
    } else {
      out += c;
    }
  }
  return out;
}

void append_log(String facility, String text) {
  if (degraded) return;

  File file = SPIFFS.open(LOG_FILE, "a");
  if (file) {
    String log_line = String(getBootCount()) + "; " + String(millis()) + "; " +
                      sanitize_log_field(facility) + "; " +
                      sanitize_log_field(text);
    file.println(log_line);
    DBG_OUTPUT_PORT.println("Appending to log: " + String(millis()) + " " +
                            text);
    file.close();
  } else {
    DBG_OUTPUT_PORT.println("Failed opening log file.");
  }
}

void showAddress() {
  display_line(2, false, String("IP: ") + WiFi.localIP().toString());
}

// Config reset: four presses of the reset line, each 50-500 ms apart, in the
// window between 15 and 60 seconds after boot. The window keeps a noisy line
// from wiping a deployed device.
void IRAM_ATTR resetConfig(void) {
  static unsigned long last_event = 0;
  unsigned long now = millis();

  if (now < 15000 || now > 60000) {
    return;
  }

  if (now - last_event > 50 && now - last_event < 500) {
    reset_button_counter++;
  } else {
    reset_button_counter = 0;
  }
  last_event = now;
}

void setup() {
  heartbeat_init();

  DBG_OUTPUT_PORT.begin(115200);
  DBG_OUTPUT_PORT.print("\n");

  display_init();

  output_debug_string("Chip ID: 0x" + String(getChipID(), HEX));
  DBG_OUTPUT_PORT.println(String("Board: ") + TICK_BOARD.name);

  dhcp_hostname = String(HOSTNAME);
  dhcp_hostname += String(getChipID(), HEX);
  output_debug_string("Hostname: " + dhcp_hostname);
  display_line(0, false, dhcp_hostname);

  // Format on failure rather than giving up. A device that cannot mount its
  // filesystem used to return from setup() while loop() carried on calling
  // into modules that had never been initialised - no radio, no interrupts,
  // no way in, and it is sealed inside a reader.
  if (!SPIFFS.begin(true)) {
    output_debug_string(F("Failed to mount SPIFFS"));
    degraded = true;
  } else {
    DBG_OUTPUT_PORT.println(F("SPIFFS mount suceeded"));
  }

  // If a log.txt exists, use ap_ssid=TheTick-<chipid> instead of the default
  // TheTick-config. A config file will take precedence over this.
  bool seen_before = !degraded && SPIFFS.exists(LOG_FILE);

#ifdef USE_WIFI
  // Seeded before the config files are read so that a configured ssid still
  // takes precedence, which is what the original comment promised.
  if (seen_before) {
    dhcp_hostname.toCharArray(ap_ssid, sizeof(ap_ssid));
  }
#endif

  if (!degraded) {
    append_log("boot", "Starting up!");
    loadAllConfig();
  } else {
    output_debug_string(F("Running degraded: web interface only."));
  }

#ifdef USE_WIFI
  // Never leave the access point nameless.
  if (strlen(ap_ssid) == 0) {
    dhcp_hostname.toCharArray(ap_ssid, sizeof(ap_ssid));
  }
#endif

  // Housekeeping pins. Wiegand is open collector and the controller supplies
  // the pull-up; the internal one only keeps the input from floating when
  // nothing is attached. The previous code wrote HIGH to an input pin, which
  // enables a pull-up on an AVR and does nothing at all on an ESP32.
  if (tick_pin_is_valid(tick_pin.aux)) pinMode(tick_pin.aux, INPUT_PULLUP);
  if (tick_pin_is_valid(tick_pin.reset)) pinMode(tick_pin.reset, INPUT_PULLUP);

  // Park the RS-485 driver whatever mode we end up in.
  osdp_disable_transceiver();

  if (degraded) {
    tick_protocol_select(&tick_protocol_disabled);
  } else if (tick_current->init && !tick_current->init()) {
    // A driver that cannot claim its hardware falls back to doing nothing,
    // rather than running half-initialised.
    output_debug_string(String("Mode ") + tick_proto_name() +
                        " failed to start");
    append_log("config", String("mode ") + tick_proto_name() + " init failed");
    tick_protocol_select(&tick_protocol_disabled);
  }

  display_line(1, false, String("mode: ") + tick_proto_short_name());

  wifi_init();
  syslog_init();
  ota_init();
  ble_init();
  http_init();
  mdns_responder_init();

  tick_proto_attach();

  if (tick_pin_is_valid(tick_pin.reset)) {
    attachInterrupt(digitalPinToInterrupt(tick_pin.reset), resetConfig, CHANGE);
  }

  showAddress();
}

void card_read_handler(String s) {
  String card_id = s;

  output_debug_string(card_id);

  ble_card_read(card_id.c_str());

  if (strlen(DoS_id) > 0 && strcasecmp(card_id.c_str(), DoS_id) == 0) {
    jamming_enable();
    append_log("dos", String("enabled by control card ") + card_id);
  } else {
    append_log(tick_proto_name(), card_id);
  }
}

void loop() {
  display_loop();
  heartbeat_loop();
  reset_loop();

  tick_proto_loop();

  // Replay requests from the web interface, from BLE and from control cards
  // all land here, on this task, one at a time.
  tick_tx_service();

  wifi_loop();
  http_loop();
  ble_loop();
  ota_loop();
}
