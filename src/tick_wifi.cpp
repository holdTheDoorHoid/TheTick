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

#ifdef USE_WIFI
#include <WiFi.h>

#include "tick_utils.h"
#include "tick_wifi.h"

static bool station_configured = false;
static unsigned long last_reconnect_attempt = 0;

// How long setup() will wait for the station to associate before handing over
// to the main loop. The device is not capturing while it waits, so this is
// deliberately short - the connection completes in the background either way.
static const unsigned long INITIAL_WAIT_MS = 8000;
static const unsigned long RECONNECT_INTERVAL_MS = 30000;

void wifi_init(void) {
  output_debug_string("WIFI INIT STARTED");

  station_configured = strlen(station_ssid) > 0;

  // Bring up the access point alongside the station rather than only as a
  // fallback after the station fails. Previously a device whose configured
  // network was out of range spent sixty seconds in a blocking loop and then
  // fell back; if the network dropped later there was no reconnect logic at
  // all, and no access point either, so the device was simply gone.
  wifi_mode_t mode;
  if (station_configured && ap_enable) {
    mode = WIFI_AP_STA;
  } else if (station_configured) {
    mode = WIFI_STA;
  } else if (ap_enable) {
    mode = WIFI_AP;
  } else {
    output_debug_string(F("No WiFi configured."));
    WiFi.mode(WIFI_OFF);
    return;
  }

  WiFi.mode(mode);
  WiFi.setHostname(dhcp_hostname.c_str());

  if (ap_enable) {
    WiFi.softAPConfig(ap_ip, ap_ip, IPAddress(255, 255, 255, 0));
    if (WiFi.softAP(ap_ssid, strlen(ap_psk) ? ap_psk : NULL, 0, ap_hidden)) {
      // Deliberately not printing the passphrase. WiFi.printDiag() used to be
      // called here and put the PSK on the serial console.
      output_debug_string("AP: " + String(ap_ssid) + " " +
                          WiFi.softAPIP().toString());
    } else {
      output_debug_string(F("Failed to start access point."));
    }
  }

  if (station_configured) {
    WiFi.setAutoReconnect(true);
    WiFi.begin(station_ssid, station_psk);

    unsigned long start = millis();
    while (WiFi.status() != WL_CONNECTED &&
           (unsigned long)(millis() - start) < INITIAL_WAIT_MS) {
      DBG_OUTPUT_PORT.write('.');
      delay(250);
    }
    DBG_OUTPUT_PORT.println();

    if (WiFi.status() == WL_CONNECTED) {
      output_debug_string("IP: " + WiFi.localIP().toString());
    } else {
      // Not an error: the association carries on in the background and
      // wifi_loop() keeps retrying. Capture starts now either way.
      output_debug_string(F("Station not up yet, continuing."));
    }
  }

  last_reconnect_attempt = millis();
}

void wifi_loop(void) {
  if (!station_configured) return;
  if (WiFi.status() == WL_CONNECTED) return;

  if ((unsigned long)(millis() - last_reconnect_attempt) <
      RECONNECT_INTERVAL_MS) {
    return;
  }
  last_reconnect_attempt = millis();

  DBG_OUTPUT_PORT.println(F("WiFi station down, retrying."));
  WiFi.disconnect();
  WiFi.begin(station_ssid, station_psk);
}

#else

void wifi_init(void) {}
void wifi_loop(void) {}

#endif
