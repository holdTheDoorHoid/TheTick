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

#ifdef USE_HTTP

#ifndef USE_WIFI
#error "USE_HTTP must be used with USE_WIFI"
#endif

#include <Arduino.h>
#include <FS.h>
#include <SPIFFS.h>
#include <WebServer.h>

#include "tick_board.h"
#include "tick_capture.h"
#include "tick_findings.h"
#include "tick_http.h"
#include "tick_protocol.h"
#ifdef USE_OSDP_MONITOR
#include "tick_osdp_monitor.h"
#endif
#include "tick_utils.h"

WebServer server(80);
File fsUploadFile;

#ifdef USE_OTA_HTTP
#include <HTTPUpdateServer.h>
HTTPUpdateServer httpUpdater;
#endif

bool basicAuthFailed() {
  if (strlen(www_username) > 0 && strlen(www_password) > 0) {
    if (!server.authenticate(www_username, www_password)) {
      server.requestAuthentication();
      return true;
    }
  }
  return false;  // This is good
}

// Escape a value for inclusion in a JSON string. Config values and filenames
// end up in these responses and are then written into the page by the
// browser, so an unescaped quote is both malformed JSON and a way into the
// operator's dashboard.
static String jsonEscape(const String &in) {
  String out;
  out.reserve(in.length() + 8);
  for (size_t i = 0; i < in.length(); i++) {
    char c = in[i];
    switch (c) {
      case '"': out += F("\\\""); break;
      case '\\': out += F("\\\\"); break;
      case '\n': out += F("\\n"); break;
      case '\r': out += F("\\r"); break;
      case '\t': out += F("\\t"); break;
      case '<': out += F("\\u003c"); break;
      case '>': out += F("\\u003e"); break;
      case '&': out += F("\\u0026"); break;
      default:
        if ((unsigned char)c < 0x20) {
          char buf[7];
          snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
          out += buf;
        } else {
          out += c;
        }
    }
  }
  return out;
}

static String jsonString(const String &in) {
  return String("\"") + jsonEscape(in) + "\"";
}

void handleTxId() {
  // This endpoint transmits a credential to the door controller. It is the
  // most sensitive thing the device does and it was the one handler with no
  // authentication check at all.
  if (basicAuthFailed()) return;

  if (!server.hasArg("v")) {
    server.send(400, F("text/plain"), F("BAD ARGS"));
    return;
  }

  if (!tick_proto_can_tx()) {
    server.send(409, F("text/plain"), F("mode cannot transmit"));
    return;
  }

  // Validated and length-bounded inside tick_tx_submit_pair, and actually
  // sent from the main loop rather than from this handler's task.
  if (!tick_tx_submit_pair(server.arg("v").c_str())) {
    server.send(400, F("text/plain"), F("bad value, or a send is in flight"));
    return;
  }

  server.send(200, F("text/plain"), "");
}

String getContentType(String filename) {
  if (server.hasArg("download"))
    return F("application/octet-stream");
  else if (filename.endsWith(".htm") || filename.endsWith(".html"))
    return F("text/html");
  else if (filename.endsWith(".css"))
    return F("text/css");
  else if (filename.endsWith(".js"))
    return F("application/javascript");
  return "text/plain";
}

bool handleFileRead(String path) {
  DBG_OUTPUT_PORT.println("handleFileRead: " + path);
  if (path.equals(F("/"))) {
    // The landing page comes from the active driver rather than from a switch
    // that had to be extended for every new protocol.
    const char *page = tick_current->ui_page;
    path = page ? String(page) : String(F("/dashboard.html"));
  }
  if (path.endsWith(F("/"))) path += F("index.html");
  String contentType = getContentType(path);
  String pathWithGz = path + F(".gz");
  if (SPIFFS.exists(pathWithGz) || SPIFFS.exists(path)) {
    if (SPIFFS.exists(pathWithGz)) path += F(".gz");
    File file = SPIFFS.open(path, "r");
    server.sendHeader("Now", String(millis()));
    server.streamFile(file, contentType);
    file.close();
    return true;
  }
  return false;
}

void handleFileUpload() {
  // This runs once per chunk of the request body. The authentication check
  // therefore happens once, at the start, and the answer is remembered -
  // calling requestAuthentication() on every chunk would emit a stream of
  // 401 responses into the middle of an upload.
  static bool upload_allowed = false;

  if (server.uri() != F("/edit")) return;
  HTTPUpload &upload = server.upload();

  if (upload.status == UPLOAD_FILE_START) {
    upload_allowed = !basicAuthFailed();
  }
  if (!upload_allowed) return;

  if (upload.status == UPLOAD_FILE_START) {
    String filename = upload.filename;
    if (!filename.startsWith("/")) filename = "/" + filename;
    DBG_OUTPUT_PORT.println("handleFileUpload Name: " + filename);
    fsUploadFile = SPIFFS.open(filename, "w");
    filename = String();
  } else if (upload.status == UPLOAD_FILE_WRITE) {
    if (fsUploadFile) fsUploadFile.write(upload.buf, upload.currentSize);
  } else if (upload.status == UPLOAD_FILE_END) {
    if (fsUploadFile) fsUploadFile.close();
    DBG_OUTPUT_PORT.println("handleFileUpload Size: " +
                            String(upload.totalSize));
  }
}

void handleFileList() {
  if (basicAuthFailed()) return;
  if (!server.hasArg("dir")) {
    server.send(400, "text/plain", "BAD ARGS");
    return;
  }

  String path = server.arg("dir");
  DBG_OUTPUT_PORT.println("handleFileList: " + path);

  File dir = SPIFFS.open(path);

  String output = "[";
  while (File file = dir.openNextFile()) {
    if (strstr(file.path(), ".gz") != NULL) {
      continue;
    }
    if (strstr(file.path(), ".html") != NULL) {
      continue;
    }
    if (strstr(file.path(), "/static") != NULL) {
      continue;
    }

    if (output != "[") {
      output += ",";
    }
    output += "{\"type\":";
    output += jsonString(file.isDirectory() ? "dir" : "file");
    output += ",\"name\":";
    output += jsonString(String(file.path()).substring(1));
    output += "}";
  }

  output += "]";

  dir.close();
  server.send(200, "application/json", output);
}

void handleDoS() {
  if (basicAuthFailed())
    return;
  jamming_enable();
  server.send(200, F("text/plain"), "");
  output_debug_string(F("DoS MODE"));
  append_log("dos", "enabled by API request");
}

void handleDisableDoS() {
  if (basicAuthFailed())
    return;
  jamming_disable();
  server.send(200, F("text/plain"), "");
  output_debug_string(F("DoS MODE deactivated"));
  append_log("dos", "disabled by API request");
}

void handleRestart() {
  if (basicAuthFailed())
    return;
  output_debug_string(F("RESET"));
  append_log("boot", "reset by API request");
  server.send(200, "text/plain", "OK");
  ESP.restart();
}

void clearConfig() {
  if (basicAuthFailed())
    return;
  clear_config();
  server.send(200, "text/plain", "OK");
  ESP.restart();
}

// Files that carry secrets: the WiFi PSK, the web and OTA passwords, the OSDP
// secure channel key, and the record of every credential the device has seen.
// They get their own explicitly authenticated handlers, registered ahead of
// any static handler, so that they stay behind the password even if someone
// later adds a catch-all serveStatic back.
static void handleProtectedFile() {
  if (basicAuthFailed()) return;
  if (!handleFileRead(server.uri())) {
    server.send(404, "text/plain", "FileNotFound");
  }
}

void http_init(void) {
  server.on("/config.txt", HTTP_GET, handleProtectedFile);
  server.on("/config.default", HTTP_GET, handleProtectedFile);
  server.on("/log.txt", HTTP_GET, handleProtectedFile);

  // SERVER INIT
  server.on("/dos", HTTP_GET, handleDoS);
  server.on("/disabledos", HTTP_GET, handleDisableDoS);
  server.on("/txid", HTTP_GET, handleTxId);
  server.on("/clear", HTTP_GET, clearConfig);

  // list directory
  server.on("/list", HTTP_GET, handleFileList);
  // load editor
  server.on("/edit", HTTP_GET, []() {
    if (basicAuthFailed()) return;
    if (!handleFileRead("/editor.html")) {
      server.send(404, "text/plain", "FileNotFound");
    }
  });

  // first callback is called after the request has ended with all parsed
  // arguments, second callback handles file uploads at that location
  server.on(
      "/edit", HTTP_POST,
      []() {
        if (basicAuthFailed()) return;
        server.send(200, "text/plain", "");
      },
      handleFileUpload);
  server.on("/restart", HTTP_GET, handleRestart);

  // called when the url is not defined here
  // use it to load content from SPIFFS
  server.onNotFound([]() {
    if (basicAuthFailed()) return;
    if (!handleFileRead(server.uri()))
      server.send(404, "text/plain", "FileNotFound");
  });

  server.on("/version", HTTP_GET, []() {
    if (basicAuthFailed()) return;

    if (server.hasArg("epoch")) {
      static bool epoch_registered = false;
      if (!epoch_registered) {
        append_log("epoch", server.arg("epoch"));
        epoch_registered = true;
      }
    }

    // Feature and mode lists are built from the registry, so a new protocol
    // shows up here without this file being touched.
    String features;
#ifdef USE_BLE
    features += jsonString("ble") + ",";
#endif
#ifdef USE_WIFI
    features += jsonString("wifi") + ",";
#endif
#ifdef USE_MDNS_RESPONDER
    features += jsonString("mdns") + ",";
#endif
#ifdef USE_OTA
    features += jsonString("ota") + ",";
#endif
#ifdef USE_OTA_HTTP
    features += jsonString("ota_http") + ",";
#endif
#ifdef USE_SYSLOG
    features += jsonString("syslog") + ",";
#endif
#ifdef USE_LCD
    features += jsonString("lcd") + ",";
#endif
    for (size_t i = 0; i < tick_protocol_registry_count; i++) {
      const tick_protocol *proto = tick_protocol_registry[i];
      if (proto == &tick_protocol_disabled) continue;
      features += jsonString(proto->name) + ",";
    }
    features += jsonString("http");

    String modes;
    for (size_t i = 0; i < tick_protocol_registry_count; i++) {
      if (i) modes += ",";
      modes += jsonString(tick_protocol_registry[i]->name);
    }

    String json = "{";
    json += "\"version\":" + jsonString(VERSION);
    json += ",\"log_name\":" + jsonString(log_name);
    json += ",\"board\":" + jsonString(TICK_BOARD.name);
    json += ",\"ChipID\":" + jsonString(String(getChipID(), HEX));
    json += ",\"features\":[" + features + "]";
    json += ",\"modes\":[" + modes + "]";
    json += ",\"mode\":" + jsonString(tick_proto_name());
    json += ",\"auth\":" + String(www_auth_disabled ? "false" : "true");
    json += "}\n";
    server.send(200, "application/json", json);
  });

  // Findings and bus state, for the assessment page and the client report.
  server.on("/osdp.json", HTTP_GET, []() {
    if (basicAuthFailed()) return;

    static char findings[2048];
    tick_findings_to_json(&tick_global_findings, findings, sizeof(findings));

    String json = "{";
    json += "\"device\":" + jsonString(String(log_name) + "-" +
                                       String(getChipID(), HEX));
    json += ",\"board\":" + jsonString(TICK_BOARD.name);
    json += ",\"version\":" + jsonString(VERSION);
    json += ",\"mode\":" + jsonString(tick_proto_name());
    json += ",\"uptime_ms\":" + String(millis());
    json += ",\"boot\":" + String(getBootCount());
    json += ",\"worst\":" +
            jsonString(tick_severity_name(tick_findings_worst(&tick_global_findings)));
    json += ",\"dropped\":" + String(tick_global_findings.dropped);

#ifdef USE_OSDP_MONITOR
    const osdp_monitor *mon = osdp_monitor_state();
    json += ",\"bus\":{\"frames\":" + String(mon->frames_seen) +
            ",\"bad_frames\":" + String(mon->frames_bad) + "}";

    json += ",\"peers\":[";
    bool first_peer = true;
    for (int i = 0; i < OSDP_MONITOR_MAX_PEERS; i++) {
      const osdp_peer_state *p = &mon->peers[i];
      if (!p->in_use) continue;
      if (!first_peer) json += ",";
      first_peer = false;
      json += "{\"address\":" + String(p->address);
      json += ",\"secure\":" + String(p->saw_secure_data ? "true" : "false");
      json += ",\"handshake\":" + String(p->saw_handshake ? "true" : "false");
      json += ",\"cleartext_frames\":" + String(p->cleartext_frames);
      json += ",\"cleartext_card_reads\":" + String(p->cleartext_card_reads);
      json += ",\"crypto_advertised\":" +
              String(p->cap_known ? (p->cap_supports_crypto ? "true" : "false")
                                  : "null");
      json += ",\"key_recovered\":" +
              String(p->key_recovered ? "true" : "false");
      json += "}";
    }
    json += "]";
#else
    json += ",\"bus\":null,\"peers\":[]";
#endif

    json += ",\"findings\":";
    json += findings;
    json += "}\n";
    server.send(200, "application/json", json);
  });

  // get heap status, analog input value and all GPIO statuses in one json call
  server.on("/all", HTTP_GET, []() {
    if (basicAuthFailed()) return;

    uint32_t data = (digitalRead(tick_pin.d0) == HIGH ? 1 : 0) * 1 +
                    (digitalRead(tick_pin.d1) == HIGH ? 1 : 0) * 2 +
                    (digitalRead(tick_pin.aux) == HIGH ? 1 : 0) * 4 +
                    (digitalRead(tick_pin.reset) == HIGH ? 1 : 0) * 8;

    String json = "{";
    json += "\"heap\":" + String(ESP.getFreeHeap());
    json += ", \"vdc\":" + String(readVDCVoltage());
    json += ", \"gpio\":" + String((uint32_t)data);
    json += "}";
    server.send(200, "application/json", json);
  });

  // Static files.
  //
  // serveStatic registers its own handler that runs before onNotFound and
  // never consults basicAuthFailed(), so anything it covers is world
  // readable. The previous setup mapped the whole filesystem that way, which
  // handed out config.txt - WiFi PSK, web password, OTA password, OSDP secure
  // channel key - and the captured credential log to anyone who asked.
  //
  // Only the vendored CSS and JS under /static is served this way now.
  // Everything else falls through to onNotFound, which checks the password
  // first. There is deliberately no catch-all here: a prefix match on "/"
  // would put every one of those files back on the open path.
  server.serveStatic("/static", SPIFFS, "/static", "max-age=86400");

#ifdef USE_OTA_HTTP
  // Firmware upload demands the same password as everything else. Without
  // this it is an unauthenticated remote code execution primitive.
  if (strlen(www_username) > 0 && strlen(www_password) > 0) {
    httpUpdater.setup(&server, www_username, www_password);
  } else {
    output_debug_string(F("HTTP OTA disabled: set an http password first"));
  }
#endif
  server.begin();
}

void http_loop(void) {
  // Check for HTTP requests
  server.handleClient();
}

#else

void http_init(void) {}
void http_loop(void) {}

#endif
