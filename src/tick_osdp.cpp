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
#include <soc/soc_caps.h>

#include "tick_board.h"
#include "tick_default_config.h"
#include "tick_osdp.h"
#include "tick_utils.h"

// Transceiver pins live at file scope even when OSDP is compiled out, because
// setup() puts the RS-485 driver into high impedance on every boot regardless
// of mode - an implant that leaves a transceiver driving the bus is an
// implant that gets noticed.
static int pin_de = TICK_PIN_NONE;
static int pin_re = TICK_PIN_NONE;
static int pin_rx = TICK_PIN_NONE;
static int pin_tx = TICK_PIN_NONE;
static int pin_term = TICK_PIN_NONE;

void osdp_pins_defaults(void) {
  pin_de = TICK_BOARD.osdp_pin_de;
  pin_re = TICK_BOARD.osdp_pin_re;
  pin_rx = TICK_BOARD.osdp_pin_rx;
  pin_tx = TICK_BOARD.osdp_pin_tx;
  pin_term = TICK_BOARD.osdp_pin_term;
}

void osdp_pins_configure(SPIFFSIniFile &ini, char *buffer, size_t buffer_len) {
  int value = 0;

  // Deliberately no reset to board defaults here. config.default is read
  // first and config.txt is overlaid on top of it, so re-seeding on every
  // pass would throw away whatever config.default set for any key the
  // operator's own file happens not to mention.

  if (ini.getValue("osdp", "pin_de", buffer, buffer_len, value)) pin_de = value;
  if (ini.getValue("osdp", "pin_re", buffer, buffer_len, value)) pin_re = value;
  if (ini.getValue("osdp", "pin_rx", buffer, buffer_len, value)) pin_rx = value;
  if (ini.getValue("osdp", "pin_tx", buffer, buffer_len, value)) pin_tx = value;
  if (ini.getValue("osdp", "pin_term", buffer, buffer_len, value)) {
    pin_term = value;
  }

  pin_de = tick_pin_checked("osdp.pin_de", pin_de, TICK_BOARD.osdp_pin_de, true);
  pin_re = tick_pin_checked("osdp.pin_re", pin_re, TICK_BOARD.osdp_pin_re, true);
  pin_rx = tick_pin_checked("osdp.pin_rx", pin_rx, TICK_BOARD.osdp_pin_rx, false);
  pin_tx = tick_pin_checked("osdp.pin_tx", pin_tx, TICK_BOARD.osdp_pin_tx, true);
  pin_term =
      tick_pin_checked("osdp.pin_term", pin_term, TICK_BOARD.osdp_pin_term, true);
}

void osdp_disable_transceiver(void) {
  // Driver disabled, outputs high impedance.
  if (tick_pin_is_valid_output(pin_de)) {
    pinMode(pin_de, OUTPUT);
    digitalWrite(pin_de, LOW);
  }
  if (tick_pin_is_valid(pin_tx)) pinMode(pin_tx, INPUT);

  // Receiver disabled (active low enable held high).
  if (tick_pin_is_valid_output(pin_re)) {
    pinMode(pin_re, OUTPUT);
    digitalWrite(pin_re, HIGH);
  }
  if (tick_pin_is_valid(pin_rx)) pinMode(pin_rx, INPUT);

  // Terminator off. The sentinel for "no terminator fitted" used to be -1
  // stored in a uint8_t, so it arrived as 255 and this guard never fired -
  // meaning the firmware called pinMode(255, OUTPUT) on every board.
  if (pin_term != TICK_PIN_NONE && tick_pin_is_valid_output(pin_term)) {
    pinMode(pin_term, OUTPUT);
    digitalWrite(pin_term, LOW);
  }
}

// UART0 is the console, so it is deliberately not offered here.
static HardwareSerial *uart_for(uint8_t index) {
  switch (index) {
#if SOC_UART_NUM > 1
    case 1:
      return &Serial1;
#endif
#if SOC_UART_NUM > 2
    case 2:
      return &Serial2;
#endif
    default:
      return NULL;
  }
}

// Bring the transceiver up receive-only and hand back the UART.
//
// This is what passive monitoring needs and it deliberately does not depend
// on libosdp: a build that only listens does not need a protocol stack, and
// keeping the dependency out means the monitor also fits a minimal image.
HardwareSerial *osdp_listen_begin(int baudrate) {
  if (!tick_pin_is_valid(pin_rx) || !tick_pin_is_valid_output(pin_de) ||
      !tick_pin_is_valid_output(pin_re)) {
    output_debug_string(F("OSDP listen: transceiver pins not usable"));
    return NULL;
  }

  HardwareSerial *serial = uart_for(TICK_BOARD.osdp_uart);
  if (serial == NULL) {
    output_debug_string(F("OSDP listen: no UART available"));
    return NULL;
  }

  // Driver off, receiver on. Nothing this mode does ever drives the bus.
  pinMode(pin_de, OUTPUT);
  digitalWrite(pin_de, LOW);
  pinMode(pin_re, OUTPUT);
  digitalWrite(pin_re, LOW);
  pinMode(pin_rx, INPUT);
  if (tick_pin_is_valid(pin_tx)) pinMode(pin_tx, INPUT);

  // Receive only: no TX pin is handed to the driver, so the firmware cannot
  // transmit even by mistake.
  serial->begin(baudrate, SERIAL_8N1, pin_rx, -1);
  return serial;
}

void osdp_listen_end(HardwareSerial *serial) {
  if (serial) serial->end();
  osdp_disable_transceiver();
}

#ifdef USE_OSDP

#include <osdp.hpp>

#include "tick_capture.h"

static OSDP::PeripheralDevice pd;
static OSDP::ControlPanel cp;

// Module-owned settings.
static int baudrate = OSDP_BAUDRATE;
static int address = 101;
static bool terminator_enabled = false;
static char scbk_hex[CONFIG_PASSWORD_LENGTH] = {0};
static uint8_t scbk_raw[16];

static HardwareSerial *osdp_serial = NULL;
static bool pd_ready = false;
static bool cp_ready = false;
static bool jamming = false;

static osdp_pd_info_t pd_info[] = {{
    .name = "pd[101]",
    .baud_rate = OSDP_BAUDRATE,
    .address = 101,
    .flags = 0,
    .id =
        {
            .version = 1,
            .model = 153,
            .vendor_code = 31337,
            .serial_number = 0x01020304,
            .firmware_version = 0x0A0B0C0D,
        },
    .cap =
        (struct osdp_pd_cap[]){
            {.function_code = OSDP_PD_CAP_READER_LED_CONTROL,
             .compliance_level = 1,
             .num_items = 1},
            {.function_code = OSDP_PD_CAP_READERS,
             .compliance_level = 1,
             .num_items = 1},
            {.function_code = OSDP_PD_CAP_CARD_DATA_FORMAT,
             .compliance_level = 1,
             .num_items = 1},
            {static_cast<uint8_t>(-1), 0, 0} /* Sentinel */
        },
    .channel = {.data = nullptr,
                .id = 0,
                .recv = nullptr,
                .send = nullptr,
                .flush = nullptr},
    .scbk = nullptr,
}};

int osdp_serial_send_func(void *data, uint8_t *buf, int len) {
  (void)(data);
  if (osdp_serial == NULL) return -1;
  return osdp_serial->write(buf, (size_t)len);
}

int osdp_serial_recv_func(void *data, uint8_t *buf, int len) {
  (void)(data);
  if (osdp_serial == NULL) return -1;
  return osdp_serial->read(buf, (size_t)len);
}

int osdp_pd_event_handler(void *data, struct osdp_cmd *cmd) {
  (void)(data);
  if (cmd == NULL) return -1;
  append_log("osdp", String("command ") + String((int)cmd->id) + " received");
  return 0;
}

int osdp_cp_event_handler(void *data, int pd_idx, struct osdp_event *event) {
  (void)(data);
  (void)(pd_idx);
  if (event == NULL) return -1;

  if (event->type == OSDP_EVENT_CARDREAD) {
    // A card read arriving at the control panel is the interesting case: it
    // is a credential presented to the reader we are sitting behind.
    int bits = event->cardread.length;
    int bytes = (bits + 7) / 8;
    if (bytes > OSDP_EVENT_CARDREAD_MAX_DATALEN) {
      bytes = OSDP_EVENT_CARDREAD_MAX_DATALEN;
    }

    String hex;
    hex.reserve((unsigned int)(bytes * 2 + 1));
    for (int i = 0; i < bytes; i++) {
      hex += c2h((unsigned char)(event->cardread.data[i] >> 4));
      hex += c2h((unsigned char)(event->cardread.data[i] & 0x0F));
    }
    hex.toUpperCase();
    card_read_handler(hex + ":" + String(bits));
  } else {
    append_log("osdp", String("event ") + String((int)event->type));
  }
  return 0;
}

// --- shared setup -----------------------------------------------------------

static void osdp_configure(SPIFFSIniFile &ini, char *buffer,
                           size_t buffer_len) {
  int value = 0;
  bool flag = false;

  if (ini.getValue("osdp", "baudrate", buffer, buffer_len, value)) {
    // libosdp accepts these six rates; anything else is a typo, and silently
    // running at a different speed than the config claims is worse than
    // saying so.
    if (value == 9600 || value == 19200 || value == 38400 || value == 57600 ||
        value == 115200 || value == 230400) {
      baudrate = value;
    } else {
      output_debug_string(String("Invalid OSDP baudrate ") + value +
                          ", using " + OSDP_BAUDRATE);
      baudrate = OSDP_BAUDRATE;
    }
  }

  if (ini.getValue("osdp", "address", buffer, buffer_len, value)) {
    // OSDP addresses are 7 bit; 0x7F is the broadcast address.
    if (value >= 0 && value <= 0x7F) {
      address = value;
    } else {
      output_debug_string(String("Invalid OSDP address ") + value);
    }
  }

  if (ini.getValue("osdp", "terminator", buffer, buffer_len, flag)) {
    terminator_enabled = flag;
  }

  ini.getValue("osdp", "scbk", buffer, buffer_len, scbk_hex,
               CONFIG_PASSWORD_LENGTH);
}

// Bring up the transceiver and the UART. Shared by both modes.
static bool osdp_common_init(void) {
  if (!tick_pin_is_valid_output(pin_de) || !tick_pin_is_valid_output(pin_tx) ||
      !tick_pin_is_valid(pin_rx) || !tick_pin_is_valid_output(pin_re)) {
    output_debug_string(F("OSDP: transceiver pins not usable on this board"));
    return false;
  }

  osdp_serial = uart_for(TICK_BOARD.osdp_uart);
  if (osdp_serial == NULL) {
    output_debug_string(F("OSDP: no UART available for this board"));
    return false;
  }

  // Park the Wiegand lines so the reader interface is not driving while OSDP
  // owns the wires.
  if (tick_pin_is_valid_output(tick_pin.d0)) {
    pinMode(tick_pin.d0, OUTPUT);
    digitalWrite(tick_pin.d0, HIGH);
  }
  if (tick_pin_is_valid_output(tick_pin.d1)) {
    pinMode(tick_pin.d1, OUTPUT);
    digitalWrite(tick_pin.d1, HIGH);
  }

  pinMode(pin_de, OUTPUT);
  digitalWrite(pin_de, LOW);
  pinMode(pin_re, OUTPUT);
  digitalWrite(pin_re, LOW);
  pinMode(pin_tx, OUTPUT);
  digitalWrite(pin_tx, LOW);
  pinMode(pin_rx, INPUT);

  if (pin_term != TICK_PIN_NONE && tick_pin_is_valid_output(pin_term)) {
    pinMode(pin_term, OUTPUT);
    digitalWrite(pin_term, terminator_enabled ? HIGH : LOW);
  }

  // This configuration at the first glance is a bit counterintuitive:
  // - receiver is permanently enabled, as:
  //    - it is used for collision detection
  //    - echo is suppresed by UART hardware
  // - hardware flow in the UART controller is DISABLED, as it doesn't support
  // half-duplex communication
  // - RTS signal is controlled the software UART driver
  // - CTS signal is not used
  osdp_serial->begin(baudrate, SERIAL_8N1, pin_rx, pin_tx);
  osdp_serial->setMode(UART_MODE_RS485_HALF_DUPLEX);
  osdp_serial->setPins(pin_rx, pin_tx, -1, pin_de);
  osdp_serial->setHwFlowCtrlMode(UART_HW_FLOWCTRL_DISABLE, 122);

  pd_info[0].channel.recv = osdp_serial_recv_func;
  pd_info[0].channel.send = osdp_serial_send_func;
  pd_info[0].baud_rate = baudrate;
  pd_info[0].address = address;

  // A secure channel base key is 16 bytes, written as 32 hex characters.
  // Anything else means no secure channel rather than a half-parsed key.
  size_t scbk_len = strnlen(scbk_hex, CONFIG_PASSWORD_LENGTH);
  if (scbk_len == 32) {
    for (int i = 0; i < 16; i++) {
      scbk_raw[i] = (uint8_t)(hex_to_byte(scbk_hex[i * 2]) << 4 |
                              hex_to_byte(scbk_hex[i * 2 + 1]));
    }
    pd_info[0].scbk = scbk_raw;
  } else {
    if (scbk_len != 0) {
      output_debug_string(F("OSDP: scbk must be 32 hex characters, ignoring"));
    }
    pd_info[0].scbk = nullptr;
  }

  return true;
}

static void osdp_shutdown_transceiver(void) {
  if (osdp_serial) osdp_serial->end();
  osdp_disable_transceiver();
}

// Jamming: hold the reader's data lines down.
//
// NOTE for anyone working on OSDP with hardware in hand: this drives the
// Wiegand GPIOs, inherited from the original implementation. On the Tick the
// reader connector's two data wires are shared between the Wiegand level
// shifter and the RS-485 transceiver, so whether this actually disrupts an
// OSDP bus depends on the board revision, and it has not been verified here.
// The protocol-level alternative is to assert DE with TX held low so the
// transceiver drives the pair to a dominant state - do not do both at once,
// as that puts the level shifter and the transceiver in contention.
static void osdp_jam_on(void) {
  if (jamming) return;
  if (tick_pin_is_valid_output(tick_pin.d0)) {
    pinMode(tick_pin.d0, OUTPUT);
    digitalWrite(tick_pin.d0, LOW);
  }
  if (tick_pin_is_valid_output(tick_pin.d1)) {
    pinMode(tick_pin.d1, OUTPUT);
    digitalWrite(tick_pin.d1, LOW);
  }
  jamming = true;
}

static void osdp_jam_off(void) {
  if (!jamming) return;
  if (tick_pin_is_valid_output(tick_pin.d0)) digitalWrite(tick_pin.d0, HIGH);
  if (tick_pin_is_valid_output(tick_pin.d1)) digitalWrite(tick_pin.d1, HIGH);
  jamming = false;
}

// --- peripheral device mode -------------------------------------------------

static bool osdp_pd_init(void) {
  if (!osdp_common_init()) return false;

  pd.logger_init("osdp::pd", OSDP_LOG_DEBUG, NULL);

  // setup() returns false when libosdp refuses the configuration. Carrying on
  // regardless leaves a null context that refresh() then walks into.
  if (!pd.setup(pd_info)) {
    output_debug_string(F("OSDP: peripheral device setup failed"));
    osdp_shutdown_transceiver();
    return false;
  }

  pd.set_command_callback(osdp_pd_event_handler, nullptr);
  pd_ready = true;
  output_debug_string(F("OSDP Peripheral Device started"));
  return true;
}

static void osdp_pd_loop(void) {
  if (!pd_ready) return;
  // libosdp wants refresh() called as often as possible; there is no rate
  // limit to apply here. The previous code had one that never fired because
  // its subtraction was reversed, which happened to give the right behaviour
  // for the wrong reason.
  pd.refresh();
}

static void osdp_pd_tx(const char *hex, size_t hex_len, unsigned long bits) {
  if (!pd_ready) {
    append_log("tx", "refused, OSDP not running");
    return;
  }

  osdp_event card_event = {
      .type = OSDP_EVENT_CARDREAD,
      .flags = 0,
      .cardread = osdp_event_cardread{
          .reader_no = 0, .format = OSDP_CARD_FMT_RAW_WIEGAND, .direction = 1}};

  // Bound the copy to the event buffer. This loop previously ran for
  // strlen(value)/2 iterations with no limit, so a long value posted to /txid
  // wrote straight past a 64 byte array on the stack.
  size_t bytes =
      osdp_cardread_bytes(hex_len, bits, OSDP_EVENT_CARDREAD_MAX_DATALEN);

  for (size_t i = 0; i < bytes; i++) {
    card_event.cardread.data[i] =
        (uint8_t)(hex_to_byte(hex[i * 2]) << 4 | hex_to_byte(hex[i * 2 + 1]));
  }

  unsigned long max_bits = (unsigned long)bytes * 8;
  if (bits > max_bits) {
    output_debug_string(String("OSDP: card data truncated to ") + bytes +
                        " bytes");
  }
  card_event.cardread.length = (int)(bits > max_bits ? max_bits : bits);

  pd.submit_event(&card_event);
}

const tick_protocol tick_protocol_osdp_pd = {
    .name = "osdp_pd",
    .short_name = "OSDP-PD",
    .ui_page = NULL,
    .configure = osdp_configure,
    .init = osdp_pd_init,
    .attach = NULL,
    .detach = NULL,
    .loop = osdp_pd_loop,
    .tx = osdp_pd_tx,
    .jam_on = osdp_jam_on,
    .jam_off = osdp_jam_off,
};

// --- control panel mode -----------------------------------------------------

static bool osdp_cp_init(void) {
  if (!osdp_common_init()) return false;

  // In control panel mode we are the one asking, so we advertise no
  // capabilities and no identity of our own.
  pd_info[0].cap = nullptr;
  pd_info[0].id = {};

  cp.logger_init("osdp::cp", OSDP_LOG_DEBUG, NULL);

  if (!cp.setup(1, pd_info)) {
    output_debug_string(F("OSDP: control panel setup failed"));
    osdp_shutdown_transceiver();
    return false;
  }

  cp.set_event_callback(osdp_cp_event_handler, nullptr);
  cp_ready = true;
  output_debug_string(F("OSDP Control Panel started"));
  return true;
}

static void osdp_cp_loop(void) {
  if (!cp_ready) return;
  cp.refresh();
  // There used to be a cp.submit_command(0, nullptr) here, on every pass.
  // libosdp reads cmd->flags without a null check; it only survived because
  // the call returns early while the peripheral is offline, so the crash
  // waited until the mode actually started working.
}

const tick_protocol tick_protocol_osdp_cp = {
    .name = "osdp_cp",
    .short_name = "OSDP-CP",
    .ui_page = NULL,
    .configure = osdp_configure,
    .init = osdp_cp_init,
    .attach = NULL,
    .detach = NULL,
    .loop = osdp_cp_loop,
    // A control panel receives credentials, it does not present them.
    .tx = NULL,
    .jam_on = osdp_jam_on,
    .jam_off = osdp_jam_off,
};

#endif
