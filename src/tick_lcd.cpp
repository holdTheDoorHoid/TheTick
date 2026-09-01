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

#include "tick_lcd.h"

#ifdef USE_LCD
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Wire.h>
#include <tick_default_config.h>

#define logo_w 24
#define logo_h 16

const unsigned char logo_b [] PROGMEM= {
  0x00, 0x81, 0x01, 0x80, 0x81, 0x01, 0x80, 0x19, 0x03, 0xb0, 0xbd, 0x09,
  0x60, 0xbd, 0x0c, 0xe0, 0x7d, 0x07, 0xc0, 0xff, 0x03, 0xe0, 0xff, 0x07,
  0xe0, 0xff, 0x0f, 0xb0, 0xff, 0x09, 0xd0, 0x7e, 0x1b, 0x60, 0x7c, 0x02,
  0x60, 0x3c, 0x06, 0x60, 0x00, 0x06, 0x40, 0x00, 0x06, 0x00, 0x00, 0x00 };

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

void display_string(String data) {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println(data);
  display.display();
}


void display_status_message(String data){
  
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 3*(SCREEN_HEIGHT/4));

  display.print(data);

  display.display();
}

void display_tick_logo(){
  display.clearDisplay();
  display.drawXBitmap(SCREEN_WIDTH-logo_w, 0, logo_b, logo_w, logo_h, SSD1306_WHITE);
  display.display();
}

void display_line(int line, bool invert, String data){
  display.setTextSize(1);
  display.setTextColor(invert ? SSD1306_BLACK : SSD1306_WHITE);
  if(line < 2){
    display.fillRect(0, line*(SCREEN_HEIGHT/4), SCREEN_WIDTH-logo_w, SCREEN_HEIGHT/4, invert ? SSD1306_WHITE :SSD1306_BLACK);
    display.setCursor(16, line * 8);
  }else {
    display.fillRect(0, line*(SCREEN_HEIGHT/4), SCREEN_WIDTH, SCREEN_HEIGHT/4, invert ? SSD1306_WHITE :SSD1306_BLACK);
    display.setCursor(0, line * 8);
  }
  display.print(data);
  display.display();
}

// Held as a start time plus a duration rather than an absolute deadline in an
// int, which overflowed after about 24.8 days of uptime and then compared
// wrong against an unsigned millis().
static unsigned long temporary_message_start = 0;
static unsigned long temporary_message_duration = 0;
static bool temporary_message_active = false;

void display_temporary_message(String data, int duration){
  display_line(3, true, data);
  display.dim(false);
  temporary_message_start = millis();
  temporary_message_duration = (duration > 0) ? (unsigned long)duration : 0;
  temporary_message_active = true;
}

void display_loop(){
  if (!temporary_message_active) return;
  if ((unsigned long)(millis() - temporary_message_start) >=
      temporary_message_duration) {
    display_line(3, false, "");
    temporary_message_active = false;
    display.dim(true);
    display.display();
  }
}

void display_init() {
  display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS);
  display_tick_logo();
}
#else

// Every symbol tick_lcd.h declares needs a stub here. display_line() and
// display_status_message() were missing, so any build without USE_LCD failed
// to link - which is why only the two shipped flag combinations ever built.
void display_string(String data) { (void)data; }
void display_status_message(String data) { (void)data; }
void display_line(int line, bool invert, String data) {
  (void)line;
  (void)invert;
  (void)data;
}
void display_temporary_message(String data, int duration) {
  (void)data;
  (void)duration;
}
void display_init() {}
void display_loop() {}

#endif