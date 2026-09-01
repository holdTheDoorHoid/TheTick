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

#include <esp32-hal-gpio.h>
#include <esp32-hal-rgb-led.h>
#include "tick_heartbeat.h"

// A pulsing LED on a device hidden inside a card reader is a liability, so it
// is a configured choice rather than a compile-time accident of which board
// definition happens to declare an RGB LED.
bool heartbeat_enabled = true;

#ifdef RGB_BUILTIN

struct Color {
  int r, g, b;
};

void heartbeat_init(void) {}

void heartbeat_loop(void) {
  if (!heartbeat_enabled) return;

  constexpr Color colors[] = {
      {32, 49, 84}, {227, 65, 70}, {124, 138, 165}, {69, 94, 124}};

  static int currentColorIndex = 0;
  static unsigned long startTime = millis();
  static unsigned long last_step = millis();

  unsigned long now = millis();
  // Reversed subtraction here used to make this condition true on almost
  // every call, and last_step was never updated.
  if ((unsigned long)(now - last_step) > 10) {
    unsigned long elapsed = now - startTime;

    float t = float(elapsed) / 1000;

    if (t >= 1.0) {
      startTime = now;
      currentColorIndex = (currentColorIndex + 1) % 4;
      t = 0.0;
    }

    int nextColorIndex = (currentColorIndex + 1) % 4;

    Color c1 = colors[currentColorIndex];
    Color c2 = colors[nextColorIndex];

    int r = c1.r + (c2.r - c1.r) * t;
    int g = c1.g + (c2.g - c1.g) * t;
    int b = c1.b + (c2.b - c1.b) * t;

    neopixelWrite(RGB_BUILTIN, r/5, g/5, b/5);

    last_step = now;
  }
}

#else

void heartbeat_init(void) { pinMode(LED_BUILTIN, OUTPUT); }

void heartbeat_loop(void) {
  if (!heartbeat_enabled) return;

  static unsigned int counter = 0;
  static unsigned long step = 0;
  unsigned long now = micros();

  if(now - step > 500000){
    step = now;
    if (counter++ % 2) {
      digitalWrite(LED_BUILTIN, HIGH);
    } else {
      digitalWrite(LED_BUILTIN, LOW);
    }
  }
}

#endif