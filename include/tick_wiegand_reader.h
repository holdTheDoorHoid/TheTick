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

// This code is based on ESPKey, by Kenny McElroy
// https://github.com/octosavvi/ESPKey/blob/master/ESPKey.ino
// released under GNU General Public License version 2.

#ifndef TICK_WIEGAND_READER_H
#define TICK_WIEGAND_READER_H

#include "tick_protocol.h"

#ifdef USE_WIEGAND
extern const tick_protocol tick_protocol_wiegand;
#endif

#endif
