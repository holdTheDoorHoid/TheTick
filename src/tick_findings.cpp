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

#include "tick_findings.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

tick_findings tick_global_findings;

void tick_findings_init(tick_findings *store) {
  if (store == NULL) return;
  memset(store, 0, sizeof(*store));
}

// Copy only printable ASCII, and never a quote or backslash. The detail field
// carries values read off a wire, and the report they end up in is JSON.
// Filtering on the way in beats escaping on the way out, because there is
// exactly one way in and several ways out.
static void copy_sanitised(char *dst, size_t dst_len, const char *src) {
  size_t n = 0;
  if (dst_len == 0) return;
  if (src != NULL) {
    for (size_t i = 0; src[i] != '\0' && n + 1 < dst_len; i++) {
      unsigned char c = (unsigned char)src[i];
      if (c < 0x20 || c > 0x7E) continue;
      if (c == '"' || c == '\\') continue;
      dst[n++] = (char)c;
    }
  }
  dst[n] = '\0';
}

void tick_finding_record(tick_findings *store, const char *name,
                         const char *detail, tick_severity severity,
                         bool has_address, uint8_t address, uint32_t now_ms) {
  if (store == NULL || name == NULL || name[0] == '\0') return;

  char clean_name[TICK_FINDING_NAME_LEN];
  copy_sanitised(clean_name, sizeof(clean_name), name);
  if (clean_name[0] == '\0') return;

  // Same finding against the same peripheral folds into one row.
  for (size_t i = 0; i < TICK_MAX_FINDINGS; i++) {
    tick_finding *f = &store->items[i];
    if (!f->used) continue;
    if (strcmp(f->name, clean_name) != 0) continue;
    if (f->has_address != has_address) continue;
    if (has_address && f->address != address) continue;

    f->count++;
    f->last_ms = now_ms;
    if (severity > f->severity) f->severity = severity;
    // A later observation with a value beats an earlier one without.
    if (detail != NULL && detail[0] != '\0' && f->detail[0] == '\0') {
      copy_sanitised(f->detail, sizeof(f->detail), detail);
    }
    return;
  }

  for (size_t i = 0; i < TICK_MAX_FINDINGS; i++) {
    tick_finding *f = &store->items[i];
    if (f->used) continue;

    f->used = true;
    memcpy(f->name, clean_name, sizeof(f->name));
    copy_sanitised(f->detail, sizeof(f->detail), detail);
    f->severity = severity;
    f->has_address = has_address;
    f->address = address;
    f->first_ms = now_ms;
    f->last_ms = now_ms;
    f->count = 1;
    return;
  }

  // Full. Counted rather than silently discarded, so a report can say so.
  store->dropped++;
}

const char *tick_severity_name(tick_severity severity) {
  switch (severity) {
    case TICK_SEVERITY_CRITICAL: return "critical";
    case TICK_SEVERITY_HIGH: return "high";
    case TICK_SEVERITY_MEDIUM: return "medium";
    case TICK_SEVERITY_LOW: return "low";
    default: return "info";
  }
}

size_t tick_findings_count(const tick_findings *store) {
  size_t n = 0;
  if (store == NULL) return 0;
  for (size_t i = 0; i < TICK_MAX_FINDINGS; i++) {
    if (store->items[i].used) n++;
  }
  return n;
}

tick_severity tick_findings_worst(const tick_findings *store) {
  tick_severity worst = TICK_SEVERITY_INFO;
  if (store == NULL) return worst;
  for (size_t i = 0; i < TICK_MAX_FINDINGS; i++) {
    if (store->items[i].used && store->items[i].severity > worst) {
      worst = store->items[i].severity;
    }
  }
  return worst;
}

// Append to a bounded buffer, tracking how much has been written. Returning
// the would-be length lets the caller notice truncation without ever writing
// past the end.
static void append(char *out, size_t out_len, size_t *pos, const char *fmt,
                   ...) {
  if (*pos >= out_len) return;
  va_list args;
  va_start(args, fmt);
  int n = vsnprintf(out + *pos, out_len - *pos, fmt, args);
  va_end(args);
  if (n < 0) return;
  *pos += (size_t)n;
  if (*pos >= out_len) *pos = out_len - 1;
}

size_t tick_findings_to_json(const tick_findings *store, char *out,
                             size_t out_len) {
  if (out == NULL || out_len == 0) return 0;
  out[0] = '\0';

  // "[]" plus a terminator is the smallest valid document. Anything smaller
  // gets an empty string rather than a lone opening bracket.
  if (out_len < 3) return 0;

  if (store == NULL) {
    snprintf(out, out_len, "[]");
    return strlen(out);
  }

  size_t pos = 0;
  append(out, out_len, &pos, "[");

  bool first = true;
  for (size_t i = 0; i < TICK_MAX_FINDINGS; i++) {
    const tick_finding *f = &store->items[i];
    if (!f->used) continue;

    // Stop cleanly rather than emitting a half written object, always
    // leaving room for the closing bracket and the terminator. A truncated
    // report that is valid JSON can still be read; a corrupt one cannot.
    if (pos + 160 + 2 >= out_len) break;

    append(out, out_len, &pos, "%s{", first ? "" : ",");
    first = false;
    append(out, out_len, &pos, "\"name\":\"%s\"", f->name);
    append(out, out_len, &pos, ",\"severity\":\"%s\"",
           tick_severity_name(f->severity));
    append(out, out_len, &pos, ",\"detail\":\"%s\"", f->detail);
    if (f->has_address) {
      append(out, out_len, &pos, ",\"address\":%u", (unsigned)f->address);
    } else {
      append(out, out_len, &pos, ",\"address\":null");
    }
    append(out, out_len, &pos, ",\"first_ms\":%lu", (unsigned long)f->first_ms);
    append(out, out_len, &pos, ",\"last_ms\":%lu", (unsigned long)f->last_ms);
    append(out, out_len, &pos, ",\"count\":%lu}", (unsigned long)f->count);
  }

  append(out, out_len, &pos, "]");
  return strlen(out);
}
