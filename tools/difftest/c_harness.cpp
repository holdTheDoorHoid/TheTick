// Reads one hex-encoded buffer per line and prints a canonical description of
// what the C dissector made of it. The Rust harness prints the same format
// over the same corpus, and the two are compared byte for byte.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "../../src/tick_osdp_dissect.cpp"

static void emit(const char *status, const osdp_frame *f, size_t consumed) {
  if (f == NULL) {
    printf("%s\n", status);
    return;
  }
  printf("%s addr=%u rep=%d len=%u seq=%u crc=%d scb=", status,
         (unsigned)f->address, f->is_reply ? 1 : 0, (unsigned)f->length,
         (unsigned)f->sequence, f->uses_crc ? 1 : 0);
  if (f->has_scb) {
    printf("%02x:", (unsigned)f->scb_type);
    for (int i = 0; i < f->scb_data_len; i++) printf("%02x", f->scb_data[i]);
  } else {
    printf("none");
  }
  printf(" id=%02x enc=%d tv=%d used=%zu pl=", (unsigned)f->id,
         f->payload_encrypted ? 1 : 0, f->trailer_valid ? 1 : 0, consumed);
  for (uint16_t i = 0; i < f->payload_len; i++) printf("%02x", f->payload[i]);
  printf("\n");
}

int main() {
  char line[8192];
  while (fgets(line, sizeof(line), stdin)) {
    std::vector<uint8_t> buf;
    for (size_t i = 0; line[i] && line[i] != '\n'; i += 2) {
      unsigned v = 0;
      if (sscanf(line + i, "%2x", &v) != 1) break;
      buf.push_back((uint8_t)v);
    }

    osdp_frame f;
    size_t consumed = 0;
    // Always hand over a valid pointer, even for an empty buffer. Passing
    // NULL would exercise the C null guard rather than the empty-input path,
    // which is not what the Rust side receives.
    uint8_t placeholder = 0;
    osdp_dissect_result r = osdp_dissect(
        buf.empty() ? &placeholder : buf.data(), buf.size(), &f, &consumed);

    switch (r) {
      case OSDP_DISSECT_OK:
      case OSDP_DISSECT_BAD_TRAILER:
        // Normalised: the Rust version returns a frame with trailer_valid
        // false rather than a separate error, which is the same information.
        emit("ok", &f, consumed);
        break;
      case OSDP_DISSECT_NEED_MORE: emit("need_more", NULL, 0); break;
      case OSDP_DISSECT_NO_SOM: emit("no_som", NULL, 0); break;
      case OSDP_DISSECT_BAD_LENGTH: emit("bad_length", NULL, 0); break;
      case OSDP_DISSECT_BAD_SCB: emit("bad_scb", NULL, 0); break;
      default: emit("other", NULL, 0); break;
    }
  }
  return 0;
}
