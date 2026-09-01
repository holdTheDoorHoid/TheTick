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

// Plain language for each finding. The device reports a short identifier; a
// person reading a report needs to know what it means and what to do, without
// having read the OSDP specification.
const FINDING_INFO = {
  cleartext_session: {
    title: "Bus is not encrypted",
    means: "This reader and controller talk with no secure channel at all. Anyone who can reach the two data wires can read every badge presented.",
    fix: "Turn on OSDP secure channel at the controller and the reader, and configure the controller to refuse readers that will not use it."
  },
  cleartext_card_read: {
    title: "Badge numbers readable on the wire",
    means: "A credential crossed the wire unencrypted. It can be copied and replayed by anything attached to the cable.",
    fix: "Enable the secure channel. Until then, treat the cable run as if it were the far side of the door."
  },
  no_crypto_advertised: {
    title: "Reader reports it cannot encrypt",
    means: "The reader told the controller it does not support encryption, so the controller did not attempt it. Either the reader genuinely cannot, or something on the wire rewrote that message.",
    fix: "Confirm the reader's real capabilities against its datasheet. If it does support encryption, treat this as evidence of a device in the cable."
  },
  capability_changed: {
    title: "Reader's capabilities were rewritten in transit",
    means: "The reader advertised encryption support and later advertised none. Readers do not change what they are, so something between the reader and the controller is altering messages.",
    fix: "Inspect the cable run for an inline device. This is the signature of an active downgrade attack."
  },
  keyset_on_wire: {
    title: "Encryption key sent over the cable",
    means: "The secure channel key was installed across the wire. Anyone listening at that moment now holds it and can decrypt everything afterwards.",
    fix: "Re-key from a trusted position: pair the reader to the controller on a short inspected cable, then install it. Treat the current key as compromised."
  },
  install_mode: {
    title: "Controller is stuck in install mode",
    means: "Keys have been installed repeatedly. A controller left in install mode will hand its key to any device that asks, including one an attacker plants.",
    fix: "Disable install mode on the controller and verify it stays disabled after a reboot."
  },
  install_mode_key_disclosed: {
    title: "Controller gave up its key on request",
    means: "This device asked the controller for the site key and the controller supplied it. The key in the evidence column is the real one, recovered live. Anything that can reach these wires can do the same.",
    fix: "Disable install mode immediately, then re-key every reader on this controller."
  },
  default_key: {
    title: "Default encryption key in use",
    means: "The secure channel is using SCBK-D, the default key printed in the OSDP specification. It is public, so the encryption is decorative.",
    fix: "Install a randomly generated key on every reader and confirm the default is no longer accepted."
  },
  weak_key: {
    title: "Encryption key guessed",
    means: "The base key was recovered from the handshake in under a second by trying the patterns that appear in sample code. The key in the evidence column is the real one.",
    fix: "Re-key with randomly generated material. Do not use patterns, and do not reuse a key across sites."
  },
  null_cipher: {
    title: "Secure channel is not encrypting",
    means: "The channel is running in a mode that checks messages for tampering but does not encrypt them, so badge numbers remain readable.",
    fix: "Configure both ends to use the encrypting secure channel modes."
  },
  security_regression: {
    title: "Encrypted session fell back to cleartext",
    means: "A session that had established encryption reverted to unencrypted messages without a reset. That is what forcing a downgrade mid-conversation looks like.",
    fix: "Inspect the cable run, and configure the controller to refuse unencrypted messages once a secure channel exists."
  },
  sc_retry_storm: {
    title: "Repeated failed handshakes",
    means: "The secure channel is being attempted over and over without succeeding, which is what key guessing looks like from the side. It can also be a genuine key mismatch.",
    fix: "Check that the reader and controller hold the same key."
  },
  credential_replay_accepted: {
    title: "Replayed badge was accepted",
    means: "A credential captured from this bus was presented back to the controller by this device, and the controller accepted it - releasing the door output or telling the reader to signal success. A copied badge works here.",
    fix: "Enable the OSDP secure channel so captured traffic cannot be replayed, and review whether the controller should accept a reader that appears without prior enrolment."
  },
  credential_replay_rejected: {
    title: "Replayed badge reached the controller but was refused",
    means: "A credential was injected onto the bus and the controller processed it, then refused it. The injection path works even though this particular card was not accepted - a valid one would be.",
    fix: "Enable the OSDP secure channel. The concern is that unauthenticated messages are being processed at all."
  },
  sequence_anomaly: {
    title: "Messages arriving out of order",
    means: "A message arrived with an unexpected sequence number, which can indicate injected traffic. It can also be a noisy cable.",
    fix: "Check cable quality and termination before treating this as an attack."
  }
};

// Findings that require the device to have transmitted on the bus rather
// than merely listened. The method statement in the report depends on this,
// and a report that understates what was done to a client's system is worse
// than no report.
const ACTIVE_FINDINGS = ["install_mode_key_disclosed",
                         "credential_replay_accepted",
                         "credential_replay_rejected"];

// Modes that can transmit. Monitor mode opens its UART without a transmit
// pin, so replay is not merely disabled in the interface - it is impossible.
const TRANSMITTING_MODES = ["osdp_pd", "wiegand", "clockanddata"];

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEVERITY_CLASS = {
  critical: "badge-danger",
  high: "badge-danger",
  medium: "badge-warning",
  low: "badge-secondary",
  info: "badge-light"
};

let latest = null;

function describe(name) {
  return FINDING_INFO[name] || {
    title: name,
    means: "No description available for this finding.",
    fix: ""
  };
}

function duration(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m";
  const h = Math.floor(m / 60);
  return h + "h " + (m % 60) + "m";
}

function renderVerdict(data) {
  const count = data.findings.length;
  let cls, text;

  if (count === 0) {
    cls = "alert-success";
    text = "No findings yet. Leave the device attached while the system is in normal use — a bus is only assessed once it has been observed carrying traffic.";
  } else if (SEVERITY_ORDER[data.worst] >= 4) {
    cls = "alert-danger";
    text = "Critical: the encryption on this bus can be defeated. Credentials presented here can be read and replayed.";
  } else if (SEVERITY_ORDER[data.worst] >= 3) {
    cls = "alert-danger";
    text = "High: credentials on this bus are exposed, or something is altering traffic in the cable.";
  } else {
    cls = "alert-warning";
    text = "Weaknesses were observed on this bus. See the findings below.";
  }

  $("#verdict").html("").append(
    $("<div>").addClass("alert " + cls).attr("role", "alert").text(text)
  );
}

function renderFindings(data) {
  const body = $("#findings_body").empty();

  const sorted = data.findings.slice().sort(function (a, b) {
    return (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0);
  });

  if (sorted.length === 0) {
    body.append($("<tr>").append(
      $("<td>").attr("colspan", 6).addClass("text-center text-gray-500")
        .text("Nothing observed yet.")));
    return;
  }

  sorted.forEach(function (f) {
    const info = describe(f.name);
    const row = $("<tr>");

    row.append($("<td>").append(
      $("<span>").addClass("badge " + (SEVERITY_CLASS[f.severity] || "badge-secondary"))
        .text(f.severity)));

    const titleCell = $("<td>").append(
      $("<strong>").text(info.title),
      $("<div>").addClass("small text-gray-600").text(f.name));
    if (ACTIVE_FINDINGS.indexOf(f.name) !== -1) {
      titleCell.append($("<div>").addClass("small text-gray-700 mt-1")
        .append($("<em>").text("Required transmitting on the bus")));
    }
    row.append(titleCell);

    const means = $("<td>").append($("<div>").text(info.means));
    if (info.fix) {
      means.append($("<div>").addClass("small text-gray-700 mt-1")
        .append($("<strong>").text("Remediation: "), document.createTextNode(info.fix)));
    }
    row.append(means);

    row.append($("<td>").text(f.address === null ? "-" : f.address));
    row.append($("<td>").append($("<code>").text(f.detail || "-")));
    row.append($("<td>").text(f.count + "x, over " + duration(f.last_ms - f.first_ms)));

    body.append(row);
  });
}

function renderPeers(data) {
  const body = $("#peers_body").empty();

  if (!data.peers || data.peers.length === 0) {
    body.append($("<tr>").append(
      $("<td>").attr("colspan", 6).addClass("text-center text-gray-500")
        .text("No peripherals observed.")));
    return;
  }

  data.peers.forEach(function (p) {
    const yesNo = function (v) {
      if (v === null) return "unknown";
      return v ? "yes" : "no";
    };
    body.append($("<tr>")
      .append($("<td>").text(p.address))
      .append($("<td>").text(yesNo(p.secure)))
      .append($("<td>").text(yesNo(p.crypto_advertised)))
      .append($("<td>").text(p.cleartext_frames))
      .append($("<td>").text(p.cleartext_card_reads))
      .append($("<td>").text(yesNo(p.key_recovered))));
  });
}

// The client deliverable. Everything needed to reproduce and act on the
// finding, in a form that can be pasted into an engagement report.
function buildReport(data) {
  const lines = [];
  const now = new Date();

  lines.push("OSDP BUS ASSESSMENT");
  lines.push("===================");
  lines.push("");
  lines.push("Generated:    " + now.toISOString());
  lines.push("Device:       " + data.device);
  lines.push("Board:        " + data.board);
  lines.push("Firmware:     " + data.version);
  lines.push("Mode:         " + data.mode);
  lines.push("Observed for: " + duration(data.uptime_ms) + " (boot " + data.boot + ")");
  if (data.bus) {
    lines.push("Frames:       " + data.bus.frames + " (" + data.bus.bad_frames +
               " failed integrity check)");
  }
  lines.push("");

  if (data.findings.length === 0) {
    lines.push("No findings were recorded during this observation window.");
    lines.push("");
    lines.push("Note: an absence of findings is only meaningful if the bus was");
    lines.push("carrying normal traffic throughout. Check the frame count above.");
    return lines.join("\n");
  }

  lines.push("SUMMARY");
  lines.push("-------");
  const bySeverity = {};
  data.findings.forEach(function (f) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  });
  ["critical", "high", "medium", "low", "info"].forEach(function (sev) {
    if (bySeverity[sev]) lines.push("  " + sev + ": " + bySeverity[sev]);
  });
  lines.push("");

  lines.push("FINDINGS");
  lines.push("--------");
  const sorted = data.findings.slice().sort(function (a, b) {
    return (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0);
  });

  sorted.forEach(function (f, i) {
    const info = describe(f.name);
    lines.push("");
    lines.push((i + 1) + ". [" + f.severity.toUpperCase() + "] " + info.title);
    lines.push("   Identifier:  " + f.name);
    if (f.address !== null) lines.push("   Peripheral:  address " + f.address);
    lines.push("   Occurrences: " + f.count);
    lines.push("   First seen:  " + duration(f.first_ms) + " after boot");
    lines.push("   Last seen:   " + duration(f.last_ms) + " after boot");
    if (f.detail) lines.push("   Evidence:    " + f.detail);
    lines.push("");
    lines.push("   What it means:");
    lines.push("     " + info.means);
    if (info.fix) {
      lines.push("");
      lines.push("   Remediation:");
      lines.push("     " + info.fix);
    }
  });

  if (data.peers && data.peers.length) {
    lines.push("");
    lines.push("PERIPHERALS OBSERVED");
    lines.push("--------------------");
    data.peers.forEach(function (p) {
      lines.push("  Address " + p.address +
                 ": secure channel " + (p.secure ? "yes" : "no") +
                 ", cleartext frames " + p.cleartext_frames +
                 ", credentials in the clear " + p.cleartext_card_reads +
                 (p.key_recovered ? ", KEY RECOVERED" : ""));
    });
  }

  if (data.dropped > 0) {
    lines.push("");
    lines.push("Note: " + data.dropped + " further findings were not recorded " +
               "because the evidence store was full.");
  }

  const active = data.findings.filter(function (f) {
    return ACTIVE_FINDINGS.indexOf(f.name) !== -1;
  });

  lines.push("");
  lines.push("METHOD");
  lines.push("------");
  lines.push("Findings are based on the OSDP weaknesses published by Bishop Fox");
  lines.push("(\"Badge of Shame\", 2023).");
  lines.push("");
  lines.push("Passive findings were obtained by observing the RS-485 pair only;");
  lines.push("the device did not transmit. Recovered encryption keys were");
  lines.push("obtained by recomputing the secure channel handshake against");
  lines.push("known-weak key patterns, using data the bus had already sent.");

  if (active.length > 0) {
    lines.push("");
    lines.push("The following finding(s) required the device to transmit on the");
    lines.push("bus, presenting itself to the controller as a peripheral:");
    active.forEach(function (f) {
      lines.push("  - " + f.name + " (address " + f.address + ")");
    });
    lines.push("");
    lines.push("No door was released and no credential was replayed in obtaining");
    lines.push("these. They are listed separately because they involved active");
    lines.push("interaction with the system rather than observation alone.");
  } else {
    lines.push("");
    lines.push("No traffic was transmitted onto the bus during this assessment.");
  }

  return lines.join("\n");
}

function downloadReport() {
  if (!latest) return;
  const text = buildReport(latest);
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "osdp-assessment-" + latest.device + ".txt";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function replay(value) {
  if (!confirm("Present " + value + " to the controller as if a badge had " +
               "been swiped?\n\nThis transmits on the client's live access " +
               "control bus and may unlock a door.")) {
    return;
  }
  $.get("/txid?v=" + encodeURIComponent(value))
    .done(function () {
      alert("Sent " + value + ".\n\nWatch the findings table: if the " +
            "controller accepts it, that appears within a few seconds.");
      setTimeout(refresh, 1500);
    })
    .fail(function (xhr) {
      alert("Refused: " + xhr.status + " " + xhr.responseText);
    });
}

// Captured credentials come from the log, which is where every capture lands
// regardless of which wire protocol saw it.
function renderCredentials(data) {
  const body = $("#credentials_body").empty();
  const notice = $("#replay_notice").empty();

  const canTransmit = TRANSMITTING_MODES.indexOf(data.mode) !== -1;
  if (!canTransmit) {
    notice.append($("<div>").addClass("alert alert-info mb-0")
      .text("This device is in " + data.mode + " mode, which never transmits. " +
            "To replay a captured credential, switch the mode to osdp_pd in " +
            "the configuration and restart."));
  }

  $.get("/log.txt", function (log) {
    const rows = [];
    log.trim().split("\n").forEach(function (line) {
      const parts = line.split("; ");
      if (parts.length < 4) return;
      if (parts[2].indexOf("osdp") !== 0) return;
      const value = parts[3];
      if (!/^[0-9a-fA-F]+:[0-9]+$/.test(value)) return;
      rows.push({ boot: parts[0], ms: parseInt(parts[1], 10), value: value });
    });

    if (rows.length === 0) {
      body.append($("<tr>").append(
        $("<td>").attr("colspan", 4).addClass("text-center text-gray-500")
          .text("No credentials captured in the clear.")));
      return;
    }

    rows.reverse().slice(0, 50).forEach(function (r) {
      const parts = r.value.split(":");
      const row = $("<tr>")
        .append($("<td>").text("boot " + r.boot + ", " + duration(r.ms)))
        .append($("<td>").append($("<code>").text(parts[0])))
        .append($("<td>").text(parts[1]));

      const btn = $("<button>").addClass("btn btn-sm btn-danger")
        .text("Replay").attr("data-value", r.value);
      if (!canTransmit) btn.prop("disabled", true);
      row.append($("<td>").append(btn));
      body.append(row);
    });

    body.off("click", "button[data-value]").on("click", "button[data-value]",
      function () { replay($(this).attr("data-value")); });
  });
}

function refresh() {
  $.getJSON("/osdp.json", function (data) {
    latest = data;
    $("#stat_frames").text(data.bus ? data.bus.frames : "n/a");
    $("#stat_bad").text(data.bus ? data.bus.bad_frames : "n/a");
    $("#stat_peers").text(data.peers ? data.peers.length : 0);
    $("#stat_findings").text(data.findings.length);
    renderVerdict(data);
    renderFindings(data);
    renderPeers(data);
    renderCredentials(data);
  });
}

$(document).ready(function () {
  $("#download_report").on("click", downloadReport);
  refresh();
  setInterval(refresh, 5000);
});
