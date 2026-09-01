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

// Corporate 1000 bit default layouts (override if the target uses a custom mapping)
const C1000_LAYOUTS = {
  35: { fcStart: 2, fcLen: 12, cnStart: 14, cnLen: 20 }, // Bits 3–14 (Company/Facility), 15–34 (Card #)
  48: { fcStart: 2, fcLen: 22, cnStart: 24, cnLen: 23 }, // Bits 3–24 (Company/Facility), 25–47 (Card #)
};

// Helper to extract fields using the layout definition
function decodeCorporate1000(binaryData, bitLength) {
  const L = C1000_LAYOUTS[bitLength];
  if (!L) return null;
  const facilityCode = parseInt(binaryData.substring(L.fcStart, L.fcStart + L.fcLen), 2);
  const cardNumber  = parseInt(binaryData.substring(L.cnStart, L.cnStart + L.cnLen), 2);
  // For display, provide the raw hex (no preamble).
  const paddedData  = parseInt(binaryData, 2).toString(16).toUpperCase();
  const format = bitLength === 35 ? "C1000-35" : "C1000-48";
  return { format, facilityCode, cardNumber, paddedData };
}

function decodeWiegand(rawData, bitLength) {
  let binaryData = 
    parseInt(rawData, 16).toString(2).padStart(bitLength, '0');
  let format, facilityCode, cardNumber, preamble, paddedData;

  switch (bitLength) {
    case 26:
      format = "H10301";
      facilityCode = parseInt(binaryData.substring(1, 9), 2);
      cardNumber = parseInt(binaryData.substring(9, 25), 2);
      preamble = '000000100000000001';
      paddedData = parseInt((preamble + binaryData), 2).toString(16);
      break;
    case 35: { // HID Corporate 1000 (35-bit. Configurable in C1000_LAYOUTS)
      const c = decodeCorporate1000(binaryData, 35);
      if (c) ({ format, facilityCode, cardNumber, paddedData } = c);
      else { format = "C1000-35"; facilityCode = "N/A"; cardNumber = "N/A"; paddedData = "N/A"; }
      break;
    }
    case 37:
      format = "H10304";
      facilityCode = parseInt(binaryData.substring(1, 17), 2);
      cardNumber = parseInt(binaryData.substring(17, 36), 2);
      preamble = '0000000';
      paddedData = parseInt((preamble + binaryData), 2).toString(16);
      break;
    case 46:
      format = "H800002";
      facilityCode = parseInt(binaryData.substring(1, 15), 2);
      cardNumber = parseInt(binaryData.substring(15, 45), 2);
      paddedData = 'N/A';
      break;
    case 48: { // HID Corporate 1000 (48-bit variant. Configurable in C1000_LAYOUTS)
      const c = decodeCorporate1000(binaryData, 48);
      if (c) ({ format, facilityCode, cardNumber, paddedData } = c);
      else { format = "C1000-48"; facilityCode = "N/A"; cardNumber = "N/A"; paddedData = "N/A"; }
      break;
    }
    default:
      format = "Unknown";
      facilityCode = "N/A";
      cardNumber = "N/A";
      paddedData = 'N/A';
  }

  return { format, facilityCode, cardNumber, paddedData };
}

// Helpers to count bits and calculate even/odd parity
function _bitCount(x) {
  let v = (typeof x === "bigint") ? x : BigInt(x);
  let count = 0n;
  while (v) {
    v &= v - 1n;
    count += 1n;
  }
  return Number(count);
}

const _evenParityBit = s => {
    let count = 0;
    for (let i = 0; i < s.length; i++) {
        if (s[i] === '1') count++;
    }
    return count % 2 === 0 ? 0 : 1;
};

const _oddParityBit = s => {
    let count = 0;
    for (let i = 0; i < s.length; i++) {
        if (s[i] === '1') count++;
    }
    return count % 2 === 1 ? 0 : 1;
};

function calculateWiegandParity(rawData, bitLength) {
  const isTriple = (bitLength === 35 || bitLength === 48);
  const dataLen = bitLength - (isTriple ? 3 : 2);
  const binaryData = parseInt(rawData, 16).toString(2).padStart(dataLen, '0');

  let p1, p2, p3;

  switch (bitLength) {
    case 26: {
      const first = binaryData.substring(0, 12);
      const last  = binaryData.substring(12);
      p1  = _evenParityBit(first);
      p2  = _oddParityBit(last);
      break;
    }
    case 37: {
      const first = binaryData.substring(0, 18);
      const last  = binaryData.substring(18);
      p1  = _evenParityBit(first);
      p2  = _oddParityBit(last);
      break;
    }
    case 46: {
      p1  = _evenParityBit(binaryData);
      p2  = _oddParityBit(binaryData);
      break;
    }
    case 35: {
      const cardData = BigInt('0x' + rawData);
      p1 = (_bitCount(cardData & 0x1B6DB6DB6n) & 1) ^ 1;
      const forP2 = (BigInt(p1) << 33n) | cardData;
      p2 = (_bitCount(forP2 & 0x36DB6DB6Cn) & 1);
      const pre = (BigInt(p1) << 34n) | (BigInt(p2) << 33n) | (cardData << 1n);
      p3 = (_bitCount(pre) & 1) ^ 1;
      break;
    }
    case 48: {
      const cardData = BigInt('0x' + rawData);
      const base = cardData << 1n;
      p2 = _bitCount(base & 0x1B6DB6DB6DB6n) & 1;
      let withP2 = base | (BigInt(p2) << 46n);
      p3 = (_bitCount(withP2 & 0x36DB6DB6DB6Cn) & 1) ^ 1;
      let withP2P3 = withP2 | BigInt(p3);
      p1 = (_bitCount(withP2P3 & 0x7FFFFFFFFFFFn) & 1) ^ 1;
      break;
    }
    default:
      return { error: "Unsupported bit length" };
  }

  return { p1, p2, p3 };
}

function encodeWiegand(format, facilityCode, cardNumber) {
  let bitLength;
  let binaryData;

  switch (format) {
    case "H10301":
      bitLength  = 26;
      binaryData = facilityCode.toString(2).padStart(8, '0')
                 + cardNumber.toString(2).padStart(16, '0');
      break;
    case "H10304":
      bitLength  = 37;
      binaryData = facilityCode.toString(2).padStart(16, '0')
                 + cardNumber.toString(2).padStart(19, '0');
      break;
    case "H800002":
      bitLength  = 46;
      binaryData = facilityCode.toString(2).padStart(14, '0')
                 + cardNumber.toString(2).padStart(30, '0');
      break;
    case "C1000-35":
      bitLength  = 35;
      binaryData = facilityCode.toString(2).padStart(12, '0')
                 + cardNumber.toString(2).padStart(20, '0');
      break;
    case "C1000-48":
      bitLength  = 48;
      binaryData = facilityCode.toString(2).padStart(22, '0')
                 + cardNumber.toString(2).padStart(23, '0');
      break;
    default:
      return { error: "Unsupported format" };
  }

  const { p1, p2, p3 } =
    calculateWiegandParity(parseInt(binaryData, 2).toString(16), bitLength);

  let encodedData;
  if (bitLength === 35 || bitLength === 48) {
    // 3 parity bits: [p1][p2] DATA [p3]
    encodedData = `${p1}${p2}${binaryData}${p3}`;
  } else {
    // 2 parity bits: [p1] DATA [p2]
    encodedData = `${p1}${binaryData}${p2}`;
  }
  return parseInt(encodedData, 2).toString(16).toUpperCase() + ":" + String(bitLength);
}

function send_wiegand(data) {
  $.get("/txid?v=" + encodeURIComponent(data))
    .done(function () { alert(`Data sent: ${data}`); })
    .fail(function (xhr) { alert(`Send refused: ${xhr.status} ${xhr.responseText}`); });
}

function send_wiegand_raw(event) {
  event.preventDefault();
  let wiegand_raw = $("#wiegand_raw")[0].value;
  send_wiegand(wiegand_raw);

  return false;
}

function send_wiegand_formatted(event) {
  event.preventDefault();
  let wiegand_format = $("#wiegand_format")[0].value;
  let wiegand_fc = parseInt($("#wiegand_fc")[0].value, 10);
  let wiegand_cn = parseInt($("#wiegand_cn")[0].value, 10);

  let wiegand_raw = encodeWiegand(
    wiegand_format,
    wiegand_fc,
    wiegand_cn
  );

  send_wiegand(wiegand_raw);

  return false;
}

$(document).ready(function () {
  $.get("/log.txt", function (data) {
    let lines = data.trim().split("\n");
    let tableBody = "";
    let epochs = get_epochs(lines);
    // epoch, timestamp, facility, data  
    lines.forEach(line => {
      let parts = line.split("; ");
      if (parts[2] == "wiegand") {
        let wiegand = parts[3];
        let dataParts = wiegand.split(":");
        if (dataParts.length === 2) {
          let rawData = dataParts[0];
          let bitLength = parseInt(dataParts[1], 10);

          if (rawData.length != bitLength) {
            let { format, facilityCode, cardNumber, paddedData } = decodeWiegand(rawData, bitLength);
            let time = get_epoch_time(epochs, parts[0], parts[1]);
            // Values here come from the log, which holds data read off the
            // wire and text supplied over HTTP. Escaped, and the replay
            // control carries its value in a data attribute rather than in
            // an inline onclick that the value could break out of.
            tableBody += `<tr><td>${esc(time)}</td><td>${esc(wiegand)}</td><td>${esc(format)}</td><td>${esc(facilityCode)}</td><td>${esc(cardNumber)}</td><td>${esc(paddedData)}</td><td><i class="fas fa-reply tick-replay" role="button" tabindex="0" data-value="${esc(wiegand)}"></i></td></tr>`;
          }
        }
      }
    });
    $("#dataTable tbody").html(tableBody);
    $("#dataTable tbody").on("click", ".tick-replay", function () {
      send_wiegand($(this).attr("data-value"));
    });
    $('#dataTable').DataTable();
  });
});
