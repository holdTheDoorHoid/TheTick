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

function decode_aba_track_ii(card_data) {
  function get_num(bcd) {
    return String(8 * bcd[3] + 4 * bcd[2] + 2 * bcd[1] + 1 * bcd[0]);
  }

  let decoded_data = "";
  for (let i = 0; i < card_data.length; i += 5) {
    let group = card_data.substr(i, 5);
    let data_bits = group.substr(0, 4);
    let parity_bit = group.substr(4, 1);

    // Check odd parity
    let ones_count = data_bits.split('1').length - 1;
    if ((ones_count % 2) == parseInt(parity_bit)) {
      return false;
    }

    decoded_data += get_num(data_bits);
  }
  let hexID = BigInt(decoded_data).toString(16).toUpperCase();
  decoded_hex = hexID.padStart(10, '0');
  return decoded_hex;
}

function decode_magstripe_unitek_aba_track_ii(data) {
  let l = data.length;
  let start_sentinel = data.substr(0, 5); // 11010

  let card_data = data.substr(15, l - 35);

  let end_sentinel = data.substr(l - 10, 5); // 11111
  let lrc = data.substr(l - 5, 5); // Longitudinal Redundancy Check


  if (start_sentinel != "11010")
    return false;

  return decode_aba_track_ii(card_data);
}

function decode_magstripe_aba_track_ii(data) {
  let l = data.length;
  let leading_zeros = data.substr(0, 10); // 00000 00000
  let start_sentinel = data.substr(10, 5); // 11010

  let card_data = data.substr(15, l - 35);

  let end_sentinel = data.substr(l - 20, 5); // 11111
  let lrc = data.substr(l - 15, 5); // Longitudinal Redundancy Check
  let trailing_zeros = data.substr(l - 10, 10); // 00000 00000


  if (leading_zeros != "0000000000" || start_sentinel != "11010" || trailing_zeros != "0000000000")
    return false;

  return decode_aba_track_ii(card_data);
}

// 0000000000110100000100001100000000101000010000110100010101101100101000011010010010011000100100010000000010000110000000010000110000001001011000001000010000100001000010000100001000010000100001000010000111111011100000000000
function decode_magstripe_paxton_aba_track_ii(data) {
  let l = data.length;
  let leading_zeros = data.substr(0, 10); // 00000 00000
  let start_sentinel = data.substr(10, 5); // 11010

  let card_data = data.substr(15, l - 35);
  data_block_0 = card_data.substr(0, 8 * 5); // 0000100001100000000101000010000110100010
  sentinel_d_1 = card_data.substr(8 * 5, 5); // 10110
  data_block_1 = card_data.substr(9 * 5, 15 * 5); // 110010100001101001001001100010010001000000001000011000000001000011000000100
  sentinel_d_2 = card_data.substr(24 * 5, 5); // 10110
  data_block_2 = card_data.substr(25 * 5, 12 * 5); // 000010000100001000010000100001000010000100001000010000100001

  let end_sentinel = data.substr(l - 20, 5); // 11111
  let lrc = data.substr(l - 15, 5); // 10111 - Longitudinal Redundancy Check
  let trailing_zeros = data.substr(l - 10, 10); // 00000 00000

  if (leading_zeros != "0000000000" || start_sentinel != "11010" || sentinel_d_1 != "10110" || sentinel_d_2 != "10110" || trailing_zeros != "0000000000")
    return false;

  let decoded_block_0 = parseInt(decode_aba_track_ii(data_block_0), 16).toString(10);
  let decoded_block_1 = parseInt(decode_aba_track_ii(data_block_1), 16).toString(10);
  let decoded_block_2 = parseInt(decode_aba_track_ii(data_block_2), 16).toString(10);

  var card_type = "unknown";
  switch (decoded_block_1[decoded_block_1.length - 2]) {
    case "1": card_type = "Switch2 Fob";
  }

  var card_color = decoded_block_1[decoded_block_1.length - 1];
  switch (decoded_block_1[decoded_block_1.length - 1]) {
    case "1": card_color = "green";
    case "2": card_color = "yellow";
    case "4": card_color = "red";
  }

  return "Card number: " + decoded_block_0 + "<br>" +
    "Card type: " + card_type + "<br>" +
    "Card colour: " + card_color + "<br>" +
    "Card data 1: " + decoded_block_1 + "<br>" +
    "Card data 2: " + decoded_block_2;
}

function decodeClockAndData(rawData, bitLength) {
  let format, cardData;

  let data = false;
  raw = rawData;
  format = "??";
  cardData = "??";

  data = decode_magstripe_paxton_aba_track_ii(rawData);
  if (data !== false) {
    raw = 'length: ' + bitLength;
    format = "Magstripe Paxton";
    cardData = data;
    return { raw, format, cardData };
  }

  data = decode_magstripe_aba_track_ii(rawData);
  if (data !== false) {
    raw = 'length: ' + bitLength;
    format = "Magstripe ABA track II";
    cardData = data;
    return { raw, format, cardData };
  }

  data = decode_magstripe_unitek_aba_track_ii(rawData);
  if (data !== false) {
    raw = 'length: ' + bitLength;
    format = "Magstripe UNITEK";
    cardData = data;
    return { raw, format, cardData };
  }

  return { raw, format, cardData };
}


function encodeClockAndData(format, cardData) {
  //     let bitLength;
  //     let binaryData;

  switch (format) {
    //         case "Magstripe ABA track II":
    //         bitLength = 26;
    //         binaryData = facilityCode.toString(2).padStart(8, '0') + cardNumber.toString(2).padStart(16, '0');
    //         break;
    //         case "H10304":
    //         bitLength = 37;
    //         binaryData = facilityCode.toString(2).padStart(16, '0') + cardNumber.toString(2).padStart(19, '0');
    //         break;
    //         case "H800002":
    //         bitLength = 46;
    //         binaryData = facilityCode.toString(2).padStart(14, '0') + cardNumber.toString(2).padStart(30, '0');
    //         break;
    default:
      return { error: "Unsupported format" };
  }

  //     let { evenParity, oddParity } = calculateWiegandParity(parseInt(binaryData, 2).toString(16), bitLength);
  //     let encodedData = evenParity.toString() + binaryData + oddParity.toString();
  //     return parseInt(encodedData, 2).toString(16).toUpperCase() + ":" + bitLength.toString(10);
}


function send_clockanddata(data) {
  $.get("/txid?v=" + data);
  alert(`Data sent: ${data}`);
}


function send_clockanddata_raw(event) {
  event.preventDefault();
  let wiegand_raw = $("#wiegand_raw")[0].value;
  send_wiegand(wiegand_raw);

  return false;
}

function send_clockanddata_formatted(event) {
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
      if (parts[2] == "clockanddata") {
        let clockanddata = parts[3].trim()
        let dataParts = clockanddata.split(":");
        if (dataParts.length === 2) {
          let rawData = dataParts[0];
          let bitLength = parseInt(dataParts[1], 10);

          console.log(rawData);

          if (rawData.length == bitLength) {
            let { raw, format, cardData } = decodeClockAndData(rawData, bitLength);
            let time = get_epoch_time(epochs, parts[0], parts[1]);
            tableBody += `<tr><td>${esc(time)}</td><td>${esc(raw)}</td><td>${esc(format)}</td><td>${esc(cardData)}</td><td><i class="fas fa-reply tick-replay" role="button" tabindex="0" data-value="${esc(clockanddata)}"></i></td></tr>`;
          }
        }
      }
    });
    $("#dataTable tbody").html(tableBody);
    $("#dataTable tbody").on("click", ".tick-replay", function () {
      send_clockanddata($(this).attr("data-value"));
    });
    $('#dataTable').DataTable();
  });
});
