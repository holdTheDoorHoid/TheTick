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

// This code comes from ESP Monitor example

var heap, digi, vdc;
var reloadPeriod = 100;
var running = false;

function loadValues() {
  if (!running) return;
  var xh = new XMLHttpRequest();
  xh.onreadystatechange = function () {
    if (xh.readyState == 4) {
      if (xh.status == 200) {
        var res = JSON.parse(xh.responseText);
        heap.add(res.heap);
        vdc.add(res.vdc);
        digi.add(res.gpio);
        if (running) setTimeout(loadValues, reloadPeriod);
      } else running = false;
    }
  };
  xh.open("GET", "/all", true);
  xh.send(null);
};

function run() {
  if (!running) {
    running = true;
    loadValues();
  }
}

function onBodyLoad() {
  var refreshInput = document.getElementById("refresh-rate");
  refreshInput.value = reloadPeriod;
  refreshInput.onchange = function (e) {
    var value = parseInt(e.target.value);
    reloadPeriod = (value > 0) ? value : 0;
    e.target.value = reloadPeriod;
  }
  var stopButton = document.getElementById("stop-button");
  stopButton.onclick = function (e) {
    running = false;
  }
  var startButton = document.getElementById("start-button");
  startButton.onclick = function (e) {
    run();
  }
  vdc = createGraph(document.getElementById("vdc"), "VDC (mV)", 100, 125, 0, 30000, true, "white");
  heap = createGraph(document.getElementById("heap"), "Current Heap", 100, 125, 0, 30000, true, "orange");
  digi = createDigiGraph(document.getElementById("digital"), "GPIO (D0, D1, AUX, RST)", 100, 146, [3, 2, 1, 0], "gold");
  run();
}

function get_features() {
  $.getJSON("/version", function (data) {

    $("#body_features").html(
      "<ul>" + data.features.map(a => "<li>" + esc(a) + "</li>").join("") + "</ul>");

  });
}

$(document).ready(function () {
  onBodyLoad();
  get_features();
});
