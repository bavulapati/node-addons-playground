const addon = require("bindings")("timer");
let timer;
let ticks = 0;

function onTick() {
  ticks++;
  console.log("Timer tick");
  if (ticks === 5) {
    addon.stopTimer(timer);
  }
}

timer = addon.startTimer(onTick, 1000);
