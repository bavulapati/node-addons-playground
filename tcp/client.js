const tcp = require("bindings")("tcp");

function onData(data) {
  console.log("Data: ", data);
}

function onConnect() {
  console.log("Connected!");
}

function onDisconnect() {
  console.log("Disconnected.");
}

tcp.connect("127.0.0.1", 4242, onConnect, onData, onDisconnect);
