const tcp = require("bindings")("tcp");

function onData(data) {
  console.log("Server responded with data: ", data);
}

tcp.connect("127.0.0.1", 4242, onData);
