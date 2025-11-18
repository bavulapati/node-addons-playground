const tcp = require("bindings")("tcp");

console.log("tcp", tcp);

function onData(data) {
  console.log("Server responded with data: ", data);
}

tcp.connect(onData);
