const tcpConnect = require(".");

function onData2(data) {
  console.log("Data2: ", data);
}

function onConnect2() {
  console.log("Connected! 2");
}

function onEnd2() {
  console.log("Disconnected.2 ");
}

function onError2(err) {
  console.error("Error2: ", err);
}
function onData(data) {
  console.log("Data: ", data);
}

function onConnect() {
  console.log("Connected!");
}

function onEnd() {
  console.log("Disconnected.");
}

function onError(err) {
  console.error("Error: ", err);
}

try {
  const client1 = tcpConnect(
    "23.192.228.80",
    80,
    "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
  );
  // const client1 = tcpConnect("127.0.0.1", 4243);
  const client2 = tcpConnect("127.0.0.1", 4243, "Hello\r\n\r\n");
  client1.on("connect", onConnect);
  client1.on("data", onData);
  client1.on("end", onEnd);
  client1.on("error", onError);
  client2.on("connect", onConnect2);
  client2.on("data", onData2);
  client2.on("end", onEnd2);
  client2.on("error", onError2);
} catch (err) {
  console.error("Error received at JS layer", err);
}
