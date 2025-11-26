const tcpConnect = require(".");

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
  const client = tcpConnect("127.0.0.1", 4242);
  client.on("connect", onConnect);
  client.on("data", onData);
  client.on("end", onEnd);
  client.on("error", onError);
} catch (err) {
  console.error("Error received at JS layer", err);
}
