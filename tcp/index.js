const tcp = require("bindings")("tcp");
const EventEmitter = require("events");

function wrapped(...args) {
  const emitter = new EventEmitter();

  // Replace expected callback positions with event emitters
  const connectCb = (...cbArgs) => emitter.emit("connect", ...cbArgs);
  const dataCb = (...cbArgs) => emitter.emit("data", ...cbArgs);
  const endCb = (...cbArgs) => emitter.emit("end", ...cbArgs);
  const errorCb = (...cbArgs) => emitter.emit("error", ...cbArgs);

  // Call original with event-capturing callbacks in the right order
  tcp.connect(...args, connectCb, dataCb, endCb, errorCb);

  return emitter;
}

module.exports = wrapped;
