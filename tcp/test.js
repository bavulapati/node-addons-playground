const { test } = require("brittle");
const tcpConnect = require(".");

test("validate function signature", (t) => {
  t.is(typeof tcpConnect, "function", "default export should be a function");
  t.exception(() => {
    tcpConnect();
  }, "expects host and port as input");
  t.exception(() => {
    tcpConnect("12");
  }, "expects port as input");
  t.exception(() => {
    tcpConnect(4242);
  }, "expects host and port");
  t.exception(() => {
    tcpConnect("127.0.0.", 4242);
  }, "expects a valid host");
  t.exception.all(() => {
    tcpConnect(127, "4242");
  }, "expects a valid port");
  t.exception.all(() => {
    tcpConnect("127.0.0.1", "4242");
  }, "expects a valid port");
  // t.exception(() => {
  //   tcpConnect("127.0.0.1", 4242);
  // });
});
