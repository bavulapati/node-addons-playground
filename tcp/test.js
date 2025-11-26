const { test, solo } = require("brittle");
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
  }, "expects host as string");
  t.exception.all(() => {
    tcpConnect("127.0.0.1", "4242");
  }, "expects port as number");
  t.execution(() => {
    tcpConnect("127.0.0.1", 4242);
  }, "Should not throw");
});

test("connection should be refused without server", async (t) => {
  const client = tcpConnect("127.0.0.1", 4242);
  t.is(typeof client, "object", "should return object");
  await t.exception(
    () =>
      new Promise((resolve, reject) => {
        client.once("error", (err) => {
          reject(err);
        });
        setTimeout(resolve, 5000);
      }),
    "should emit error",
  );
});
