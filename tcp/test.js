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
});

test("connection should be refused without server", async (t) => {
  t.plan(2);

  const lc = t.test("no server");
  lc.plan(2);

  const client = tcpConnect("127.0.0.1", 4242);
  lc.is(typeof client, "object", "client should be object");
  client.once("error", (err) => {
    lc.pass("client emitted error");
  });

  await lc;
  t.pass();
});

test("should receive data when server is accepting connections", async (t) => {
  function waitForServer(server) {
    return new Promise((resolve, reject) => {
      function done(error) {
        error ? reject(error) : resolve();
      }

      server.on("listening", done).on("error", done);
    });
  }

  t.plan(2);

  const lc = t.test("server available");
  lc.plan(4);

  const net = require("node:net");
  const server = net.createServer((c) => {
    c.on("close", () => {
      t.pass("server connection closed");
    });
    c.end("hello\r\n");
  });
  server.on("error", (err) => {
    lc.fail("server error");
  });
  server.listen(4242, () => {
    lc.pass("server bound");
  });

  await waitForServer(server);

  const client = tcpConnect("127.0.0.1", 4242);
  client.once("connect", () => {
    lc.pass("client connected successfully");
  });
  client.once("end", () => {
    lc.pass("client connection ended successfully");
  });
  client.on("data", () => {
    lc.pass("client received data successfully");
  });
  client.on("error", () => {
    lc.fail("client received error");
  });

  await lc;
  server.close();
});
