const { solo, test } = require("brittle");
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

function waitForServer(server) {
  return new Promise((resolve, reject) => {
    function done(error) {
      error ? reject(error) : resolve();
    }

    server.on("listening", done).on("error", done);
  });
}
test("should receive data when server is accepting connections", async (t) => {
  t.plan(2);

  const lc = t.test("server available");
  lc.plan(4);

  const net = require("node:net");
  const server = net.createServer((c) => {
    c.on("close", () => {
      console.log("server connection closed");
    });
    c.end("hello\r\n");
  });
  server.on("error", (err) => {
    lc.fail("server error");
  });
  server.listen(4241, () => {
    lc.pass("server bound");
  });

  await waitForServer(server);

  const client = tcpConnect("127.0.0.1", 4241);
  client.once("connect", () => {
    lc.pass("client connected successfully");
  });
  client.once("end", () => {
    lc.pass("client connection ended successfully");
    t.pass();
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

test("multiple connections", async (t) => {
  t.plan(3);

  const lc = t.test("server available");
  lc.plan(7);

  const net = require("node:net");
  const server = net.createServer((c) => {
    c.on("close", () => {
      console.log("closing server");
    });
    c.end("hello\r\n");
  });
  server.on("error", (err) => {
    lc.fail("server error");
  });
  server.listen(4243, () => {
    lc.pass("server bound");
  });

  await waitForServer(server);

  const client = tcpConnect("127.0.0.1", 4243);
  client.once("connect", () => {
    lc.pass("client connected successfully");
  });
  client.once("end", () => {
    lc.pass("client connection ended successfully");
    t.pass();
  });
  client.on("data", () => {
    lc.pass("client received data successfully");
  });
  client.on("error", () => {
    lc.fail("client received error");
  });

  const client2 = tcpConnect("127.0.0.1", 4243);
  client2.once("connect", () => {
    lc.pass("client connected successfully");
  });
  client2.once("end", () => {
    lc.pass("client connection ended successfully");
    t.pass();
  });
  client2.on("data", () => {
    lc.pass("client received data successfully");
  });
  client2.on("error", () => {
    lc.fail("client received error");
  });

  await lc;
  server.close();
});

test("Remote Server", async (t) => {
  t.plan(3);

  const lc = t.test("Remote server");
  lc.plan(6);

  const client = tcpConnect("23.192.228.80", 80);
  client.once("connect", () => {
    lc.pass("client connected successfully");
  });
  client.once("end", () => {
    lc.pass("client connection ended successfully");
    t.pass();
  });
  client.on("data", () => {
    lc.pass("client received data successfully");
  });
  client.on("error", () => {
    lc.fail("client received error");
  });

  const client2 = tcpConnect("23.192.228.80", 80);
  client2.once("connect", () => {
    lc.pass("client connected successfully");
  });
  client2.once("end", () => {
    lc.pass("client connection ended successfully");
    t.pass();
  });
  client2.on("data", () => {
    lc.pass("client received data successfully");
  });
  client2.on("error", () => {
    lc.fail("client received error");
  });

  await lc;
});
