const addon = require("./build/callbacks.node");

addon(function (msg) {
  console.log(msg);
});
