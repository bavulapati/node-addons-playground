let addon = require("./build/n-api-without-gyp.node");

addon.hello();

const x = 9,
  y = 999;
const sum = addon.add(x, y);

console.log("Sum of ", x, " & ", y, " is ", sum);
