// Release some parts we dont need

var fs = require("fs");

function read(f) {
  return fs.readFileSync(f).toString();
}
function include(f) {
  eval.apply(global, [read(f)]);
}

include('./parts.min.js');
var boards = JSON.parse(fs.readFileSync("boards.json").toString());
var out = {};
Object.getOwnPropertyNames(parts).forEach(function (pn) {
  console.log("Checking part", pn);
  var partName = parts[pn].AVRPart.toString().toLowerCase();
  boards.forEach(function (b) {
    if (partName == b.build.mcu)
      out[partName] = parts[pn];
  });
});

fs.writeFileSync("clean.parts.json", JSON.stringify(out));
