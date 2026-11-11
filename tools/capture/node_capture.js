// Capture Node.js HTTPS (HTTP/1.1) or HTTP/2 fingerprints.
const https = require("https");
const http2 = require("http2");
const fs = require("fs");

const URL = "https://tls.peet.ws/api/all";

function save(path, body) {
  fs.writeFileSync(path, body);
}

const mode = process.argv[2];
const out = process.argv[3];

if (mode === "fetch") {
  fetch(URL)
    .then(async (res) => {
      save(out, await res.text());
      console.log(`node fetch ${res.status}`);
    })
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
} else if (mode === "http2") {
  const client = http2.connect("https://tls.peet.ws");
  client.on("error", (err) => {
    console.error(err);
    process.exit(1);
  });
  const req = client.request({ ":path": "/api/all", ":method": "GET" });
  const chunks = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    save(out, Buffer.concat(chunks));
    console.log("node http2");
    client.close();
  });
} else {
  https
    .get(URL, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        save(out, Buffer.concat(chunks));
        console.log(`node https ${res.statusCode}`);
      });
    })
    .on("error", (err) => {
      console.error(err);
      process.exit(1);
    });
}
