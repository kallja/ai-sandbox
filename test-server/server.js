const express = require("express");

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.text());
app.use(express.urlencoded({ extended: true }));
app.use(express.raw({ type: "*/*" }));

app.use((req, res) => {
  const timestamp = new Date().toISOString();
  console.log(`\n--- ${timestamp} ---`);
  console.log(`${req.method} ${req.url}`);
  console.log("Headers:", JSON.stringify(req.headers, null, 2));
  if (req.body && Object.keys(req.body).length > 0) {
    console.log("Body:", typeof req.body === "string" ? req.body : JSON.stringify(req.body, null, 2));
  }
  console.log("---\n");

  res.json({ status: "ok", received: { method: req.method, url: req.url, headers: req.headers } });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Test server listening on port ${PORT}`);
});
