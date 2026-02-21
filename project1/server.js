const express = require("express");
const bodyParser = require("body-parser");
const db = require("./database");

const app = express();

// ❌ Security Misconfiguration
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.json());
app.set("trust proxy", true);
app.listen(3000, () => console.log("Server running on port 3000"));

/* ------------------------
   LOGIN (SQL Injection)
-------------------------*/
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // ❌ SQL Injection (string concatenation)
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.query(query, (err, results) => {
    if (results.length > 0) {
      res.redirect(`/profile?user=${username}`);
    } else {
      res.send("Invalid credentials");
    }
  });
});

/* ------------------------
   XSS Vulnerability
-------------------------*/
app.get("/profile", (req, res) => {
  const user = req.query.user;

  // ❌ No sanitization
  res.send(`
    <h2>Welcome</h2>
    <p>Hello ${user}</p>
  `);
});