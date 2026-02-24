const express = require("express");
const db = require("./db");
const router = express.Router();

router.get("/user", (req, res) => {
  const username = req.query.username;

  const query = `SELECT * FROM users WHERE username = '${username}'`;

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

router.get("/account/:id", (req, res) => {
  const accountId = req.params.id;

  db.query(
    "SELECT * FROM accounts WHERE id = ?",
    [accountId],
    (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.json(results[0]);
    },
  );
});

module.exports = router;
