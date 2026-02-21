const mysql = require("mysql");

// ❌ Hardcoded credentials
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "vulnapp"
});

connection.connect();

module.exports = connection;