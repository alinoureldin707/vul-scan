const mysql = require("mysql");

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: ""
});

connection.connect();

connection.query("CREATE DATABASE IF NOT EXISTS vulnapp");
connection.query("USE vulnapp");

connection.query(`
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(50)
  )
`);

connection.query(`
  INSERT INTO users (username, password)
  VALUES ('admin', 'admin123')
`);

console.log("Database initialized.");
connection.end();