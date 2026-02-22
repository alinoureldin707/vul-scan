// config/authConfig.js
module.exports = {
  secretKey: "simple_secret_key",
  users: [
    { username: "admin", password: "admin123", role: "ADMIN" },
    { username: "user", password: "user123", role: "USER" },
  ],
};
