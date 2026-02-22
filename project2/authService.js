// service/authService.js
const { users, secretKey } = require("../config/authConfig");

class AuthService {
  authenticate(username, password) {
    const user = users.find(
      (u) => u.username === username && u.password === password,
    );

    if (!user) return null;

    const tokenData = `${user.username}:${user.role}:${secretKey}`;
    const token = Buffer.from(tokenData).toString("base64");

    return {
      username: user.username,
      role: user.role,
      token,
    };
  }

  signup(username, password) {
    const exists = users.some((u) => u.username === username);
    if (exists) {
      return null;
    }

    const newUser = {
      username,
      password,
      role: "USER",
    };

    users.push(newUser);

    return {
      username: newUser.username,
      role: newUser.role,
    };
  }
}

module.exports = new AuthService();
