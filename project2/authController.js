// controller/authController.js
const authService = require("../service/authService");

const login = (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Missing credentials" });
  }

  const result = authService.authenticate(username, password);

  if (!result) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  res.json(result);
};

const signup = (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Missing credentials" });
  }

  const user = authService.signup(username, password);

  if (!user) {
    return res.status(409).json({ error: "Username already exists" });
  }

  res.status(201).json({
    message: "User registered successfully",
    user,
  });
};

module.exports = { login, signup };
