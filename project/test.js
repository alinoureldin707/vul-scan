export const test = () => {
  // vulnerable_app
  const sqlite3 = require("sqlite3").verbose();
  const fs = require("fs");
  const API_KEY = "sk_live_123456789";

  // vulnerable_app
  function run_command(cmd) {
    // Potential RCE vulnerability
    return require("child_process").execSync(cmd).toString();
  }
};
