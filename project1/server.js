const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// ❌ Weak hash algorithm (SonarQube will flag MD5)
function hashPassword(password) {
    return crypto.createHash("md5").update(password).digest("hex");
}

app.post("/comment", (req, res) => {
    const comment = req.body.comment;

    // ❌ Reflected XSS vulnerability
    res.send(`<h1>User Comment:</h1><p>${comment}</p>`);
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});