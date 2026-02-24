const { exec } = require("child_process");

function generateReport(filename) {
  const command = `cat reports/${filename}`;

  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error.message}`);
      return;
    }
    console.log(`Report output:\n${stdout}`);
  });
}

function processRequest(req) {
  const filename = req.body.filename;
  generateReport(filename);
}

module.exports = { processRequest };
