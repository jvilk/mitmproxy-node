#!/usr/bin/env node

const child_process = require('child_process');

const result = child_process.spawnSync("python3", ["scripts/install_python_deps.py"], {stdio: "inherit"});
if (result.error && result.error.code === "ENOENT") {
  const result2 = child_process.spawnSync("python", ["scripts/install_python_deps.py"], {stdio: "inherit"});
  if (result2.error) {
    console.log("Failed to run python3 or python: ");
    console.log(result.error);
    console.log(result2.error);
  }
}
