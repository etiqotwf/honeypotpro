// check-large-files.js
// ✅ بدل السطور دي:
// const { execSync } = require("child_process");
// const fs = require("fs");
// const path = require("path");

// 👇 استخدم:
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import process from "process";

function runCommand(cmd) {
  try {
    return execSync(cmd, { encoding: "utf8" }).trim();
  } catch {
    return "";
  }
}

function getLargeGitObjects(limitMB = 90) {
  console.log("🔍 Searching for large Git objects (> " + limitMB + "MB)...\n");
  const sizes = runCommand(`git verify-pack -v .git/objects/pack/*.idx | sort -k 3 -n`);
  if (!sizes) {
    console.log("⚠️ No packed objects found. Skipping pack check.\n");
    return [];
  }

  const largeObjects = [];
  const lines = sizes.split("\n");
  for (const line of lines) {
    const parts = line.split(" ");
    const size = parseInt(parts[2] || 0);
    const hash = parts[0];
    if (size > limitMB * 1024 * 1024) {
      largeObjects.push({ hash, sizeMB: (size / (1024 * 1024)).toFixed(2) });
    }
  }
  return largeObjects;
}

function findObjectPath(hash) {
  const searchResult = runCommand(`git rev-list --objects --all | findstr ${hash}`);
  return searchResult || "Unknown origin (likely cache or binary)";
}

function checkWorkingDir(limitMB = 90) {
  console.log("\n📂 Checking working directory for large files (> " + limitMB + "MB)...\n");
  const largeFiles = [];

  function walk(dir) {
    const files = fs.readdirSync(dir);
    for (const file of files) {
      const fullPath = path.join(dir, file);
      try {
        const stats = fs.statSync(fullPath);
        if (stats.isDirectory() && !fullPath.includes(".git")) {
          walk(fullPath);
        } else if (stats.size > limitMB * 1024 * 1024) {
          largeFiles.push({
            path: fullPath,
            sizeMB: (stats.size / (1024 * 1024)).toFixed(2),
          });
        }
      } catch {}
    }
  }

  walk(".");
  return largeFiles;
}

// 🧾 التشغيل
const limit = 90;
const gitLarge = getLargeGitObjects(limit);
const dirLarge = checkWorkingDir(limit);

if (gitLarge.length === 0 && dirLarge.length === 0) {
  console.log("✅ No large files detected. You're clean!");
  process.exit(0);
}

// ⬇️ طباعة النتائج
if (gitLarge.length > 0) {
  console.log("\n🧱 Large Git history objects found:");
  for (const obj of gitLarge) {
    const origin = findObjectPath(obj.hash);
    console.log(` - ${obj.hash} (${obj.sizeMB} MB): ${origin}`);
  }
}

if (dirLarge.length > 0) {
  console.log("\n🗂️ Large working directory files found:");
  for (const f of dirLarge) {
    console.log(` - ${f.path} (${f.sizeMB} MB)`);
  }
}

console.log("\n🔎 Review these files — if they’re from libraries (node_modules, cache), you can safely delete or ignore them.");
