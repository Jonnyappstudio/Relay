import { readFileSync, writeFileSync } from "node:fs";

const version = process.argv[2]?.replace(/^(?:relay-)?v/, "");
if (!/^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$/.test(version || "")) {
  throw new Error("Provide a semantic version such as 0.2.0");
}

for (const file of ["package.json", "package-lock.json", "src-tauri/tauri.conf.json"]) {
  const json = JSON.parse(readFileSync(file, "utf8"));
  json.version = version;
  if (file === "package-lock.json" && json.packages?.[""]) json.packages[""].version = version;
  writeFileSync(file, `${JSON.stringify(json, null, 2)}\n`);
}

const cargoPath = "src-tauri/Cargo.toml";
const cargo = readFileSync(cargoPath, "utf8").replace(
  /(^\[package\][\s\S]*?^version\s*=\s*)"[^"]+"/m,
  `$1"${version}"`
);
writeFileSync(cargoPath, cargo);
console.log(`Relay version set to ${version}`);
