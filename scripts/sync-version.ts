import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "..");
const check = process.argv.includes("--check");

const cargo = Bun.TOML.parse(readFileSync(join(root, "Cargo.toml"), "utf8")) as {
  workspace?: { package?: { version?: string } };
};
const version = cargo.workspace?.package?.version;
if (!version) throw new Error("workspace.package.version missing from Cargo.toml");

const targets = ["apps/desktop/src-tauri/tauri.conf.json", "apps/desktop/package.json", "package.json"];
const stale: string[] = [];

for (const rel of targets) {
  const path = join(root, rel);
  const text = readFileSync(path, "utf8");
  const current = JSON.parse(text).version;
  if (current === version) continue;
  stale.push(`${rel}: ${current ?? "(none)"}`);
  if (check) continue;

  const next =
    current === undefined
      ? text.replace(/^(\s*)("name":\s*"[^"]*",)$/m, `$1$2\n$1"version": "${version}",`)
      : text.replace(/^(\s*"version":\s*)"[^"]*"/m, `$1"${version}"`);
  if (JSON.parse(next).version !== version) throw new Error(`could not update version in ${rel}`);
  writeFileSync(path, next);
}

if (stale.length === 0) {
  console.log(`version ${version} in sync`);
} else if (check) {
  console.error(`out of sync with Cargo.toml (${version}):\n  ${stale.join("\n  ")}\nrun: bun run version:sync`);
  process.exit(1);
} else {
  console.log(`set version ${version} in:\n  ${stale.join("\n  ")}`);
}
