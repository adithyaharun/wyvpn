import { existsSync, readdirSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, join } from "node:path";

const appDir = join(import.meta.dir, "..", "apps", "desktop");
// Compiled into the frontend bundle although declared as devDependencies.
const bundledRuntime = ["svelte", "@sveltejs/kit"];

type Manifest = {
  name: string;
  version: string;
  license?: string | { type?: string };
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
};

function resolvePackage(name: string, fromDir: string): string | undefined {
  for (let dir = fromDir; ; dir = dirname(dir)) {
    if (basename(dir) !== "node_modules") {
      const candidate = join(dir, "node_modules", name, "package.json");
      if (existsSync(candidate)) return realpathSync(dirname(candidate));
    }
    if (dirname(dir) === dir) return undefined;
  }
}

const readManifest = (dir: string): Manifest => JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));

const root = readManifest(appDir);
const queue: Array<[string, string, boolean]> = [
  ...Object.keys(root.dependencies ?? {}).map((n) => [n, appDir, false] as [string, string, boolean]),
  ...Object.keys(root.optionalDependencies ?? {}).map((n) => [n, appDir, true] as [string, string, boolean]),
  ...bundledRuntime.map((n) => [n, appDir, false] as [string, string, boolean]),
];
const packages = new Map<string, { manifest: Manifest; dir: string }>();

while (queue.length > 0) {
  const [name, from, optional] = queue.shift()!;
  const dir = resolvePackage(name, from);
  if (!dir) {
    if (optional) continue;
    throw new Error(`cannot resolve ${name} from ${from}; run bun install`);
  }
  const manifest = readManifest(dir);
  const key = `${manifest.name}@${manifest.version}`;
  if (packages.has(key)) continue;
  packages.set(key, { manifest, dir });
  for (const dep of Object.keys(manifest.dependencies ?? {})) queue.push([dep, dir, false]);
  for (const dep of Object.keys(manifest.optionalDependencies ?? {})) queue.push([dep, dir, true]);
}

const licenseFiles = (dir: string) =>
  readdirSync(dir)
    .filter((f) => /^(licen[cs]e|copying|notice)([.-].*)?$/i.test(f))
    .sort();

const out: string[] = ["JavaScript packages", "===================", ""];
for (const key of [...packages.keys()].sort()) {
  const { manifest, dir } = packages.get(key)!;
  const declared = typeof manifest.license === "string" ? manifest.license : manifest.license?.type;
  out.push("-".repeat(80), `${key} (${declared ?? "no license field"})`, "");
  const files = licenseFiles(dir);
  if (files.length === 0) out.push(`No license file is shipped with this package; declared license: ${declared ?? "unknown"}.`, "");
  for (const file of files) out.push(readFileSync(join(dir, file), "utf8").trimEnd(), "");
}
process.stdout.write(out.join("\n") + "\n");
