#!/usr/bin/env node
// Bundle the dependency-free Python GRIM package into npm/python for publishing.
// Run automatically on `npm pack` / `npm publish` (prepack).

import { cpSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const npmRoot = join(here, "..");
const repoRoot = join(npmRoot, "..");
const src = join(repoRoot, "src", "grim");
const dest = join(npmRoot, "python", "grim");

rmSync(join(npmRoot, "python"), { recursive: true, force: true });
cpSync(src, dest, {
  recursive: true,
  filter: (p) => !p.includes("__pycache__") && !p.endsWith(".pyc"),
});
console.log(`[grim-mcp] bundled Python engine: ${src} -> ${dest}`);
