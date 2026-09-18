#!/usr/bin/env node
// GRIM MCP launcher.
//
// The GRIM engine is dependency-free Python (stdlib only). This npm package bundles
// the Python sources and runs them as the MCP stdio server, so any MCP client can use
// `npx -y grim-mcp` exactly like the other servers in the family.
//
// stdout is inherited by the Python child, so the MCP JSON-RPC stream is never
// touched by this launcher. Diagnostics go to stderr.

import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { delimiter, dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const pyRoot = join(here, "..", "python");
const entry = join(pyRoot, "grim", "__main__.py");

if (!existsSync(entry)) {
  process.stderr.write(
    "[grim-mcp] bundled Python sources are missing from this install.\n" +
      "[grim-mcp] reinstall with: npm install -g grim-mcp\n",
  );
  process.exit(1);
}

function detectPython() {
  const found = [];
  if (process.env.GRIM_PYTHON) found.push(process.env.GRIM_PYTHON);
  if (process.platform === "win32") found.push("py", "python", "python3");
  else found.push("python3", "python");

  for (const cmd of found) {
    const baseArgs = cmd === "py" ? ["-3"] : [];
    let probe;
    try {
      probe = spawnSync(cmd, [...baseArgs, "--version"], { stdio: ["ignore", "pipe", "ignore"] });
    } catch {
      continue;
    }
    if (probe.status !== 0) continue;
    const text = (probe.stdout || "").toString().trim();
    const m = text.match(/Python (\d+)\.(\d+)/);
    if (!m) continue;
    const major = Number(m[1]);
    const minor = Number(m[2]);
    if (major > 3 || (major === 3 && minor >= 10)) return { cmd, baseArgs };
    process.stderr.write(
      `[grim-mcp] found ${text} but GRIM needs Python 3.10+; ` +
        "install a newer Python or set GRIM_PYTHON to its path.\n",
    );
  }
  return null;
}

const python = detectPython();
if (!python) {
  process.stderr.write(
    "[grim-mcp] Python 3.10+ was not found on PATH.\n" +
      "[grim-mcp] GRIM ships as a Python engine. Install Python 3.10+ (https://www.python.org/downloads/)\n" +
      "[grim-mcp] or set GRIM_PYTHON to the interpreter path, then retry.\n",
  );
  process.exit(1);
}

let cliArgs = process.argv.slice(2);
if (cliArgs.length === 0) {
  cliArgs = ["mcp"];
} else if (cliArgs[0] === "--version" || cliArgs[0] === "-v") {
  cliArgs = ["version"];
}

const env = { ...process.env };
env.PYTHONPATH = [pyRoot, process.env.PYTHONPATH].filter(Boolean).join(delimiter);
env.PYTHONUTF8 = env.PYTHONUTF8 || "1";
env.PYTHONIOENCODING = env.PYTHONIOENCODING || "utf-8";

const child = spawn(python.cmd, [...python.baseArgs, "-m", "grim", ...cliArgs], {
  stdio: "inherit",
  env,
});

for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(sig, () => {
    try {
      child.kill(sig);
    } catch {
      /* already gone */
    }
  });
}

child.on("error", (err) => {
  process.stderr.write(`[grim-mcp] failed to start Python engine: ${err.message}\n`);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) process.exit(1);
  process.exit(code ?? 0);
});
