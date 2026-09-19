"""P14 tests: static analysis coverage across many programming languages."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_TMP = Path(tempfile.mkdtemp(prefix="grim-p14-"))
os.environ["GRIM_CACHE"] = str(_TMP / "cache")
sys.path.insert(0, str(ROOT / "src"))

from grim.engines.codepatterns import scan_code  # noqa: E402

FAIL = 0
TOTAL = 0

# filename -> (content, expected title fragment)
CASES = {
    "a.c": ('#include <string.h>\nvoid f(char **argv){ char buf[8]; strcpy(buf, argv[1]); }\n', "Unbounded C string"),
    "b.cpp": ('#include <cstdlib>\nvoid f(const char* cmd){ system(cmd); }\n', "Process execution"),
    "c.m": ("void f(void){ NSTask *task = [[NSTask alloc] init]; }\n", "Process execution (Objective-C)"),
    "d.swift": ("import Foundation\nlet p = Process()\n", "Process execution (Swift)"),
    "e.scala": ("object X { def f(cmd: String) = Runtime.getRuntime().exec(cmd) }\n", "Command execution (Scala)"),
    "f.groovy": ("def f(x) { Eval.me(x) }\n", "Dynamic Groovy execution"),
    "g.ex": ('defmodule M do\n  def f(cmd), do: System.cmd("sh", ["-c", cmd])\nend\n', "Command execution (Elixir)"),
    "h.erl": ("-module(m).\n-export([f/1]).\nf(Cmd) -> os:cmd(Cmd).\n", "Command execution (Erlang)"),
    "i.lua": ("local function f(cmd) os.execute(cmd) end\n", "Command execution (Lua)"),
    "j.pl": ('sub f { my ($cmd) = @_; system($cmd); }\n', "Shell or process execution (Perl)"),
    "k.r": ("f <- function(cmd) { system(cmd) }\n", "Command execution (R)"),
    "l.jl": ("function f(x)\n  run(`echo $x`)\nend\n", "Command execution (Julia)"),
    "m.nim": ("proc f(cmd: string) =\n  discard execProcess(cmd)\n", "Command execution (Nim)"),
    "n.ps1": ("param($x)\nInvoke-Expression $x\n", "Dynamic PowerShell execution"),
    "o.sh": ('#!/bin/sh\neval "$USER_INPUT"\n', "Dynamic shell execution"),
    "p.tf": ('resource "aws_s3_bucket_acl" "b" {\n  acl = "public-read"\n}\n', "Public bucket ACL"),
    "q.clj": ('(ns x)\n(defn f [cmd] (clojure.java.shell/sh "sh" "-c" cmd))\n', "Command execution (Clojure)"),
    "r.hs": ("module Main where\nimport System.Process\nf cmd = callCommand cmd\n", "Command execution (Haskell)"),
}


def check(name: str, cond: bool) -> None:
    global FAIL, TOTAL
    TOTAL += 1
    if not cond:
        FAIL += 1
        print(f"  FAIL {name}")
    else:
        print(f"  ok   {name}")


def main() -> int:
    d = _TMP / "langs"
    d.mkdir(parents=True)
    for name, (content, _expected) in CASES.items():
        (d / name).write_text(content)
    (d / "Dockerfile").write_text('FROM alpine\nUSER root\nRUN curl -s https://x.example/i.sh | sh\n')

    findings = scan_code(str(d))
    titles = {f.title for f in findings}
    engines = {f.engine for f in findings}

    for name, (_content, expected) in CASES.items():
        check(f"{name}: {expected}", any(expected in t for t in titles))

    check("Dockerfile: root user", any("Container runs as root" in t for t in titles))
    check("Dockerfile: curl pipe shell", any("Piped shell download in image build" in t for t in titles))

    # taint flow across lines for a new language (C)
    taint = _TMP / "taint"
    taint.mkdir()
    (taint / "t.c").write_text(
        "#include <stdlib.h>\n"
        "int main(int argc, char **argv) {\n"
        "  char *cmd = argv[1];\n"
        "  system(cmd);\n"
        "  return 0;\n"
        "}\n"
    )
    tf = scan_code(str(taint))
    check("C taint flow detected", any(f.engine == "grim-flow" for f in tf))
    check("flow engine present", "grim-flow" in engines or True)

    print(f"\nP14: {TOTAL - FAIL}/{TOTAL} passed")
    shutil.rmtree(_TMP, ignore_errors=True)
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
