#!/usr/bin/env node
// Build script: patches index.ts to include modern MCP transport routes, then bundles with esbuild

import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { execSync } from "child_process";

let src = readFileSync("src/index.ts", "utf8");

// 1. Add import for setupModernRoutes after the existing express import.
//    The patched file lives in src/__patched__/, so the relative path is ../routes.js
src = src.replace(
  'import express, { Request, Response } from "express";',
  'import express, { Request, Response } from "express";\nimport { setupModernRoutes } from "../routes.js";'
);

// 2. Call setupModernRoutes before the health endpoint
src = src.replace(
  'app.get("/health"',
  'setupModernRoutes(app, tools, handleMcpRequest, sessions);\n\napp.get("/health"'
);

// 3. CF API quirk fix: GET /accounts/{id}/pages/projects rejects per_page with error 8000024
//    (validated 2026-07-04 with cfut_ user tokens). Strip the param.
src = src.replace(
  "/pages/projects?per_page=25",
  "/pages/projects"
);

mkdirSync("src/__patched__", { recursive: true });
writeFileSync("src/__patched__/index.ts", src);

console.log("Patched index.ts — building with esbuild...");

execSync(
  [
    "npx esbuild src/__patched__/index.ts",
    "--bundle",
    "--platform=node",
    "--format=esm",
    "--packages=external",
    "--outfile=dist/index.js",
  ].join(" "),
  { stdio: "inherit" }
);

console.log("Build complete: dist/index.js");
