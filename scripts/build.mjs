#!/usr/bin/env node
// Build script: patches index.ts to include modern MCP transport routes, then bundles with esbuild

import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { execSync } from "child_process";

let src = readFileSync("src/index.ts", "utf8");

// 1. Add import for setupModernRoutes after the existing express import
src = src.replace(
  'import express, { Request, Response } from "express";',
  'import express, { Request, Response } from "express";\nimport { setupModernRoutes } from "./routes.js";'
);

// 2. Call setupModernRoutes before the health endpoint
src = src.replace(
  'app.get("/health"',
  'setupModernRoutes(app, tools, handleMcpRequest, sessions);\n\napp.get("/health"'
);

// 3. Bump version to 3.1.0
src = src.replace(/v3\.0\.0/g, "v3.1.0");
src = src.replace(/"3\.0\.0"/g, '"3.1.0"');

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
