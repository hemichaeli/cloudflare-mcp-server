#!/usr/bin/env node
// Build script: patches index.ts to include modern MCP transport routes, then bundles with esbuild

import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { execSync } from "child_process";

let src = readFileSync("src/index.ts", "utf8");

// Every patch below is load-bearing (several are security-critical: they install the bearer
// gate on the MCP transport endpoints). A silently-missed replacement would ship an ungated
// server, so each one asserts that its anchor was actually found.
function patch(label, find, replace, opts = {}) {
  const count = src.split(find).length - 1;
  const expected = opts.count ?? 1;
  if (count !== expected) {
    throw new Error(
      `build patch "${label}" expected ${expected} occurrence(s) of its anchor but found ${count}. ` +
      `src/index.ts changed shape — fix scripts/build.mjs before shipping.`
    );
  }
  src = opts.count ? src.split(find).join(replace) : src.replace(find, replace);
}

// 1. Add import for setupModernRoutes after the existing express import.
//    The patched file lives in src/__patched__/, so the relative paths are ../routes.js
//    and ../mcp-auth.js
patch(
  "imports",
  'import express, { Request, Response } from "express";',
  'import express, { Request, Response } from "express";\n' +
  'import { setupModernRoutes } from "../routes.js";\n' +
  'import { registerOAuth, requireBearer, authEnabled } from "../mcp-auth.js";'
);

// 2. Public base URL, used for the OAuth issuer and the WWW-Authenticate resource hint.
patch(
  "base-url",
  "const PORT = process.env.PORT || 3000;",
  "const PORT = process.env.PORT || 3000;\n" +
  "const BASE_URL =\n" +
  "  process.env.SERVER_URL ||\n" +
  "  (process.env.RAILWAY_PUBLIC_DOMAIN\n" +
  '    ? "https://" + process.env.RAILWAY_PUBLIC_DOMAIN\n' +
  '    : "http://localhost:" + PORT);'
);

// 3. Shared-secret gate on the legacy SSE transport endpoints. No-op when AUTH_SECRET is unset.
patch(
  "gate-sse",
  'app.get("/sse", (req: Request, res: Response) => {',
  'app.get("/sse", requireBearer(BASE_URL), (req: Request, res: Response) => {'
);

patch(
  "gate-messages",
  'app.post("/messages", async (req: Request, res: Response) => {',
  'app.post("/messages", requireBearer(BASE_URL), async (req: Request, res: Response) => {'
);

// 4. Call setupModernRoutes before the health endpoint
patch(
  "modern-routes",
  'app.get("/health"',
  "setupModernRoutes(app, tools, handleMcpRequest, sessions);\n\napp.get(\"/health\""
);

// 5. Expose whether the gate is armed on /health, keeping the existing Cloudflare
//    credential-type field under `cfAuth`.
patch(
  "health-auth",
  'auth: CF_AUTH_TYPE === "global_key" ? "Global API Key" : "API Token"',
  'auth: authEnabled, cfAuth: CF_AUTH_TYPE === "global_key" ? "Global API Key" : "API Token"'
);

// 6. OAuth 2.1 discovery + DCR + authorize/token, registered right after /health so the
//    /health and /.well-known routes stay open while the transports stay gated.
patch(
  "register-oauth",
  'app.get("/", (_req: Request, res: Response) => {',
  'registerOAuth(app, { baseUrl: BASE_URL, clientPrefix: "cloudflare-mcp" });\n\n' +
  'app.get("/", (_req: Request, res: Response) => {'
);

// 7. Version bump so /health proves the deploy.
patch("version", 'version: "3.4.0"', 'version: "3.5.0"', { count: 3 });
patch("version-banner", "v3.3.0 on port", "v3.5.0 on port");

// 8. CF API quirk fix: GET /accounts/{id}/pages/projects rejects per_page with error 8000024
//    (validated 2026-07-04 with cfut_ user tokens). Strip the param.
patch("pages-per-page", "/pages/projects?per_page=25", "/pages/projects");

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
