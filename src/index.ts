import express, { Request, Response } from "express";
import { randomUUID } from "crypto";

const app = express();

// ─────────────────────────────────────────────
// Auth configuration
//
// Option A – API Token (recommended):
//   CF_AUTH_TYPE=token
//   CF_API_TOKEN=<your token>
//
// Option B – Global API Key:
//   CF_AUTH_TYPE=global_key
//   CF_API_EMAIL=<your email>
//   CF_API_KEY=<your global key>
// ─────────────────────────────────────────────

const CF_AUTH_TYPE = process.env.CF_AUTH_TYPE || "token"; // "token" | "global_key"
const CF_API_TOKEN = process.env.CF_API_TOKEN || "";
const CF_API_EMAIL = process.env.CF_API_EMAIL || "";
const CF_API_KEY = process.env.CF_API_KEY || "";
const PORT = process.env.PORT || 3000;

const CF_BASE_URL = "https://api.cloudflare.com/client/v4";

// Session management for SSE
const sessions = new Map<string, Response>();

// ─────────────────────────────────────────────
// Auth headers builder
// ─────────────────────────────────────────────
function getAuthHeaders(): Record<string, string> {
  if (CF_AUTH_TYPE === "global_key") {
    return {
      "X-Auth-Email": CF_API_EMAIL,
      "X-Auth-Key": CF_API_KEY,
      "Content-Type": "application/json",
    };
  }
  // Default: API Token
  return {
    "Authorization": `Bearer ${CF_API_TOKEN}`,
    "Content-Type": "application/json",
  };
}

// ─────────────────────────────────────────────
// Cloudflare API helper
// ─────────────────────────────────────────────
async function cfRequest(
  endpoint: string,
  method: string = "GET",
  body?: unknown
): Promise<unknown> {
  const url = `${CF_BASE_URL}${endpoint}`;
  const options: RequestInit = {
    method,
    headers: getAuthHeaders(),
  };
  if (body) options.body = JSON.stringify(body);

  const res = await fetch(url, options);
  const data = await res.json() as { success: boolean; errors: unknown[]; result: unknown };

  if (!data.success) {
    throw new Error(`Cloudflare API error: ${JSON.stringify(data.errors)}`);
  }
  return data.result;
}

// ─────────────────────────────────────────────
// Tool definitions
// ─────────────────────────────────────────────
const tools = [
  // ── Zones ──
  {
    name: "list_zones",
    description: "List all Cloudflare zones (domains) in the account. Returns zone IDs, names, and status.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Filter by zone name (e.g. u-r-quantum.com)" },
        status: { type: "string", description: "Filter by status: active | pending | paused | deactivated" },
        per_page: { type: "number", description: "Results per page (default: 50)" },
      },
    },
  },
  {
    name: "get_zone",
    description: "Get details of a specific Cloudflare zone by zone ID.",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
      },
      required: ["zone_id"],
    },
  },
  {
    name: "get_zone_by_name",
    description: "Look up a zone by domain name and return its zone ID and details.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Domain name, e.g. u-r-quantum.com" },
      },
      required: ["name"],
    },
  },

  // ── DNS Records ──
  {
    name: "list_dns_records",
    description: "List all DNS records for a zone. Supports filtering by type and name.",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
        type: { type: "string", description: "Record type filter: A | AAAA | CNAME | MX | TXT | NS | SRV | etc." },
        name: { type: "string", description: "Record name filter (e.g. @, www, mail)" },
        per_page: { type: "number", description: "Results per page (default: 100)" },
      },
      required: ["zone_id"],
    },
  },
  {
    name: "get_dns_record",
    description: "Get details of a specific DNS record by record ID.",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
        record_id: { type: "string", description: "The DNS record ID" },
      },
      required: ["zone_id", "record_id"],
    },
  },
  {
    name: "create_dns_record",
    description: "Create a new DNS record in a Cloudflare zone.",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
        type: { type: "string", description: "Record type: A | AAAA | CNAME | MX | TXT | NS | SRV | CAA | etc." },
        name: { type: "string", description: "Record name (use @ for root)" },
        content: { type: "string", description: "Record content/value (IP, hostname, text, etc.)" },
        ttl: { type: "number", description: "TTL in seconds (1 = auto, default: 1)" },
        proxied: { type: "boolean", description: "Whether to proxy through Cloudflare (orange cloud). Default: false" },
        priority: { type: "number", description: "MX/SRV record priority" },
      },
      required: ["zone_id", "type", "name", "content"],
    },
  },
  {
    name: "update_dns_record",
    description: "Update an existing DNS record.",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
        record_id: { type: "string", description: "The DNS record ID to update" },
        type: { type: "string", description: "Record type: A | AAAA | CNAME | MX | TXT | etc." },
        name: { type: "string", description: "Record name" },
        content: { type: "string", description: "New record content/value" },
        ttl: { type: "number", description: "TTL in seconds (1 = auto)" },
        proxied: { type: "boolean", description: "Whether to proxy through Cloudflare" },
      },
      required: ["zone_id", "record_id"],
    },
  },
  {
    name: "delete_dns_record",
    description: "Delete a DNS record from a zone.",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
        record_id: { type: "string", description: "The DNS record ID to delete" },
      },
      required: ["zone_id", "record_id"],
    },
  },

  // ── Cache ──
  {
    name: "purge_cache_all",
    description: "Purge all cached files for a zone (full cache purge).",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
      },
      required: ["zone_id"],
    },
  },
  {
    name: "purge_cache_files",
    description: "Purge specific URLs from Cloudflare cache.",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
        files: {
          type: "array",
          items: { type: "string" },
          description: "List of URLs to purge from cache",
        },
      },
      required: ["zone_id", "files"],
    },
  },

  // ── Page Rules ──
  {
    name: "list_page_rules",
    description: "List page rules for a zone.",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
        status: { type: "string", description: "Filter by status: active | disabled" },
      },
      required: ["zone_id"],
    },
  },

  // ── Firewall / WAF ──
  {
    name: "list_firewall_rules",
    description: "List firewall rules for a zone.",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
        per_page: { type: "number", description: "Results per page (default: 50)" },
      },
      required: ["zone_id"],
    },
  },

  // ── SSL / TLS ──
  {
    name: "get_ssl_settings",
    description: "Get SSL/TLS settings for a zone (mode: off | flexible | full | strict).",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
      },
      required: ["zone_id"],
    },
  },
  {
    name: "update_ssl_settings",
    description: "Update SSL/TLS mode for a zone.",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
        value: { type: "string", description: "SSL mode: off | flexible | full | strict" },
      },
      required: ["zone_id", "value"],
    },
  },

  // ── Zone Settings ──
  {
    name: "get_zone_settings",
    description: "Get all settings for a zone (security level, caching, minification, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
      },
      required: ["zone_id"],
    },
  },
  {
    name: "update_zone_setting",
    description: "Update a specific zone setting (e.g. security_level, always_https, browser_cache_ttl).",
    inputSchema: {
      type: "object",
      properties: {
        zone_id: { type: "string", description: "The Cloudflare zone ID" },
        setting: { type: "string", description: "Setting name, e.g. security_level | always_https | browser_cache_ttl | ssl" },
        value: { description: "New value for the setting (string, number, or boolean)" },
      },
      required: ["zone_id", "setting", "value"],
    },
  },
];

// ─────────────────────────────────────────────
// Tool execution
// ─────────────────────────────────────────────
async function executeTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  switch (name) {
    // ── Zones ──
    case "list_zones": {
      let endpoint = "/zones?per_page=" + (args.per_page || 50);
      if (args.name) endpoint += `&name=${encodeURIComponent(args.name as string)}`;
      if (args.status) endpoint += `&status=${args.status}`;
      return await cfRequest(endpoint);
    }
    case "get_zone": {
      return await cfRequest(`/zones/${args.zone_id}`);
    }
    case "get_zone_by_name": {
      const result = await cfRequest(`/zones?name=${encodeURIComponent(args.name as string)}&per_page=5`) as unknown[];
      if (!result || (result as unknown[]).length === 0) throw new Error(`Zone not found: ${args.name}`);
      return (result as unknown[])[0];
    }

    // ── DNS Records ──
    case "list_dns_records": {
      let endpoint = `/zones/${args.zone_id}/dns_records?per_page=${args.per_page || 100}`;
      if (args.type) endpoint += `&type=${args.type}`;
      if (args.name) endpoint += `&name=${encodeURIComponent(args.name as string)}`;
      return await cfRequest(endpoint);
    }
    case "get_dns_record": {
      return await cfRequest(`/zones/${args.zone_id}/dns_records/${args.record_id}`);
    }
    case "create_dns_record": {
      const body: Record<string, unknown> = {
        type: args.type,
        name: args.name,
        content: args.content,
        ttl: args.ttl || 1,
        proxied: args.proxied ?? false,
      };
      if (args.priority !== undefined) body.priority = args.priority;
      return await cfRequest(`/zones/${args.zone_id}/dns_records`, "POST", body);
    }
    case "update_dns_record": {
      const body: Record<string, unknown> = {};
      if (args.type) body.type = args.type;
      if (args.name) body.name = args.name;
      if (args.content) body.content = args.content;
      if (args.ttl !== undefined) body.ttl = args.ttl;
      if (args.proxied !== undefined) body.proxied = args.proxied;
      return await cfRequest(`/zones/${args.zone_id}/dns_records/${args.record_id}`, "PATCH", body);
    }
    case "delete_dns_record": {
      return await cfRequest(`/zones/${args.zone_id}/dns_records/${args.record_id}`, "DELETE");
    }

    // ── Cache ──
    case "purge_cache_all": {
      return await cfRequest(`/zones/${args.zone_id}/purge_cache`, "POST", { purge_everything: true });
    }
    case "purge_cache_files": {
      return await cfRequest(`/zones/${args.zone_id}/purge_cache`, "POST", { files: args.files });
    }

    // ── Page Rules ──
    case "list_page_rules": {
      let endpoint = `/zones/${args.zone_id}/pagerules`;
      if (args.status) endpoint += `?status=${args.status}`;
      return await cfRequest(endpoint);
    }

    // ── Firewall ──
    case "list_firewall_rules": {
      return await cfRequest(`/zones/${args.zone_id}/firewall/rules?per_page=${args.per_page || 50}`);
    }

    // ── SSL ──
    case "get_ssl_settings": {
      return await cfRequest(`/zones/${args.zone_id}/settings/ssl`);
    }
    case "update_ssl_settings": {
      return await cfRequest(`/zones/${args.zone_id}/settings/ssl`, "PATCH", { value: args.value });
    }

    // ── Zone Settings ──
    case "get_zone_settings": {
      return await cfRequest(`/zones/${args.zone_id}/settings`);
    }
    case "update_zone_setting": {
      return await cfRequest(`/zones/${args.zone_id}/settings/${args.setting}`, "PATCH", { value: args.value });
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ─────────────────────────────────────────────
// MCP JSON-RPC handler
// ─────────────────────────────────────────────
async function handleMcpRequest(request: {
  jsonrpc: string;
  id?: unknown;
  method: string;
  params?: Record<string, unknown>;
}): Promise<unknown> {
  const { id, method, params } = request;
  try {
    let result;
    switch (method) {
      case "initialize":
        result = {
          protocolVersion: "2024-11-05",
          serverInfo: { name: "cloudflare-mcp-server", version: "1.0.0" },
          capabilities: { tools: {} },
        };
        break;
      case "notifications/initialized":
        return null;
      case "tools/list":
        result = { tools };
        break;
      case "tools/call":
        if (!params) throw new Error("Missing params");
        const toolResult = await executeTool(
          params.name as string,
          (params.arguments as Record<string, unknown>) || {}
        );
        result = { content: [{ type: "text", text: JSON.stringify(toolResult, null, 2) }] };
        break;
      case "ping":
        result = {};
        break;
      default:
        throw new Error(`Unknown method: ${method}`);
    }
    if (id !== undefined) return { jsonrpc: "2.0", id, result };
    return null;
  } catch (error) {
    if (id !== undefined) {
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: error instanceof Error ? error.message : String(error) },
      };
    }
    return null;
  }
}

// ─────────────────────────────────────────────
// Express routes
// ─────────────────────────────────────────────
app.get("/sse", (req: Request, res: Response) => {
  const sessionId = randomUUID();
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("Access-Control-Allow-Origin", "*");
  sessions.set(sessionId, res);
  res.write(`event: endpoint\ndata: /messages?sessionId=${sessionId}\n\n`);
  const keepAlive = setInterval(() => res.write(": keepalive\n\n"), 30000);
  req.on("close", () => {
    clearInterval(keepAlive);
    sessions.delete(sessionId);
  });
});

app.post("/messages", async (req: Request, res: Response) => {
  const sessionId = req.query.sessionId as string;
  if (!sessionId || !sessions.has(sessionId)) {
    res.status(400).json({ error: "Invalid or missing sessionId" });
    return;
  }
  const sseResponse = sessions.get(sessionId)!;
  let body = "";
  req.setEncoding("utf8");
  for await (const chunk of req) body += chunk;
  try {
    const request = JSON.parse(body);
    const response = await handleMcpRequest(request);
    if (response) sseResponse.write(`event: message\ndata: ${JSON.stringify(response)}\n\n`);
    res.status(202).json({ status: "accepted" });
  } catch (error) {
    console.error("Error handling message:", error);
    res.status(400).json({ error: "Invalid request" });
  }
});

app.get("/health", (_req: Request, res: Response) => {
  const authMode = CF_AUTH_TYPE === "global_key" ? "Global API Key" : "API Token";
  res.json({ status: "ok", version: "1.0.0", authMode, sessions: sessions.size });
});

app.get("/", (_req: Request, res: Response) => {
  res.json({
    name: "Cloudflare MCP Server",
    version: "1.0.0",
    auth: CF_AUTH_TYPE === "global_key" ? "Global API Key" : "API Token",
    tools: tools.map((t) => t.name),
    endpoints: { sse: "/sse", messages: "/messages", health: "/health" },
  });
});

app.listen(PORT, () => {
  const authMode = CF_AUTH_TYPE === "global_key" ? "Global API Key" : "API Token";
  console.log(`Cloudflare MCP Server v1.0.0 running on port ${PORT} [auth: ${authMode}]`);
});
