import { randomUUID } from "crypto";
import type { Application, Request, Response } from "express";

// Adds modern MCP transport routes:
// /.well-known/mcp.json  — manifest discovery
// /mcp/sse              — SSE transport (new path convention)
// /mcp/messages         — SSE message posting (new path)
// POST /mcp             — StreamableHTTP transport (JSON-RPC)
// GET  /mcp             — StreamableHTTP SSE stream

export function setupModernRoutes(
  app: Application,
  tools: unknown[],
  handleMcpRequest: (req: unknown) => Promise<unknown>,
  sessions: Map<string, Response>
): void {

  // CORS preflight
  app.options("*" as never, (_req: Request, res: Response) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, mcp-session-id, Accept");
    res.status(204).send();
  });

  // Well-known MCP manifest
  app.get("/.well-known/mcp.json", (_req: Request, res: Response) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.json({
      name: "Cloudflare MCP Server",
      version: "3.1.0",
      description: "Full Cloudflare API coverage",
      transport: [
        { type: "sse", url: "/sse" },
        { type: "sse", url: "/mcp/sse" },
        { type: "http", url: "/mcp" }
      ],
      tools: (tools as { name: string }[]).length
    });
  });

  // /mcp/sse - SSE transport on new path
  app.get("/mcp/sse", (req: Request, res: Response) => {
    const sessionId = randomUUID();
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("Access-Control-Allow-Origin", "*");
    sessions.set(sessionId, res);
    res.write(`event: endpoint\ndata: /mcp/messages?sessionId=${sessionId}\n\n`);
    const ka = setInterval(() => res.write(": keepalive\n\n"), 30000);
    req.on("close", () => { clearInterval(ka); sessions.delete(sessionId); });
  });

  // /mcp/messages - message posting on new path
  app.post("/mcp/messages", async (req: Request, res: Response) => {
    const sessionId = req.query.sessionId as string;
    if (!sessionId || !sessions.has(sessionId)) { res.status(400).json({ error: "Invalid or missing sessionId" }); return; }
    const sseRes = sessions.get(sessionId)!;
    let body = "";
    req.setEncoding("utf8");
    for await (const chunk of req) body += chunk;
    try {
      const response = await handleMcpRequest(JSON.parse(body));
      if (response) sseRes.write(`event: message\ndata: ${JSON.stringify(response)}\n\n`);
      res.status(202).json({ status: "accepted" });
    } catch { res.status(400).json({ error: "Invalid request" }); }
  });

  // POST /mcp - StreamableHTTP transport (modern MCP protocol)
  app.post("/mcp", async (req: Request, res: Response) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    const sessionId = (req.headers["mcp-session-id"] as string) || randomUUID();
    let body = "";
    req.setEncoding("utf8");
    for await (const chunk of req) body += chunk;
    try {
      const request = JSON.parse(body);
      const response = await handleMcpRequest(request);
      if (req.headers.accept?.includes("text/event-stream")) {
        res.setHeader("Content-Type", "text/event-stream");
        res.setHeader("Cache-Control", "no-cache");
        res.setHeader("mcp-session-id", sessionId);
        if (response) res.write(`event: message\ndata: ${JSON.stringify(response)}\n\n`);
        res.end();
      } else {
        res.setHeader("Content-Type", "application/json");
        res.setHeader("mcp-session-id", sessionId);
        res.status(200).json(response ?? {});
      }
    } catch (e) {
      res.status(400).json({ error: e instanceof Error ? e.message : "Invalid request" });
    }
  });

  // GET /mcp - SSE stream for server-initiated messages (StreamableHTTP spec)
  app.get("/mcp", (req: Request, res: Response) => {
    const sessionId = (req.headers["mcp-session-id"] as string) || randomUUID();
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("mcp-session-id", sessionId);
    sessions.set(sessionId, res);
    res.write(`: connected\n\n`);
    const ka = setInterval(() => res.write(": keepalive\n\n"), 30000);
    req.on("close", () => { clearInterval(ka); sessions.delete(sessionId); });
  });
}
