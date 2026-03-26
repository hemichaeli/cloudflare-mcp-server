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
const CF_AUTH_TYPE = process.env.CF_AUTH_TYPE || "token";
const CF_API_TOKEN = process.env.CF_API_TOKEN || "";
const CF_API_EMAIL = process.env.CF_API_EMAIL || "";
const CF_API_KEY = process.env.CF_API_KEY || "";
const PORT = process.env.PORT || 3000;
const CF_BASE_URL = "https://api.cloudflare.com/client/v4";

const sessions = new Map<string, Response>();

function getAuthHeaders(): Record<string, string> {
  if (CF_AUTH_TYPE === "global_key") {
    return { "X-Auth-Email": CF_API_EMAIL, "X-Auth-Key": CF_API_KEY, "Content-Type": "application/json" };
  }
  return { "Authorization": `Bearer ${CF_API_TOKEN}`, "Content-Type": "application/json" };
}

async function cfRequest(endpoint: string, method = "GET", body?: unknown): Promise<unknown> {
  const res = await fetch(`${CF_BASE_URL}${endpoint}`, {
    method,
    headers: getAuthHeaders(),
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const data = await res.json() as { success: boolean; errors: unknown[]; result: unknown };
  if (!data.success) throw new Error(`Cloudflare API error: ${JSON.stringify(data.errors)}`);
  return data.result;
}

// ─────────────────────────────────────────────
// Tool definitions
// ─────────────────────────────────────────────
const tools = [
  // ── Account ──
  { name: "list_accounts", description: "List all Cloudflare accounts accessible with the current token.", inputSchema: { type: "object", properties: { page: { type: "number" }, per_page: { type: "number" } } } },
  { name: "get_account", description: "Get details of a specific account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_account_settings", description: "Get settings for an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },

  // ── Zones ──
  { name: "list_zones", description: "List all Cloudflare zones. Supports filtering by name and status.", inputSchema: { type: "object", properties: { name: { type: "string" }, status: { type: "string", description: "active | pending | paused | deactivated" }, per_page: { type: "number" }, page: { type: "number" } } } },
  { name: "get_zone", description: "Get details of a specific zone by ID.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_zone_by_name", description: "Find a zone by domain name and return its ID and details.", inputSchema: { type: "object", properties: { name: { type: "string", description: "e.g. example.com" } }, required: ["name"] } },
  { name: "create_zone", description: "Add a new zone to Cloudflare.", inputSchema: { type: "object", properties: { name: { type: "string" }, account_id: { type: "string" }, jump_start: { type: "boolean" }, type: { type: "string", description: "full | partial | secondary" } }, required: ["name", "account_id"] } },
  { name: "delete_zone", description: "Delete a zone from Cloudflare.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "pause_zone", description: "Pause Cloudflare on a zone (DNS-only mode).", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "unpause_zone", description: "Resume Cloudflare proxy on a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },

  // ── Zone Settings ──
  { name: "get_zone_settings", description: "Get all settings for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_zone_setting", description: "Get a single zone setting by name.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, setting: { type: "string", description: "e.g. ssl, always_https, security_level, browser_cache_ttl, minify, http2, http3, brotli, websockets" } }, required: ["zone_id", "setting"] } },
  { name: "update_zone_setting", description: "Update a zone setting (e.g. ssl, always_https, security_level, browser_cache_ttl, minify, http2, http3, brotli, websockets, development_mode, rocket_loader, polish, mirage, hotlink_protection).", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, setting: { type: "string" }, value: { description: "New value (string, number, object, or boolean)" } }, required: ["zone_id", "setting", "value"] } },

  // ── DNS Records ──
  { name: "list_dns_records", description: "List DNS records for a zone. Filter by type and name.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, type: { type: "string", description: "A | AAAA | CNAME | MX | TXT | NS | SRV | CAA | PTR | SOA" }, name: { type: "string" }, content: { type: "string" }, per_page: { type: "number" }, page: { type: "number" } }, required: ["zone_id"] } },
  { name: "get_dns_record", description: "Get a specific DNS record by ID.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, record_id: { type: "string" } }, required: ["zone_id", "record_id"] } },
  { name: "create_dns_record", description: "Create a DNS record.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, type: { type: "string" }, name: { type: "string", description: "Use @ for root" }, content: { type: "string" }, ttl: { type: "number", description: "1 = auto" }, proxied: { type: "boolean" }, priority: { type: "number", description: "MX/SRV only" }, comment: { type: "string" } }, required: ["zone_id", "type", "name", "content"] } },
  { name: "update_dns_record", description: "Update an existing DNS record.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, record_id: { type: "string" }, type: { type: "string" }, name: { type: "string" }, content: { type: "string" }, ttl: { type: "number" }, proxied: { type: "boolean" }, comment: { type: "string" } }, required: ["zone_id", "record_id"] } },
  { name: "delete_dns_record", description: "Delete a DNS record.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, record_id: { type: "string" } }, required: ["zone_id", "record_id"] } },
  { name: "export_dns_records", description: "Export DNS records as BIND zone file.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },

  // ── Cache ──
  { name: "purge_cache_all", description: "Purge all cached files for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "purge_cache_files", description: "Purge specific URLs from cache.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, files: { type: "array", items: { type: "string" } } }, required: ["zone_id", "files"] } },
  { name: "purge_cache_tags", description: "Purge cache by Cache-Tag headers.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, tags: { type: "array", items: { type: "string" } } }, required: ["zone_id", "tags"] } },
  { name: "purge_cache_hosts", description: "Purge cache for specific hostnames.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, hosts: { type: "array", items: { type: "string" } } }, required: ["zone_id", "hosts"] } },
  { name: "purge_cache_prefixes", description: "Purge cache by URL prefix.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, prefixes: { type: "array", items: { type: "string" } } }, required: ["zone_id", "prefixes"] } },

  // ── SSL/TLS ──
  { name: "get_ssl_settings", description: "Get SSL/TLS mode for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "update_ssl_settings", description: "Update SSL/TLS mode (off | flexible | full | strict).", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, value: { type: "string", description: "off | flexible | full | strict" } }, required: ["zone_id", "value"] } },
  { name: "list_certificates", description: "List SSL certificates for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_certificate", description: "Get a specific SSL certificate.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, cert_id: { type: "string" } }, required: ["zone_id", "cert_id"] } },
  { name: "delete_certificate", description: "Delete an SSL certificate.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, cert_id: { type: "string" } }, required: ["zone_id", "cert_id"] } },
  { name: "get_tls_1_3", description: "Get TLS 1.3 setting for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "update_tls_1_3", description: "Enable or disable TLS 1.3.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, value: { type: "string", description: "on | off | zrt" } }, required: ["zone_id", "value"] } },

  // ── Page Rules ──
  { name: "list_page_rules", description: "List page rules for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, status: { type: "string", description: "active | disabled" }, order: { type: "string" }, direction: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_page_rule", description: "Get a specific page rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },
  { name: "create_page_rule", description: "Create a page rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, targets: { type: "array", description: "Array of URL match targets" }, actions: { type: "array", description: "Array of actions to apply" }, status: { type: "string", description: "active | disabled" }, priority: { type: "number" } }, required: ["zone_id", "targets", "actions"] } },
  { name: "update_page_rule", description: "Update a page rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" }, targets: { type: "array" }, actions: { type: "array" }, status: { type: "string" }, priority: { type: "number" } }, required: ["zone_id", "rule_id"] } },
  { name: "delete_page_rule", description: "Delete a page rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },

  // ── Firewall / WAF ──
  { name: "list_firewall_rules", description: "List firewall rules for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, per_page: { type: "number" }, page: { type: "number" } }, required: ["zone_id"] } },
  { name: "get_firewall_rule", description: "Get a specific firewall rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },
  { name: "create_firewall_rule", description: "Create a firewall rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, filter: { type: "object", description: "Filter with expression, e.g. { expression: 'ip.src eq 1.2.3.4' }" }, action: { type: "string", description: "block | challenge | js_challenge | managed_challenge | allow | log | bypass" }, description: { type: "string" }, priority: { type: "number" } }, required: ["zone_id", "filter", "action"] } },
  { name: "update_firewall_rule", description: "Update a firewall rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" }, action: { type: "string" }, description: { type: "string" }, paused: { type: "boolean" } }, required: ["zone_id", "rule_id"] } },
  { name: "delete_firewall_rule", description: "Delete a firewall rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },
  { name: "list_ip_access_rules", description: "List IP access rules (IP block/allow list) for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, mode: { type: "string", description: "block | challenge | whitelist | js_challenge" }, per_page: { type: "number" } }, required: ["zone_id"] } },
  { name: "create_ip_access_rule", description: "Create an IP access rule to block, allow, or challenge an IP/range/country/ASN.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, mode: { type: "string", description: "block | challenge | whitelist | js_challenge" }, configuration: { type: "object", description: "{ target: 'ip'|'ip_range'|'country'|'asn', value: '1.2.3.4' }" }, notes: { type: "string" } }, required: ["zone_id", "mode", "configuration"] } },
  { name: "delete_ip_access_rule", description: "Delete an IP access rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },
  { name: "list_waf_packages", description: "List WAF rule packages for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "list_waf_rules", description: "List WAF rules in a package.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, package_id: { type: "string" }, per_page: { type: "number" } }, required: ["zone_id", "package_id"] } },

  // ── Rate Limiting ──
  { name: "list_rate_limits", description: "List rate limit rules for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, per_page: { type: "number" } }, required: ["zone_id"] } },
  { name: "get_rate_limit", description: "Get a specific rate limit rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },
  { name: "create_rate_limit", description: "Create a rate limit rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, match: { type: "object", description: "URL and request match conditions" }, threshold: { type: "number" }, period: { type: "number" }, action: { type: "object", description: "Action object with mode: simulate|ban|challenge|js_challenge" }, description: { type: "string" }, disabled: { type: "boolean" } }, required: ["zone_id", "match", "threshold", "period", "action"] } },
  { name: "delete_rate_limit", description: "Delete a rate limit rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },

  // ── Workers ──
  { name: "list_workers", description: "List all Workers scripts in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_worker", description: "Get a Worker script.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, script_name: { type: "string" } }, required: ["account_id", "script_name"] } },
  { name: "delete_worker", description: "Delete a Worker script.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, script_name: { type: "string" } }, required: ["account_id", "script_name"] } },
  { name: "list_worker_routes", description: "List Worker routes for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "create_worker_route", description: "Create a Worker route for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, pattern: { type: "string", description: "URL pattern, e.g. example.com/api/*" }, script: { type: "string", description: "Worker script name" } }, required: ["zone_id", "pattern"] } },
  { name: "delete_worker_route", description: "Delete a Worker route.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, route_id: { type: "string" } }, required: ["zone_id", "route_id"] } },

  // ── KV Storage ──
  { name: "list_kv_namespaces", description: "List all KV namespaces in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, per_page: { type: "number" } }, required: ["account_id"] } },
  { name: "create_kv_namespace", description: "Create a KV namespace.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, title: { type: "string" } }, required: ["account_id", "title"] } },
  { name: "delete_kv_namespace", description: "Delete a KV namespace.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, namespace_id: { type: "string" } }, required: ["account_id", "namespace_id"] } },
  { name: "list_kv_keys", description: "List keys in a KV namespace.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, namespace_id: { type: "string" }, limit: { type: "number" }, prefix: { type: "string" }, cursor: { type: "string" } }, required: ["account_id", "namespace_id"] } },
  { name: "get_kv_value", description: "Get the value of a KV key.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, namespace_id: { type: "string" }, key: { type: "string" } }, required: ["account_id", "namespace_id", "key"] } },
  { name: "put_kv_value", description: "Set a KV key-value pair.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, namespace_id: { type: "string" }, key: { type: "string" }, value: { type: "string" }, expiration_ttl: { type: "number" } }, required: ["account_id", "namespace_id", "key", "value"] } },
  { name: "delete_kv_key", description: "Delete a KV key.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, namespace_id: { type: "string" }, key: { type: "string" } }, required: ["account_id", "namespace_id", "key"] } },

  // ── R2 Storage ──
  { name: "list_r2_buckets", description: "List all R2 buckets in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "create_r2_bucket", description: "Create an R2 bucket.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" }, location_hint: { type: "string", description: "WNAM | ENAM | WEUR | EEUR | APAC | OC" } }, required: ["account_id", "name"] } },
  { name: "delete_r2_bucket", description: "Delete an R2 bucket.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" } }, required: ["account_id", "name"] } },
  { name: "get_r2_bucket", description: "Get details of an R2 bucket.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" } }, required: ["account_id", "name"] } },

  // ── D1 Databases ──
  { name: "list_d1_databases", description: "List all D1 databases in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, per_page: { type: "number" } }, required: ["account_id"] } },
  { name: "get_d1_database", description: "Get details of a D1 database.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, database_id: { type: "string" } }, required: ["account_id", "database_id"] } },
  { name: "create_d1_database", description: "Create a D1 database.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" } }, required: ["account_id", "name"] } },
  { name: "delete_d1_database", description: "Delete a D1 database.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, database_id: { type: "string" } }, required: ["account_id", "database_id"] } },
  { name: "query_d1_database", description: "Execute a SQL query on a D1 database.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, database_id: { type: "string" }, sql: { type: "string" }, params: { type: "array", description: "Positional parameters for the SQL query" } }, required: ["account_id", "database_id", "sql"] } },

  // ── Load Balancers ──
  { name: "list_load_balancers", description: "List load balancers for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_load_balancer", description: "Get a specific load balancer.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, lb_id: { type: "string" } }, required: ["zone_id", "lb_id"] } },
  { name: "list_lb_pools", description: "List load balancer origin pools.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_lb_pool", description: "Get a specific load balancer pool.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, pool_id: { type: "string" } }, required: ["account_id", "pool_id"] } },
  { name: "list_lb_monitors", description: "List load balancer health monitors.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },

  // ── Analytics ──
  { name: "get_zone_analytics", description: "Get zone analytics summary (requests, bandwidth, threats, pageviews).", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, since: { type: "string", description: "ISO 8601 start time, e.g. -1440 (minutes) or date string" }, until: { type: "string", description: "ISO 8601 end time" } }, required: ["zone_id"] } },
  { name: "get_zone_analytics_by_time", description: "Get zone analytics grouped by time interval.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, since: { type: "string" }, until: { type: "string" }, time_delta: { type: "string", description: "year | quarter | month | week | day | hour | dekaminute | minute" } }, required: ["zone_id"] } },
  { name: "get_dns_analytics", description: "Get DNS query analytics for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, dimensions: { type: "array", items: { type: "string" } }, metrics: { type: "array", items: { type: "string" } }, since: { type: "string" }, until: { type: "string" }, limit: { type: "number" } }, required: ["zone_id"] } },

  // ── Redirects / Bulk Redirects ──
  { name: "list_redirect_rules", description: "List redirect rules for a zone (Ruleset-based).", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "list_bulk_redirect_lists", description: "List bulk redirect lists in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_bulk_redirect_list", description: "Get a specific bulk redirect list.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, list_id: { type: "string" } }, required: ["account_id", "list_id"] } },
  { name: "list_bulk_redirect_items", description: "List items in a bulk redirect list.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, list_id: { type: "string" } }, required: ["account_id", "list_id"] } },

  // ── Zero Trust / Access ──
  { name: "list_access_applications", description: "List Zero Trust Access applications.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_access_application", description: "Get a Zero Trust Access application.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, app_id: { type: "string" } }, required: ["account_id", "app_id"] } },
  { name: "list_access_policies", description: "List policies for an Access application.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, app_id: { type: "string" } }, required: ["account_id", "app_id"] } },
  { name: "list_access_groups", description: "List Zero Trust Access groups.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "list_access_service_tokens", description: "List Access service tokens.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "create_access_service_token", description: "Create an Access service token.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" } }, required: ["account_id", "name"] } },
  { name: "rotate_access_service_token", description: "Rotate (refresh) an Access service token.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, token_id: { type: "string" } }, required: ["account_id", "token_id"] } },
  { name: "delete_access_service_token", description: "Delete an Access service token.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, token_id: { type: "string" } }, required: ["account_id", "token_id"] } },

  // ── Tunnels (Cloudflare Tunnel / Argo) ──
  { name: "list_tunnels", description: "List Cloudflare Tunnels (cloudflared) in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" }, is_deleted: { type: "boolean" } }, required: ["account_id"] } },
  { name: "get_tunnel", description: "Get details of a specific Cloudflare Tunnel.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, tunnel_id: { type: "string" } }, required: ["account_id", "tunnel_id"] } },
  { name: "create_tunnel", description: "Create a Cloudflare Tunnel.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" }, tunnel_secret: { type: "string", description: "Base64 encoded 32-byte secret" } }, required: ["account_id", "name", "tunnel_secret"] } },
  { name: "delete_tunnel", description: "Delete a Cloudflare Tunnel.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, tunnel_id: { type: "string" } }, required: ["account_id", "tunnel_id"] } },
  { name: "get_tunnel_token", description: "Get the token for a tunnel (used to run cloudflared).", inputSchema: { type: "object", properties: { account_id: { type: "string" }, tunnel_id: { type: "string" } }, required: ["account_id", "tunnel_id"] } },
  { name: "get_tunnel_connections", description: "Get active connections for a tunnel.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, tunnel_id: { type: "string" } }, required: ["account_id", "tunnel_id"] } },
  { name: "list_tunnel_routes", description: "List tunnel routes (private network CIDRs) in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_tunnel_config", description: "Get ingress config for a tunnel.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, tunnel_id: { type: "string" } }, required: ["account_id", "tunnel_id"] } },
  { name: "update_tunnel_config", description: "Update ingress config for a tunnel.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, tunnel_id: { type: "string" }, config: { type: "object", description: "Tunnel config object with ingress rules array" } }, required: ["account_id", "tunnel_id", "config"] } },

  // ── Users & Tokens ──
  { name: "get_user", description: "Get current user details.", inputSchema: { type: "object", properties: {} } },
  { name: "list_api_tokens", description: "List API tokens for the current user.", inputSchema: { type: "object", properties: {} } },
  { name: "get_api_token", description: "Get details of an API token.", inputSchema: { type: "object", properties: { token_id: { type: "string" } }, required: ["token_id"] } },
  { name: "verify_api_token", description: "Verify the current API token is valid.", inputSchema: { type: "object", properties: {} } },
  { name: "list_account_members", description: "List members of an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
];

// ─────────────────────────────────────────────
// Tool execution
// ─────────────────────────────────────────────
async function executeTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  const a = args;
  switch (name) {
    // Account
    case "list_accounts": return await cfRequest(`/accounts?page=${a.page || 1}&per_page=${a.per_page || 50}`);
    case "get_account": return await cfRequest(`/accounts/${a.account_id}`);
    case "get_account_settings": return await cfRequest(`/accounts/${a.account_id}/settings`);

    // Zones
    case "list_zones": {
      let ep = `/zones?page=${a.page || 1}&per_page=${a.per_page || 50}`;
      if (a.name) ep += `&name=${encodeURIComponent(a.name as string)}`;
      if (a.status) ep += `&status=${a.status}`;
      return await cfRequest(ep);
    }
    case "get_zone": return await cfRequest(`/zones/${a.zone_id}`);
    case "get_zone_by_name": {
      const r = await cfRequest(`/zones?name=${encodeURIComponent(a.name as string)}`) as unknown[];
      if (!r || !r.length) throw new Error(`Zone not found: ${a.name}`);
      return r[0];
    }
    case "create_zone": return await cfRequest("/zones", "POST", { name: a.name, account: { id: a.account_id }, jump_start: a.jump_start ?? true, type: a.type || "full" });
    case "delete_zone": return await cfRequest(`/zones/${a.zone_id}`, "DELETE");
    case "pause_zone": return await cfRequest(`/zones/${a.zone_id}`, "PATCH", { paused: true });
    case "unpause_zone": return await cfRequest(`/zones/${a.zone_id}`, "PATCH", { paused: false });

    // Zone Settings
    case "get_zone_settings": return await cfRequest(`/zones/${a.zone_id}/settings`);
    case "get_zone_setting": return await cfRequest(`/zones/${a.zone_id}/settings/${a.setting}`);
    case "update_zone_setting": return await cfRequest(`/zones/${a.zone_id}/settings/${a.setting}`, "PATCH", { value: a.value });

    // DNS Records
    case "list_dns_records": {
      let ep = `/zones/${a.zone_id}/dns_records?per_page=${a.per_page || 100}&page=${a.page || 1}`;
      if (a.type) ep += `&type=${a.type}`;
      if (a.name) ep += `&name=${encodeURIComponent(a.name as string)}`;
      if (a.content) ep += `&content=${encodeURIComponent(a.content as string)}`;
      return await cfRequest(ep);
    }
    case "get_dns_record": return await cfRequest(`/zones/${a.zone_id}/dns_records/${a.record_id}`);
    case "create_dns_record": {
      const body: Record<string, unknown> = { type: a.type, name: a.name, content: a.content, ttl: a.ttl || 1, proxied: a.proxied ?? false };
      if (a.priority !== undefined) body.priority = a.priority;
      if (a.comment) body.comment = a.comment;
      return await cfRequest(`/zones/${a.zone_id}/dns_records`, "POST", body);
    }
    case "update_dns_record": {
      const body: Record<string, unknown> = {};
      ["type","name","content","ttl","proxied","comment"].forEach(k => { if (a[k] !== undefined) body[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/dns_records/${a.record_id}`, "PATCH", body);
    }
    case "delete_dns_record": return await cfRequest(`/zones/${a.zone_id}/dns_records/${a.record_id}`, "DELETE");
    case "export_dns_records": {
      const res = await fetch(`${CF_BASE_URL}/zones/${a.zone_id}/dns_records/export`, { headers: getAuthHeaders() });
      return await res.text();
    }

    // Cache
    case "purge_cache_all": return await cfRequest(`/zones/${a.zone_id}/purge_cache`, "POST", { purge_everything: true });
    case "purge_cache_files": return await cfRequest(`/zones/${a.zone_id}/purge_cache`, "POST", { files: a.files });
    case "purge_cache_tags": return await cfRequest(`/zones/${a.zone_id}/purge_cache`, "POST", { tags: a.tags });
    case "purge_cache_hosts": return await cfRequest(`/zones/${a.zone_id}/purge_cache`, "POST", { hosts: a.hosts });
    case "purge_cache_prefixes": return await cfRequest(`/zones/${a.zone_id}/purge_cache`, "POST", { prefixes: a.prefixes });

    // SSL/TLS
    case "get_ssl_settings": return await cfRequest(`/zones/${a.zone_id}/settings/ssl`);
    case "update_ssl_settings": return await cfRequest(`/zones/${a.zone_id}/settings/ssl`, "PATCH", { value: a.value });
    case "list_certificates": return await cfRequest(`/zones/${a.zone_id}/ssl/certificate_packs`);
    case "get_certificate": return await cfRequest(`/zones/${a.zone_id}/ssl/certificate_packs/${a.cert_id}`);
    case "delete_certificate": return await cfRequest(`/zones/${a.zone_id}/ssl/certificate_packs/${a.cert_id}`, "DELETE");
    case "get_tls_1_3": return await cfRequest(`/zones/${a.zone_id}/settings/tls_1_3`);
    case "update_tls_1_3": return await cfRequest(`/zones/${a.zone_id}/settings/tls_1_3`, "PATCH", { value: a.value });

    // Page Rules
    case "list_page_rules": {
      let ep = `/zones/${a.zone_id}/pagerules?order=${a.order || "priority"}&direction=${a.direction || "asc"}`;
      if (a.status) ep += `&status=${a.status}`;
      return await cfRequest(ep);
    }
    case "get_page_rule": return await cfRequest(`/zones/${a.zone_id}/pagerules/${a.rule_id}`);
    case "create_page_rule": return await cfRequest(`/zones/${a.zone_id}/pagerules`, "POST", { targets: a.targets, actions: a.actions, status: a.status || "active", priority: a.priority || 1 });
    case "update_page_rule": {
      const body: Record<string, unknown> = {};
      ["targets","actions","status","priority"].forEach(k => { if (a[k] !== undefined) body[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/pagerules/${a.rule_id}`, "PATCH", body);
    }
    case "delete_page_rule": return await cfRequest(`/zones/${a.zone_id}/pagerules/${a.rule_id}`, "DELETE");

    // Firewall
    case "list_firewall_rules": return await cfRequest(`/zones/${a.zone_id}/firewall/rules?page=${a.page || 1}&per_page=${a.per_page || 50}`);
    case "get_firewall_rule": return await cfRequest(`/zones/${a.zone_id}/firewall/rules/${a.rule_id}`);
    case "create_firewall_rule": return await cfRequest(`/zones/${a.zone_id}/firewall/rules`, "POST", [{ filter: a.filter, action: a.action, description: a.description || "", priority: a.priority }]);
    case "update_firewall_rule": {
      const body: Record<string, unknown> = { id: a.rule_id };
      ["action","description","paused"].forEach(k => { if (a[k] !== undefined) body[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/firewall/rules/${a.rule_id}`, "PATCH", body);
    }
    case "delete_firewall_rule": return await cfRequest(`/zones/${a.zone_id}/firewall/rules/${a.rule_id}`, "DELETE");
    case "list_ip_access_rules": {
      let ep = `/zones/${a.zone_id}/firewall/access_rules/rules?per_page=${a.per_page || 50}`;
      if (a.mode) ep += `&mode=${a.mode}`;
      return await cfRequest(ep);
    }
    case "create_ip_access_rule": return await cfRequest(`/zones/${a.zone_id}/firewall/access_rules/rules`, "POST", { mode: a.mode, configuration: a.configuration, notes: a.notes || "" });
    case "delete_ip_access_rule": return await cfRequest(`/zones/${a.zone_id}/firewall/access_rules/rules/${a.rule_id}`, "DELETE");
    case "list_waf_packages": return await cfRequest(`/zones/${a.zone_id}/firewall/waf/packages`);
    case "list_waf_rules": return await cfRequest(`/zones/${a.zone_id}/firewall/waf/packages/${a.package_id}/rules?per_page=${a.per_page || 100}`);

    // Rate Limiting
    case "list_rate_limits": return await cfRequest(`/zones/${a.zone_id}/rate_limits?per_page=${a.per_page || 50}`);
    case "get_rate_limit": return await cfRequest(`/zones/${a.zone_id}/rate_limits/${a.rule_id}`);
    case "create_rate_limit": return await cfRequest(`/zones/${a.zone_id}/rate_limits`, "POST", { match: a.match, threshold: a.threshold, period: a.period, action: a.action, description: a.description || "", disabled: a.disabled || false });
    case "delete_rate_limit": return await cfRequest(`/zones/${a.zone_id}/rate_limits/${a.rule_id}`, "DELETE");

    // Workers
    case "list_workers": return await cfRequest(`/accounts/${a.account_id}/workers/scripts`);
    case "get_worker": return await cfRequest(`/accounts/${a.account_id}/workers/scripts/${a.script_name}`);
    case "delete_worker": return await cfRequest(`/accounts/${a.account_id}/workers/scripts/${a.script_name}`, "DELETE");
    case "list_worker_routes": return await cfRequest(`/zones/${a.zone_id}/workers/routes`);
    case "create_worker_route": return await cfRequest(`/zones/${a.zone_id}/workers/routes`, "POST", { pattern: a.pattern, script: a.script || null });
    case "delete_worker_route": return await cfRequest(`/zones/${a.zone_id}/workers/routes/${a.route_id}`, "DELETE");

    // KV Storage
    case "list_kv_namespaces": return await cfRequest(`/accounts/${a.account_id}/storage/kv/namespaces?per_page=${a.per_page || 50}`);
    case "create_kv_namespace": return await cfRequest(`/accounts/${a.account_id}/storage/kv/namespaces`, "POST", { title: a.title });
    case "delete_kv_namespace": return await cfRequest(`/accounts/${a.account_id}/storage/kv/namespaces/${a.namespace_id}`, "DELETE");
    case "list_kv_keys": {
      let ep = `/accounts/${a.account_id}/storage/kv/namespaces/${a.namespace_id}/keys?limit=${a.limit || 1000}`;
      if (a.prefix) ep += `&prefix=${encodeURIComponent(a.prefix as string)}`;
      if (a.cursor) ep += `&cursor=${a.cursor}`;
      return await cfRequest(ep);
    }
    case "get_kv_value": {
      const res = await fetch(`${CF_BASE_URL}/accounts/${a.account_id}/storage/kv/namespaces/${a.namespace_id}/values/${encodeURIComponent(a.key as string)}`, { headers: getAuthHeaders() });
      return await res.text();
    }
    case "put_kv_value": {
      const url = `${CF_BASE_URL}/accounts/${a.account_id}/storage/kv/namespaces/${a.namespace_id}/values/${encodeURIComponent(a.key as string)}`;
      const headers = { ...getAuthHeaders(), "Content-Type": "text/plain" };
      const ep = a.expiration_ttl ? `?expiration_ttl=${a.expiration_ttl}` : "";
      const res = await fetch(url + ep, { method: "PUT", headers, body: a.value as string });
      return await res.json();
    }
    case "delete_kv_key": return await cfRequest(`/accounts/${a.account_id}/storage/kv/namespaces/${a.namespace_id}/values/${encodeURIComponent(a.key as string)}`, "DELETE");

    // R2
    case "list_r2_buckets": return await cfRequest(`/accounts/${a.account_id}/r2/buckets`);
    case "create_r2_bucket": return await cfRequest(`/accounts/${a.account_id}/r2/buckets`, "POST", { name: a.name, ...(a.location_hint ? { locationHint: a.location_hint } : {}) });
    case "delete_r2_bucket": return await cfRequest(`/accounts/${a.account_id}/r2/buckets/${a.name}`, "DELETE");
    case "get_r2_bucket": return await cfRequest(`/accounts/${a.account_id}/r2/buckets/${a.name}`);

    // D1
    case "list_d1_databases": return await cfRequest(`/accounts/${a.account_id}/d1/database?per_page=${a.per_page || 50}`);
    case "get_d1_database": return await cfRequest(`/accounts/${a.account_id}/d1/database/${a.database_id}`);
    case "create_d1_database": return await cfRequest(`/accounts/${a.account_id}/d1/database`, "POST", { name: a.name });
    case "delete_d1_database": return await cfRequest(`/accounts/${a.account_id}/d1/database/${a.database_id}`, "DELETE");
    case "query_d1_database": return await cfRequest(`/accounts/${a.account_id}/d1/database/${a.database_id}/query`, "POST", { sql: a.sql, params: a.params || [] });

    // Load Balancers
    case "list_load_balancers": return await cfRequest(`/zones/${a.zone_id}/load_balancers`);
    case "get_load_balancer": return await cfRequest(`/zones/${a.zone_id}/load_balancers/${a.lb_id}`);
    case "list_lb_pools": return await cfRequest(`/accounts/${a.account_id}/load_balancers/pools`);
    case "get_lb_pool": return await cfRequest(`/accounts/${a.account_id}/load_balancers/pools/${a.pool_id}`);
    case "list_lb_monitors": return await cfRequest(`/accounts/${a.account_id}/load_balancers/monitors`);

    // Analytics
    case "get_zone_analytics": return await cfRequest(`/zones/${a.zone_id}/analytics/dashboard?since=${a.since || "-10080"}&until=${a.until || "0"}&continuous=true`);
    case "get_zone_analytics_by_time": return await cfRequest(`/zones/${a.zone_id}/analytics/dashboard?since=${a.since || "-1440"}&until=${a.until || "0"}&time_delta=${a.time_delta || "hour"}`);
    case "get_dns_analytics": {
      const dims = (a.dimensions as string[] || ["queryName"]).join(",");
      const mets = (a.metrics as string[] || ["queryCount"]).join(",");
      return await cfRequest(`/zones/${a.zone_id}/dns_analytics/report?dimensions=${dims}&metrics=${mets}&since=${a.since || "-1440"}&until=${a.until || "0"}&limit=${a.limit || 100}`);
    }

    // Redirects
    case "list_redirect_rules": return await cfRequest(`/zones/${a.zone_id}/rulesets`);
    case "list_bulk_redirect_lists": return await cfRequest(`/accounts/${a.account_id}/rules/lists?per_page=100`);
    case "get_bulk_redirect_list": return await cfRequest(`/accounts/${a.account_id}/rules/lists/${a.list_id}`);
    case "list_bulk_redirect_items": return await cfRequest(`/accounts/${a.account_id}/rules/lists/${a.list_id}/items`);

    // Zero Trust / Access
    case "list_access_applications": return await cfRequest(`/accounts/${a.account_id}/access/apps`);
    case "get_access_application": return await cfRequest(`/accounts/${a.account_id}/access/apps/${a.app_id}`);
    case "list_access_policies": return await cfRequest(`/accounts/${a.account_id}/access/apps/${a.app_id}/policies`);
    case "list_access_groups": return await cfRequest(`/accounts/${a.account_id}/access/groups`);
    case "list_access_service_tokens": return await cfRequest(`/accounts/${a.account_id}/access/service_tokens`);
    case "create_access_service_token": return await cfRequest(`/accounts/${a.account_id}/access/service_tokens`, "POST", { name: a.name });
    case "rotate_access_service_token": return await cfRequest(`/accounts/${a.account_id}/access/service_tokens/${a.token_id}/rotate`, "POST");
    case "delete_access_service_token": return await cfRequest(`/accounts/${a.account_id}/access/service_tokens/${a.token_id}`, "DELETE");

    // Tunnels
    case "list_tunnels": {
      let ep = `/accounts/${a.account_id}/cfd_tunnel?per_page=100`;
      if (a.name) ep += `&name=${encodeURIComponent(a.name as string)}`;
      if (a.is_deleted !== undefined) ep += `&is_deleted=${a.is_deleted}`;
      return await cfRequest(ep);
    }
    case "get_tunnel": return await cfRequest(`/accounts/${a.account_id}/cfd_tunnel/${a.tunnel_id}`);
    case "create_tunnel": return await cfRequest(`/accounts/${a.account_id}/cfd_tunnel`, "POST", { name: a.name, tunnel_secret: a.tunnel_secret });
    case "delete_tunnel": return await cfRequest(`/accounts/${a.account_id}/cfd_tunnel/${a.tunnel_id}`, "DELETE");
    case "get_tunnel_token": return await cfRequest(`/accounts/${a.account_id}/cfd_tunnel/${a.tunnel_id}/token`);
    case "get_tunnel_connections": return await cfRequest(`/accounts/${a.account_id}/cfd_tunnel/${a.tunnel_id}/connections`);
    case "list_tunnel_routes": return await cfRequest(`/accounts/${a.account_id}/teamnet/routes`);
    case "get_tunnel_config": return await cfRequest(`/accounts/${a.account_id}/cfd_tunnel/${a.tunnel_id}/configurations`);
    case "update_tunnel_config": return await cfRequest(`/accounts/${a.account_id}/cfd_tunnel/${a.tunnel_id}/configurations`, "PUT", { config: a.config });

    // Users & Tokens
    case "get_user": return await cfRequest("/user");
    case "list_api_tokens": return await cfRequest("/user/tokens");
    case "get_api_token": return await cfRequest(`/user/tokens/${a.token_id}`);
    case "verify_api_token": return await cfRequest("/user/tokens/verify");
    case "list_account_members": return await cfRequest(`/accounts/${a.account_id}/members?per_page=50`);

    default: throw new Error(`Unknown tool: ${name}`);
  }
}

// ─────────────────────────────────────────────
// MCP JSON-RPC handler
// ─────────────────────────────────────────────
async function handleMcpRequest(request: { jsonrpc: string; id?: unknown; method: string; params?: Record<string, unknown> }): Promise<unknown> {
  const { id, method, params } = request;
  try {
    let result;
    switch (method) {
      case "initialize":
        result = { protocolVersion: "2024-11-05", serverInfo: { name: "cloudflare-mcp-server", version: "2.0.0" }, capabilities: { tools: {} } };
        break;
      case "notifications/initialized": return null;
      case "tools/list": result = { tools }; break;
      case "tools/call":
        if (!params) throw new Error("Missing params");
        result = { content: [{ type: "text", text: JSON.stringify(await executeTool(params.name as string, (params.arguments as Record<string, unknown>) || {}), null, 2) }] };
        break;
      case "ping": result = {}; break;
      default: throw new Error(`Unknown method: ${method}`);
    }
    if (id !== undefined) return { jsonrpc: "2.0", id, result };
    return null;
  } catch (error) {
    if (id !== undefined) return { jsonrpc: "2.0", id, error: { code: -32603, message: error instanceof Error ? error.message : String(error) } };
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
  req.on("close", () => { clearInterval(keepAlive); sessions.delete(sessionId); });
});

app.post("/messages", async (req: Request, res: Response) => {
  const sessionId = req.query.sessionId as string;
  if (!sessionId || !sessions.has(sessionId)) { res.status(400).json({ error: "Invalid or missing sessionId" }); return; }
  const sseResponse = sessions.get(sessionId)!;
  let body = "";
  req.setEncoding("utf8");
  for await (const chunk of req) body += chunk;
  try {
    const response = await handleMcpRequest(JSON.parse(body));
    if (response) sseResponse.write(`event: message\ndata: ${JSON.stringify(response)}\n\n`);
    res.status(202).json({ status: "accepted" });
  } catch { res.status(400).json({ error: "Invalid request" }); }
});

app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", version: "2.0.0", auth: CF_AUTH_TYPE === "global_key" ? "Global API Key" : "API Token", tools: tools.length, sessions: sessions.size });
});

app.get("/", (_req: Request, res: Response) => {
  res.json({ name: "Cloudflare MCP Server", version: "2.0.0", auth: CF_AUTH_TYPE, tools: tools.map(t => t.name), endpoints: { sse: "/sse", messages: "/messages", health: "/health" } });
});

app.listen(PORT, () => console.log(`Cloudflare MCP Server v2.0.0 on port ${PORT} [${tools.length} tools, auth: ${CF_AUTH_TYPE}]`));
