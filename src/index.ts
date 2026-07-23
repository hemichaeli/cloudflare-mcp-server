import express, { Request, Response } from "express";
import { randomUUID } from "crypto";
import { createRequire } from "module";

const nodeRequire = createRequire(import.meta.url);
const { hash: blake3hash } = nodeRequire("blake3-wasm") as { hash: (input: string) => Buffer };

const app = express();

const CF_AUTH_TYPE = process.env.CF_AUTH_TYPE || "token";
const CF_API_TOKEN = process.env.CF_API_TOKEN || "";
const CF_API_EMAIL = process.env.CF_API_EMAIL || "";
const CF_API_KEY = process.env.CF_API_KEY || "";
const PORT = process.env.PORT || 3000;
const CF_BASE_URL = "https://api.cloudflare.com/client/v4";
const sessions = new Map<string, Response>();

function getAuthHeaders(): Record<string, string> {
  if (CF_AUTH_TYPE === "global_key") return { "X-Auth-Email": CF_API_EMAIL, "X-Auth-Key": CF_API_KEY, "Content-Type": "application/json" };
  return { "Authorization": `Bearer ${CF_API_TOKEN}`, "Content-Type": "application/json" };
}

function getAuthHeadersNoCT(): Record<string, string> {
  if (CF_AUTH_TYPE === "global_key") return { "X-Auth-Email": CF_API_EMAIL, "X-Auth-Key": CF_API_KEY };
  return { "Authorization": `Bearer ${CF_API_TOKEN}` };
}

async function cfRequest(endpoint: string, method = "GET", body?: unknown): Promise<unknown> {
  const res = await fetch(`${CF_BASE_URL}${endpoint}`, { method, headers: getAuthHeaders(), ...(body ? { body: JSON.stringify(body) } : {}) });
  const data = await res.json() as { success: boolean; errors: unknown[]; result: unknown };
  if (!data.success) {
    const errStr = JSON.stringify(data.errors);
    const hint = /"code":(9109|10000)/.test(errStr) ? " | HINT: the main CF_API_TOKEN lacks a permission for this call. Use the create_api_token tool (backed by CF_BOOTSTRAP_TOKEN) to mint a token that includes the missing permission groups, then set it as CF_API_TOKEN on the Railway service (project 68b45790, service fc306544, env 03a48f2b)." : "";
    throw new Error(`Cloudflare API error: ${errStr}${hint}`);
  }
  return data.result;
}

const CF_BOOTSTRAP_TOKEN = process.env.CF_BOOTSTRAP_TOKEN || "";
async function bootstrapRequest(endpoint: string, method = "GET", body?: unknown): Promise<unknown> {
  if (!CF_BOOTSTRAP_TOKEN) throw new Error("CF_BOOTSTRAP_TOKEN is not set on the server environment");
  const res = await fetch(`${CF_BASE_URL}${endpoint}`, { method, headers: { "Authorization": `Bearer ${CF_BOOTSTRAP_TOKEN}`, "Content-Type": "application/json" }, ...(body ? { body: JSON.stringify(body) } : {}) });
  const data = await res.json() as { success: boolean; errors: unknown[]; result: unknown };
  if (!data.success) throw new Error(`Cloudflare API error (bootstrap): ${JSON.stringify(data.errors)}`);
  return data.result;
}

const tools = [
  // ── Account ──
  { name: "list_accounts", description: "List all Cloudflare accounts.", inputSchema: { type: "object", properties: { page: { type: "number" }, per_page: { type: "number" } } } },
  { name: "get_account", description: "Get details of a specific account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_account_settings", description: "Get settings for an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "list_account_members", description: "List members of an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },

  // ── Users & Tokens ──
  { name: "get_user", description: "Get current user details.", inputSchema: { type: "object", properties: {} } },
  { name: "list_api_tokens", description: "List API tokens for the current user.", inputSchema: { type: "object", properties: {} } },
  { name: "get_api_token", description: "Get details of an API token.", inputSchema: { type: "object", properties: { token_id: { type: "string" } }, required: ["token_id"] } },
  { name: "verify_api_token", description: "Verify the current API token is valid.", inputSchema: { type: "object", properties: {} } },
  { name: "list_token_permission_groups", description: "List all Cloudflare token permission groups (id, name, scopes) via CF_BOOTSTRAP_TOKEN. Use before create_api_token to find exact permission group names.", inputSchema: { type: "object", properties: {} } },
  { name: "create_api_token", description: "Create a new Cloudflare API token using CF_BOOTSTRAP_TOKEN (a token holding API Tokens:Edit). Pass account_permissions and/or zone_permissions as permission group NAMES exactly as returned by list_token_permission_groups; names are resolved to ids automatically. Zone permissions apply to all zones. Returns the token value ONCE. Use whenever any tool fails with permission errors (codes 9109/10000), then set the returned value as CF_API_TOKEN on Railway.", inputSchema: { type: "object", properties: { name: { type: "string", description: "Token name" }, account_permissions: { type: "array", items: { type: "string" }, description: "Account-scope permission group names" }, zone_permissions: { type: "array", items: { type: "string" }, description: "Zone-scope permission group names (all zones)" }, account_id: { type: "string", description: "Account id for account-scope policy. Defaults to the first account." }, dry_run: { type: "boolean", description: "Resolve and return the policies without creating the token" } }, required: ["name"] } },

  // ── Zones ──
  { name: "list_zones", description: "List all Cloudflare zones. Filter by name and status.", inputSchema: { type: "object", properties: { name: { type: "string" }, status: { type: "string", description: "active | pending | paused | deactivated" }, per_page: { type: "number" }, page: { type: "number" } } } },
  { name: "get_zone", description: "Get details of a zone by ID.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_zone_by_name", description: "Find a zone by domain name.", inputSchema: { type: "object", properties: { name: { type: "string" } }, required: ["name"] } },
  { name: "create_zone", description: "Add a new zone to Cloudflare.", inputSchema: { type: "object", properties: { name: { type: "string" }, account_id: { type: "string" }, jump_start: { type: "boolean" }, type: { type: "string", description: "full | partial | secondary" } }, required: ["name", "account_id"] } },
  { name: "delete_zone", description: "Delete a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "pause_zone", description: "Pause Cloudflare on a zone (DNS-only mode).", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "unpause_zone", description: "Resume Cloudflare proxy on a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_zone_analytics", description: "Get zone analytics summary (requests, bandwidth, threats, pageviews).", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, since: { type: "string" }, until: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_zone_analytics_by_time", description: "Get zone analytics grouped by time interval.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, since: { type: "string" }, until: { type: "string" }, time_delta: { type: "string", description: "year | quarter | month | week | day | hour | dekaminute | minute" } }, required: ["zone_id"] } },

  // ── Zone Settings ──
  { name: "get_zone_settings", description: "Get all settings for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_zone_setting", description: "Get a single zone setting by name (e.g. ssl, always_https, security_level).", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, setting: { type: "string" } }, required: ["zone_id", "setting"] } },
  { name: "update_zone_setting", description: "Update a zone setting.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, setting: { type: "string" }, value: {} }, required: ["zone_id", "setting", "value"] } },

  // ── DNS Records ──
  { name: "list_dns_records", description: "List DNS records for a zone. Filter by type and name.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, type: { type: "string" }, name: { type: "string" }, content: { type: "string" }, per_page: { type: "number" }, page: { type: "number" } }, required: ["zone_id"] } },
  { name: "get_dns_record", description: "Get a specific DNS record by ID.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, record_id: { type: "string" } }, required: ["zone_id", "record_id"] } },
  { name: "create_dns_record", description: "Create a DNS record (A, AAAA, CNAME, MX, TXT, NS, SRV, CAA, etc.).", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, type: { type: "string" }, name: { type: "string", description: "Use @ for root" }, content: { type: "string" }, ttl: { type: "number", description: "1 = auto" }, proxied: { type: "boolean" }, priority: { type: "number", description: "MX/SRV only" }, comment: { type: "string" } }, required: ["zone_id", "type", "name", "content"] } },
  { name: "update_dns_record", description: "Update an existing DNS record.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, record_id: { type: "string" }, type: { type: "string" }, name: { type: "string" }, content: { type: "string" }, ttl: { type: "number" }, proxied: { type: "boolean" }, comment: { type: "string" } }, required: ["zone_id", "record_id"] } },
  { name: "delete_dns_record", description: "Delete a DNS record.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, record_id: { type: "string" } }, required: ["zone_id", "record_id"] } },
  { name: "export_dns_records", description: "Export DNS records as BIND zone file.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_dns_analytics", description: "Get DNS query analytics for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, dimensions: { type: "array", items: { type: "string" } }, metrics: { type: "array", items: { type: "string" } }, since: { type: "string" }, until: { type: "string" }, limit: { type: "number" } }, required: ["zone_id"] } },

  // ── Cache ──
  { name: "purge_cache_all", description: "Purge all cached files for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "purge_cache_files", description: "Purge specific URLs from cache.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, files: { type: "array", items: { type: "string" } } }, required: ["zone_id", "files"] } },
  { name: "purge_cache_tags", description: "Purge cache by Cache-Tag headers.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, tags: { type: "array", items: { type: "string" } } }, required: ["zone_id", "tags"] } },
  { name: "purge_cache_hosts", description: "Purge cache for specific hostnames.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, hosts: { type: "array", items: { type: "string" } } }, required: ["zone_id", "hosts"] } },
  { name: "purge_cache_prefixes", description: "Purge cache by URL prefix.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, prefixes: { type: "array", items: { type: "string" } } }, required: ["zone_id", "prefixes"] } },

  // ── SSL/TLS ──
  { name: "get_ssl_settings", description: "Get SSL/TLS mode for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "update_ssl_settings", description: "Update SSL/TLS mode (off | flexible | full | strict).", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, value: { type: "string" } }, required: ["zone_id", "value"] } },
  { name: "list_certificates", description: "List SSL certificates for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_certificate", description: "Get a specific SSL certificate.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, cert_id: { type: "string" } }, required: ["zone_id", "cert_id"] } },
  { name: "delete_certificate", description: "Delete an SSL certificate.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, cert_id: { type: "string" } }, required: ["zone_id", "cert_id"] } },
  { name: "get_tls_1_3", description: "Get TLS 1.3 setting for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "update_tls_1_3", description: "Enable or disable TLS 1.3 (on | off | zrt).", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, value: { type: "string" } }, required: ["zone_id", "value"] } },

  // ── Page Rules ──
  { name: "list_page_rules", description: "List page rules for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, status: { type: "string" }, order: { type: "string" }, direction: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_page_rule", description: "Get a specific page rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },
  { name: "create_page_rule", description: "Create a page rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, targets: { type: "array" }, actions: { type: "array" }, status: { type: "string" }, priority: { type: "number" } }, required: ["zone_id", "targets", "actions"] } },
  { name: "update_page_rule", description: "Update a page rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" }, targets: { type: "array" }, actions: { type: "array" }, status: { type: "string" }, priority: { type: "number" } }, required: ["zone_id", "rule_id"] } },
  { name: "delete_page_rule", description: "Delete a page rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },

  // ── WAF / Rulesets (New API) ──
  { name: "list_zone_rulesets", description: "List all rulesets for a zone (WAF custom rules, transform rules, config rules, etc.).", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_zone_ruleset", description: "Get a specific ruleset by ID for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, ruleset_id: { type: "string" } }, required: ["zone_id", "ruleset_id"] } },
  { name: "get_zone_ruleset_phase", description: "Get the ruleset for a specific phase (e.g. http_request_firewall_custom, http_request_transform, http_response_headers_transform, http_ratelimit, http_request_cache_settings).", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, phase: { type: "string" } }, required: ["zone_id", "phase"] } },
  { name: "update_zone_ruleset_phase", description: "Replace all rules in a ruleset phase for a zone. Each rule has: action, expression, description, enabled.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, phase: { type: "string" }, rules: { type: "array" } }, required: ["zone_id", "phase", "rules"] } },
  { name: "list_account_rulesets", description: "List all rulesets for an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_account_ruleset_phase", description: "Get the ruleset for a specific phase at account level.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, phase: { type: "string" } }, required: ["account_id", "phase"] } },

  // ── Firewall (Legacy) ──
  { name: "list_firewall_rules", description: "List legacy firewall rules for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, per_page: { type: "number" }, page: { type: "number" } }, required: ["zone_id"] } },
  { name: "get_firewall_rule", description: "Get a specific legacy firewall rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },
  { name: "create_firewall_rule", description: "Create a legacy firewall rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, filter: { type: "object" }, action: { type: "string", description: "block | challenge | js_challenge | managed_challenge | allow | log | bypass" }, description: { type: "string" }, priority: { type: "number" } }, required: ["zone_id", "filter", "action"] } },
  { name: "update_firewall_rule", description: "Update a legacy firewall rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" }, action: { type: "string" }, description: { type: "string" }, paused: { type: "boolean" } }, required: ["zone_id", "rule_id"] } },
  { name: "delete_firewall_rule", description: "Delete a legacy firewall rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },
  { name: "list_ip_access_rules", description: "List IP access rules for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, mode: { type: "string" }, per_page: { type: "number" } }, required: ["zone_id"] } },
  { name: "create_ip_access_rule", description: "Create an IP access rule to block, allow, or challenge an IP/range/country/ASN.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, mode: { type: "string", description: "block | challenge | whitelist | js_challenge" }, configuration: { type: "object", description: "{ target: 'ip'|'ip_range'|'country'|'asn', value: '1.2.3.4' }" }, notes: { type: "string" } }, required: ["zone_id", "mode", "configuration"] } },
  { name: "delete_ip_access_rule", description: "Delete an IP access rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },
  { name: "list_waf_packages", description: "List WAF rule packages for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "list_waf_rules", description: "List WAF rules in a package.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, package_id: { type: "string" }, per_page: { type: "number" } }, required: ["zone_id", "package_id"] } },

  // ── Rate Limiting ──
  { name: "list_rate_limits", description: "List rate limit rules for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, per_page: { type: "number" } }, required: ["zone_id"] } },
  { name: "get_rate_limit", description: "Get a specific rate limit rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },
  { name: "create_rate_limit", description: "Create a rate limit rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, match: { type: "object" }, threshold: { type: "number" }, period: { type: "number" }, action: { type: "object", description: "{ mode: simulate|ban|challenge|js_challenge }" }, description: { type: "string" }, disabled: { type: "boolean" } }, required: ["zone_id", "match", "threshold", "period", "action"] } },
  { name: "delete_rate_limit", description: "Delete a rate limit rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },

  // ── Bot Management ──
  { name: "get_bot_management", description: "Get Bot Management settings for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "update_bot_management", description: "Update Bot Management settings for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, enable_js: { type: "boolean" }, fight_mode: { type: "boolean" }, session_score: { type: "boolean" }, auto_update_model: { type: "boolean" } }, required: ["zone_id"] } },

  // ── Waiting Room ──
  { name: "list_waiting_rooms", description: "List all waiting rooms for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_waiting_room", description: "Get a specific waiting room.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, waiting_room_id: { type: "string" } }, required: ["zone_id", "waiting_room_id"] } },
  { name: "create_waiting_room", description: "Create a waiting room for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, name: { type: "string" }, host: { type: "string" }, path: { type: "string", description: "URL path (default: /)" }, total_active_users: { type: "number" }, new_users_per_minute: { type: "number" }, session_duration: { type: "number" }, enabled: { type: "boolean" } }, required: ["zone_id", "name", "host", "total_active_users", "new_users_per_minute"] } },
  { name: "update_waiting_room", description: "Update a waiting room.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, waiting_room_id: { type: "string" }, name: { type: "string" }, host: { type: "string" }, path: { type: "string" }, total_active_users: { type: "number" }, new_users_per_minute: { type: "number" }, enabled: { type: "boolean" } }, required: ["zone_id", "waiting_room_id"] } },
  { name: "delete_waiting_room", description: "Delete a waiting room.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, waiting_room_id: { type: "string" } }, required: ["zone_id", "waiting_room_id"] } },
  { name: "get_waiting_room_status", description: "Get current status of a waiting room (queued users, active users).", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, waiting_room_id: { type: "string" } }, required: ["zone_id", "waiting_room_id"] } },

  // ── Health Checks ──
  { name: "list_health_checks", description: "List all health checks for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_health_check", description: "Get a specific health check.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, health_check_id: { type: "string" } }, required: ["zone_id", "health_check_id"] } },
  { name: "create_health_check", description: "Create a health check.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, name: { type: "string" }, address: { type: "string" }, type: { type: "string", description: "HTTP | HTTPS | TCP" }, path: { type: "string" }, port: { type: "number" }, interval: { type: "number" }, retries: { type: "number" }, timeout: { type: "number" }, method: { type: "string", description: "GET | HEAD" }, enabled: { type: "boolean" } }, required: ["zone_id", "name", "address"] } },
  { name: "update_health_check", description: "Update a health check.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, health_check_id: { type: "string" }, name: { type: "string" }, address: { type: "string" }, enabled: { type: "boolean" } }, required: ["zone_id", "health_check_id"] } },
  { name: "delete_health_check", description: "Delete a health check.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, health_check_id: { type: "string" } }, required: ["zone_id", "health_check_id"] } },

  // ── Load Balancers ──
  { name: "list_load_balancers", description: "List load balancers for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_load_balancer", description: "Get a specific load balancer.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, lb_id: { type: "string" } }, required: ["zone_id", "lb_id"] } },
  { name: "list_lb_pools", description: "List load balancer origin pools.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_lb_pool", description: "Get a specific load balancer pool.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, pool_id: { type: "string" } }, required: ["account_id", "pool_id"] } },
  { name: "list_lb_monitors", description: "List load balancer health monitors.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },

  // ── Spectrum ──
  { name: "list_spectrum_apps", description: "List Spectrum applications for a zone (TCP/UDP proxying).", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "get_spectrum_app", description: "Get a specific Spectrum application.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, app_id: { type: "string" } }, required: ["zone_id", "app_id"] } },
  { name: "create_spectrum_app", description: "Create a Spectrum application.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, protocol: { type: "string", description: "e.g. tcp/22, udp/1194" }, dns: { type: "object", description: "{ type: 'CNAME', name: 'ssh.example.com' }" }, origin_dns: { type: "object", description: "{ name: 'origin.example.com' }" }, origin_port: { type: "number" }, ip_firewall: { type: "boolean" }, proxy_protocol: { type: "string", description: "off | v1 | v2 | simple" } }, required: ["zone_id", "protocol", "dns", "origin_dns", "origin_port"] } },
  { name: "update_spectrum_app", description: "Update a Spectrum application.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, app_id: { type: "string" }, protocol: { type: "string" }, ip_firewall: { type: "boolean" }, proxy_protocol: { type: "string" } }, required: ["zone_id", "app_id"] } },
  { name: "delete_spectrum_app", description: "Delete a Spectrum application.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, app_id: { type: "string" } }, required: ["zone_id", "app_id"] } },

  // ── Redirects / Bulk Redirects ──
  { name: "list_redirect_rules", description: "List redirect rules/rulesets for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "list_bulk_redirect_lists", description: "List bulk redirect lists in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_bulk_redirect_list", description: "Get a specific bulk redirect list.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, list_id: { type: "string" } }, required: ["account_id", "list_id"] } },
  { name: "list_bulk_redirect_items", description: "List items in a bulk redirect list.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, list_id: { type: "string" } }, required: ["account_id", "list_id"] } },

  // ── Notifications ──
  { name: "list_notification_policies", description: "List all notification/alert policies for an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_notification_policy", description: "Get a specific notification policy.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, policy_id: { type: "string" } }, required: ["account_id", "policy_id"] } },
  { name: "create_notification_policy", description: "Create a notification/alert policy.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" }, alert_type: { type: "string", description: "e.g. dos_attack_l7, health_check_status_notification, real_origin_monitoring, workers_alert" }, enabled: { type: "boolean" }, mechanisms: { type: "object", description: "{ email: [{id: 'email@example.com'}], webhooks: [{id: 'webhook-id'}] }" }, filters: { type: "object" } }, required: ["account_id", "name", "alert_type", "mechanisms"] } },
  { name: "update_notification_policy", description: "Update a notification policy.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, policy_id: { type: "string" }, name: { type: "string" }, enabled: { type: "boolean" }, mechanisms: { type: "object" }, filters: { type: "object" } }, required: ["account_id", "policy_id"] } },
  { name: "delete_notification_policy", description: "Delete a notification policy.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, policy_id: { type: "string" } }, required: ["account_id", "policy_id"] } },
  { name: "list_notification_webhooks", description: "List notification webhook destinations.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "create_notification_webhook", description: "Create a notification webhook destination.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" }, url: { type: "string" }, secret: { type: "string" } }, required: ["account_id", "name", "url"] } },

  // ── Logpush ──
  { name: "list_logpush_jobs", description: "List all Logpush jobs for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "list_account_logpush_jobs", description: "List all Logpush jobs for an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_logpush_job", description: "Get a specific Logpush job.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, job_id: { type: "number" } }, required: ["zone_id", "job_id"] } },
  { name: "create_logpush_job", description: "Create a Logpush job to export logs to S3, R2, Splunk, Sumo Logic, etc.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, name: { type: "string" }, destination_conf: { type: "string", description: "e.g. s3://bucket/path?region=us-east-1 or r2://bucket/path?account-id=abc" }, dataset: { type: "string", description: "http_requests | firewall_events | nel_reports | spectrum_events | dns_logs" }, logpull_options: { type: "string" }, enabled: { type: "boolean" } }, required: ["zone_id", "destination_conf", "dataset"] } },
  { name: "update_logpush_job", description: "Update a Logpush job.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, job_id: { type: "number" }, destination_conf: { type: "string" }, enabled: { type: "boolean" }, logpull_options: { type: "string" } }, required: ["zone_id", "job_id"] } },
  { name: "delete_logpush_job", description: "Delete a Logpush job.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, job_id: { type: "number" } }, required: ["zone_id", "job_id"] } },

  // ── Workers ──
  { name: "list_workers", description: "List all Workers scripts in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_worker", description: "Get a Worker script.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, script_name: { type: "string" } }, required: ["account_id", "script_name"] } },
  { name: "delete_worker", description: "Delete a Worker script.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, script_name: { type: "string" } }, required: ["account_id", "script_name"] } },
  { name: "upload_worker_script", description: "Upload (create or overwrite) a Worker script from source code. Deploys an ES-module Worker. Pass the full JS/TS module source as `script`. Optional `compatibility_date` (default today), `compatibility_flags`, and `bindings` (array of Cloudflare binding objects, e.g. KV/D1/R2/vars). Requires an API token with Workers Scripts:Edit.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, script_name: { type: "string", description: "Worker name (becomes <name>.<subdomain>.workers.dev if enabled)" }, script: { type: "string", description: "Full ES-module Worker source, e.g. export default { async fetch(req, env) { return new Response('hi'); } }" }, main_module: { type: "string", description: "Module filename (default: worker.js)" }, compatibility_date: { type: "string", description: "e.g. 2024-11-01 (default: today)" }, compatibility_flags: { type: "array", items: { type: "string" } }, bindings: { type: "array", description: "Array of binding objects, e.g. [{type:'kv_namespace',name:'MY_KV',namespace_id:'...'}, {type:'plain_text',name:'API_KEY',text:'val'}]" } }, required: ["account_id", "script_name", "script"] } },
  { name: "get_worker_content", description: "Get the source code of a Worker script (returns the raw module text).", inputSchema: { type: "object", properties: { account_id: { type: "string" }, script_name: { type: "string" } }, required: ["account_id", "script_name"] } },
  { name: "enable_worker_subdomain", description: "Enable or disable the workers.dev subdomain route for a Worker (makes it reachable at <name>.<subdomain>.workers.dev).", inputSchema: { type: "object", properties: { account_id: { type: "string" }, script_name: { type: "string" }, enabled: { type: "boolean", description: "true to enable the workers.dev route" } }, required: ["account_id", "script_name", "enabled"] } },
  { name: "list_worker_routes", description: "List Worker routes for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "create_worker_route", description: "Create a Worker route for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, pattern: { type: "string" }, script: { type: "string" } }, required: ["zone_id", "pattern"] } },
  { name: "delete_worker_route", description: "Delete a Worker route.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, route_id: { type: "string" } }, required: ["zone_id", "route_id"] } },
  { name: "list_worker_secrets", description: "List secrets for a Worker script.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, script_name: { type: "string" } }, required: ["account_id", "script_name"] } },
  { name: "put_worker_secret", description: "Set a secret for a Worker script.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, script_name: { type: "string" }, secret_name: { type: "string" }, text: { type: "string" } }, required: ["account_id", "script_name", "secret_name", "text"] } },
  { name: "delete_worker_secret", description: "Delete a secret from a Worker script.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, script_name: { type: "string" }, secret_name: { type: "string" } }, required: ["account_id", "script_name", "secret_name"] } },
  { name: "list_worker_cron_triggers", description: "List cron triggers for a Worker script.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, script_name: { type: "string" } }, required: ["account_id", "script_name"] } },
  { name: "update_worker_cron_triggers", description: "Update cron triggers for a Worker script.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, script_name: { type: "string" }, crons: { type: "array", description: "Array of {cron: '*/5 * * * *'} objects" } }, required: ["account_id", "script_name", "crons"] } },
  { name: "get_worker_subdomain", description: "Get the workers.dev subdomain for an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },

  // ── Durable Objects ──
  { name: "list_durable_object_namespaces", description: "List Durable Object namespaces in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "list_durable_objects", description: "List Durable Objects within a namespace.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, namespace_id: { type: "string" }, limit: { type: "number" }, cursor: { type: "string" } }, required: ["account_id", "namespace_id"] } },

  // ── KV Storage ──
  { name: "list_kv_namespaces", description: "List all KV namespaces in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, per_page: { type: "number" } }, required: ["account_id"] } },
  { name: "create_kv_namespace", description: "Create a KV namespace.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, title: { type: "string" } }, required: ["account_id", "title"] } },
  { name: "delete_kv_namespace", description: "Delete a KV namespace.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, namespace_id: { type: "string" } }, required: ["account_id", "namespace_id"] } },
  { name: "list_kv_keys", description: "List keys in a KV namespace.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, namespace_id: { type: "string" }, limit: { type: "number" }, prefix: { type: "string" }, cursor: { type: "string" } }, required: ["account_id", "namespace_id"] } },
  { name: "get_kv_value", description: "Get the value of a KV key.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, namespace_id: { type: "string" }, key: { type: "string" } }, required: ["account_id", "namespace_id", "key"] } },
  { name: "put_kv_value", description: "Set a KV key-value pair.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, namespace_id: { type: "string" }, key: { type: "string" }, value: { type: "string" }, expiration_ttl: { type: "number" } }, required: ["account_id", "namespace_id", "key", "value"] } },
  { name: "delete_kv_key", description: "Delete a KV key.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, namespace_id: { type: "string" }, key: { type: "string" } }, required: ["account_id", "namespace_id", "key"] } },

  // ── Queues ──
  { name: "list_queues", description: "List all Cloudflare Queues in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_queue", description: "Get details of a specific Queue.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, queue_id: { type: "string" } }, required: ["account_id", "queue_id"] } },
  { name: "create_queue", description: "Create a new Queue.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, queue_name: { type: "string" } }, required: ["account_id", "queue_name"] } },
  { name: "delete_queue", description: "Delete a Queue.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, queue_id: { type: "string" } }, required: ["account_id", "queue_id"] } },
  { name: "send_queue_messages", description: "Send messages to a Queue.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, queue_id: { type: "string" }, messages: { type: "array", description: "Array of {body: any} message objects" } }, required: ["account_id", "queue_id", "messages"] } },
  { name: "pull_queue_messages", description: "Pull messages from a Queue for consumption.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, queue_id: { type: "string" }, batch_size: { type: "number", description: "Max messages to pull (default 10, max 100)" }, visibility_timeout_ms: { type: "number" } }, required: ["account_id", "queue_id"] } },
  { name: "ack_queue_messages", description: "Acknowledge or retry pulled Queue messages.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, queue_id: { type: "string" }, acks: { type: "array", description: "Array of {lease_id} to acknowledge" }, retries: { type: "array", description: "Array of {lease_id, delay_seconds} to retry" } }, required: ["account_id", "queue_id"] } },

  // ── R2 Storage ──
  { name: "list_r2_buckets", description: "List all R2 buckets in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_r2_bucket", description: "Get details of an R2 bucket.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" } }, required: ["account_id", "name"] } },
  { name: "create_r2_bucket", description: "Create an R2 bucket.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" }, location_hint: { type: "string", description: "WNAM | ENAM | WEUR | EEUR | APAC | OC" } }, required: ["account_id", "name"] } },
  { name: "delete_r2_bucket", description: "Delete an R2 bucket.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" } }, required: ["account_id", "name"] } },

  // ── D1 Databases ──
  { name: "list_d1_databases", description: "List all D1 databases in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, per_page: { type: "number" } }, required: ["account_id"] } },
  { name: "get_d1_database", description: "Get details of a D1 database.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, database_id: { type: "string" } }, required: ["account_id", "database_id"] } },
  { name: "create_d1_database", description: "Create a D1 database.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" } }, required: ["account_id", "name"] } },
  { name: "delete_d1_database", description: "Delete a D1 database.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, database_id: { type: "string" } }, required: ["account_id", "database_id"] } },
  { name: "query_d1_database", description: "Execute a SQL query on a D1 database.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, database_id: { type: "string" }, sql: { type: "string" }, params: { type: "array" } }, required: ["account_id", "database_id", "sql"] } },

  // ── Hyperdrive ──
  { name: "list_hyperdrive_configs", description: "List all Hyperdrive configurations in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_hyperdrive_config", description: "Get a specific Hyperdrive configuration.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, config_id: { type: "string" } }, required: ["account_id", "config_id"] } },
  { name: "create_hyperdrive_config", description: "Create a Hyperdrive config to accelerate a database.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" }, origin: { type: "object", description: "{ database, host, port, scheme: 'postgres', user, password }" }, caching: { type: "object", description: "{ disabled: false, max_age: 60, stale_while_revalidate: 15 }" } }, required: ["account_id", "name", "origin"] } },
  { name: "update_hyperdrive_config", description: "Update a Hyperdrive configuration.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, config_id: { type: "string" }, name: { type: "string" }, origin: { type: "object" }, caching: { type: "object" } }, required: ["account_id", "config_id"] } },
  { name: "delete_hyperdrive_config", description: "Delete a Hyperdrive configuration.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, config_id: { type: "string" } }, required: ["account_id", "config_id"] } },

  // ── Vectorize ──
  { name: "list_vectorize_indexes", description: "List all Vectorize indexes in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_vectorize_index", description: "Get details of a Vectorize index.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, index_name: { type: "string" } }, required: ["account_id", "index_name"] } },
  { name: "create_vectorize_index", description: "Create a Vectorize index.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" }, config: { type: "object", description: "{ dimensions: 1536, metric: 'cosine'|'euclidean'|'dot-product' }" } }, required: ["account_id", "name", "config"] } },
  { name: "delete_vectorize_index", description: "Delete a Vectorize index.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, index_name: { type: "string" } }, required: ["account_id", "index_name"] } },
  { name: "query_vectorize_index", description: "Query a Vectorize index with a vector.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, index_name: { type: "string" }, vector: { type: "array", items: { type: "number" } }, top_k: { type: "number", description: "Number of results (default 5)" }, filter: { type: "object" }, return_values: { type: "boolean" }, return_metadata: { type: "string", description: "none | indexed | all" } }, required: ["account_id", "index_name", "vector"] } },
  { name: "upsert_vectorize_vectors", description: "Insert or update vectors in a Vectorize index.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, index_name: { type: "string" }, vectors: { type: "array", description: "Array of {id, values, metadata} objects" } }, required: ["account_id", "index_name", "vectors"] } },
  { name: "delete_vectorize_vectors", description: "Delete vectors from a Vectorize index by ID.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, index_name: { type: "string" }, ids: { type: "array", items: { type: "string" } } }, required: ["account_id", "index_name", "ids"] } },

  // ── AI Gateway ──
  { name: "list_ai_gateways", description: "List AI Gateways for an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_ai_gateway", description: "Get a specific AI Gateway.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, gateway_id: { type: "string" } }, required: ["account_id", "gateway_id"] } },
  { name: "create_ai_gateway", description: "Create an AI Gateway.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" }, slug: { type: "string" }, collect_logs: { type: "boolean" }, cache_ttl: { type: "number" } }, required: ["account_id", "name", "slug"] } },
  { name: "update_ai_gateway", description: "Update an AI Gateway.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, gateway_id: { type: "string" }, name: { type: "string" }, collect_logs: { type: "boolean" }, cache_ttl: { type: "number" } }, required: ["account_id", "gateway_id"] } },
  { name: "delete_ai_gateway", description: "Delete an AI Gateway.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, gateway_id: { type: "string" } }, required: ["account_id", "gateway_id"] } },
  { name: "list_ai_gateway_logs", description: "List logs for an AI Gateway.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, gateway_id: { type: "string" }, per_page: { type: "number" }, page: { type: "number" }, cached: { type: "boolean" }, provider: { type: "string" } }, required: ["account_id", "gateway_id"] } },

  // ── Images ──
  { name: "list_images", description: "List images in Cloudflare Images.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, page: { type: "number" }, per_page: { type: "number" } }, required: ["account_id"] } },
  { name: "get_image", description: "Get metadata for a specific image.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, image_id: { type: "string" } }, required: ["account_id", "image_id"] } },
  { name: "update_image", description: "Update image metadata (requireSignedURLs, metadata object).", inputSchema: { type: "object", properties: { account_id: { type: "string" }, image_id: { type: "string" }, require_signed_urls: { type: "boolean" }, metadata: { type: "object" } }, required: ["account_id", "image_id"] } },
  { name: "delete_image", description: "Delete an image from Cloudflare Images.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, image_id: { type: "string" } }, required: ["account_id", "image_id"] } },
  { name: "get_images_usage", description: "Get Cloudflare Images usage statistics.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "list_image_variants", description: "List image variants/transformations.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "create_image_variant", description: "Create an image variant (resize/crop configuration).", inputSchema: { type: "object", properties: { account_id: { type: "string" }, variant_id: { type: "string" }, options: { type: "object", description: "{ fit: 'scale-down'|'contain'|'cover'|'crop'|'pad', width: number, height: number, metadata: 'keep'|'copyright'|'none' }" } }, required: ["account_id", "variant_id", "options"] } },
  { name: "delete_image_variant", description: "Delete an image variant.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, variant_id: { type: "string" } }, required: ["account_id", "variant_id"] } },

  // ── Stream ──
  { name: "list_stream_videos", description: "List videos in Cloudflare Stream.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, per_page: { type: "number" }, search: { type: "string" } }, required: ["account_id"] } },
  { name: "get_stream_video", description: "Get details of a specific Stream video.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, video_id: { type: "string" } }, required: ["account_id", "video_id"] } },
  { name: "delete_stream_video", description: "Delete a Stream video.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, video_id: { type: "string" } }, required: ["account_id", "video_id"] } },
  { name: "upload_stream_video_url", description: "Upload a video to Cloudflare Stream from a URL.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, url: { type: "string", description: "Public URL of the video to upload" }, meta: { type: "object", description: "Optional metadata e.g. { name: 'My Video' }" } }, required: ["account_id", "url"] } },
  { name: "list_stream_live_inputs", description: "List live inputs for Cloudflare Stream.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "create_stream_live_input", description: "Create a live input for Cloudflare Stream.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, meta: { type: "object", description: "{ name: 'My Live Stream' }" }, recording: { type: "object", description: "{ mode: 'automatic' | 'off' }" } }, required: ["account_id"] } },

  // ── Pages ──
  { name: "list_pages_projects", description: "List all Cloudflare Pages projects in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_pages_project", description: "Get details of a Pages project.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" } }, required: ["account_id", "project_name"] } },
  { name: "create_pages_project", description: "Create a new Cloudflare Pages project. Optionally connect a GitHub repo via source; omit source for a Direct Upload project (then use deploy_pages_files to publish).", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string", description: "Project name (becomes <name>.pages.dev)" }, production_branch: { type: "string", description: "Default: main" }, build_config: { type: "object", description: "{ build_command: 'npm run build', destination_dir: 'dist', root_dir: '' }" }, source: { type: "object", description: "Git integration: { type: 'github', config: { owner, repo_name, production_branch: 'main', deployments_enabled: true } }" }, deployment_configs: { type: "object", description: "{ production: { env_vars: { KEY: { value: 'x' } }, compatibility_date: '2024-01-01' }, preview: {...} }" } }, required: ["account_id", "name"] } },
  { name: "update_pages_project", description: "Update a Pages project: build config, git source, env vars (deployment_configs), production branch.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" }, production_branch: { type: "string" }, build_config: { type: "object" }, source: { type: "object" }, deployment_configs: { type: "object" } }, required: ["account_id", "project_name"] } },
  { name: "delete_pages_project", description: "Delete a Pages project.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" } }, required: ["account_id", "project_name"] } },
  { name: "list_pages_deployments", description: "List deployments for a Pages project.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" }, per_page: { type: "number" } }, required: ["account_id", "project_name"] } },
  { name: "get_pages_deployment", description: "Get details of a specific Pages deployment.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" }, deployment_id: { type: "string" } }, required: ["account_id", "project_name", "deployment_id"] } },
  { name: "create_pages_deployment", description: "Trigger a new deployment for a git-connected Pages project (builds and deploys the latest commit on the branch).", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" }, branch: { type: "string", description: "Branch to deploy (omit for production branch)" } }, required: ["account_id", "project_name"] } },
  { name: "deploy_pages_files", description: "Direct Upload: publish a new Pages deployment from inline files, no git needed. files is a map of '/path' to content: a plain UTF-8 string, or { content, base64: true, content_type } for binary files. Handles the full Cloudflare upload flow (hashing, missing-asset check, asset upload, manifest deployment) server-side. Returns the deployment with its live URL.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" }, files: { type: "object", description: "e.g. { '/index.html': '<html>...</html>', '/logo.png': { content: '<base64>', base64: true, content_type: 'image/png' } }" }, branch: { type: "string", description: "Deploy as a preview on this branch (omit for production)" } }, required: ["account_id", "project_name", "files"] } },
  { name: "purge_pages_build_cache", description: "Purge the build cache for a Pages project.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" } }, required: ["account_id", "project_name"] } },
  { name: "retry_pages_deployment", description: "Retry a failed Pages deployment.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" }, deployment_id: { type: "string" } }, required: ["account_id", "project_name", "deployment_id"] } },
  { name: "rollback_pages_deployment", description: "Rollback to a previous Pages deployment.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" }, deployment_id: { type: "string" } }, required: ["account_id", "project_name", "deployment_id"] } },
  { name: "list_pages_domains", description: "List custom domains for a Pages project.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" } }, required: ["account_id", "project_name"] } },
  { name: "add_pages_domain", description: "Add a custom domain to a Pages project.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" }, domain: { type: "string" } }, required: ["account_id", "project_name", "domain"] } },
  { name: "delete_pages_domain", description: "Remove a custom domain from a Pages project.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, project_name: { type: "string" }, domain: { type: "string" } }, required: ["account_id", "project_name", "domain"] } },

  // ── Registrar ──
  { name: "list_registrar_domains", description: "List domains registered with Cloudflare Registrar.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_registrar_domain", description: "Get details of a Cloudflare Registrar domain.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, domain_name: { type: "string" } }, required: ["account_id", "domain_name"] } },
  { name: "update_registrar_domain", description: "Update Registrar domain settings (auto_renew, locked, privacy).", inputSchema: { type: "object", properties: { account_id: { type: "string" }, domain_name: { type: "string" }, auto_renew: { type: "boolean" }, locked: { type: "boolean" }, privacy: { type: "boolean" } }, required: ["account_id", "domain_name"] } },

  // ── Zero Trust / Access ──
  { name: "list_access_applications", description: "List Zero Trust Access applications.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_access_application", description: "Get a Zero Trust Access application.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, app_id: { type: "string" } }, required: ["account_id", "app_id"] } },
  { name: "list_access_policies", description: "List policies for an Access application.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, app_id: { type: "string" } }, required: ["account_id", "app_id"] } },
  { name: "list_access_groups", description: "List Zero Trust Access groups.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "list_access_service_tokens", description: "List Access service tokens.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "create_access_service_token", description: "Create an Access service token.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" } }, required: ["account_id", "name"] } },
  { name: "rotate_access_service_token", description: "Rotate an Access service token.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, token_id: { type: "string" } }, required: ["account_id", "token_id"] } },
  { name: "delete_access_service_token", description: "Delete an Access service token.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, token_id: { type: "string" } }, required: ["account_id", "token_id"] } },

  // ── Tunnels ──
  { name: "list_tunnels", description: "List Cloudflare Tunnels in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" }, is_deleted: { type: "boolean" } }, required: ["account_id"] } },
  { name: "get_tunnel", description: "Get details of a specific Cloudflare Tunnel.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, tunnel_id: { type: "string" } }, required: ["account_id", "tunnel_id"] } },
  { name: "create_tunnel", description: "Create a Cloudflare Tunnel.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, name: { type: "string" }, tunnel_secret: { type: "string", description: "Base64 encoded 32-byte secret" } }, required: ["account_id", "name", "tunnel_secret"] } },
  { name: "delete_tunnel", description: "Delete a Cloudflare Tunnel.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, tunnel_id: { type: "string" } }, required: ["account_id", "tunnel_id"] } },
  { name: "get_tunnel_token", description: "Get the token for a tunnel (used to run cloudflared).", inputSchema: { type: "object", properties: { account_id: { type: "string" }, tunnel_id: { type: "string" } }, required: ["account_id", "tunnel_id"] } },
  { name: "get_tunnel_connections", description: "Get active connections for a tunnel.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, tunnel_id: { type: "string" } }, required: ["account_id", "tunnel_id"] } },
  { name: "list_tunnel_routes", description: "List tunnel routes (private network CIDRs) in an account.", inputSchema: { type: "object", properties: { account_id: { type: "string" } }, required: ["account_id"] } },
  { name: "get_tunnel_config", description: "Get ingress config for a tunnel.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, tunnel_id: { type: "string" } }, required: ["account_id", "tunnel_id"] } },
  { name: "update_tunnel_config", description: "Update ingress config for a tunnel.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, tunnel_id: { type: "string" }, config: { type: "object", description: "Tunnel config object with ingress rules array" } }, required: ["account_id", "tunnel_id", "config"] } },

  // ── Email Routing ──
  { name: "get_email_routing_settings", description: "Get Email Routing settings for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "enable_email_routing", description: "Enable Email Routing for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "disable_email_routing", description: "Disable Email Routing for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "list_email_routing_rules", description: "List all Email Routing rules for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, per_page: { type: "number" }, enabled: { type: "boolean" } }, required: ["zone_id"] } },
  { name: "get_email_routing_rule", description: "Get a specific Email Routing rule by ID.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },
  { name: "create_email_routing_rule", description: "Create an Email Routing rule. Matchers: [{type:'literal',field:'to',value:'hello@example.com'}]. Actions: [{type:'forward',value:['dest@example.com']}] or [{type:'drop'}].", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, name: { type: "string" }, enabled: { type: "boolean" }, matchers: { type: "array" }, actions: { type: "array" } }, required: ["zone_id", "matchers", "actions"] } },
  { name: "update_email_routing_rule", description: "Update an existing Email Routing rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" }, name: { type: "string" }, enabled: { type: "boolean" }, matchers: { type: "array" }, actions: { type: "array" } }, required: ["zone_id", "rule_id"] } },
  { name: "delete_email_routing_rule", description: "Delete an Email Routing rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, rule_id: { type: "string" } }, required: ["zone_id", "rule_id"] } },
  { name: "get_catch_all_rule", description: "Get the catch-all Email Routing rule for a zone.", inputSchema: { type: "object", properties: { zone_id: { type: "string" } }, required: ["zone_id"] } },
  { name: "update_catch_all_rule", description: "Update the catch-all Email Routing rule.", inputSchema: { type: "object", properties: { zone_id: { type: "string" }, enabled: { type: "boolean" }, name: { type: "string" }, matchers: { type: "array" }, actions: { type: "array" } }, required: ["zone_id", "actions"] } },
  { name: "list_email_destination_addresses", description: "List verified destination email addresses for Email Routing.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, per_page: { type: "number" }, verified: { type: "boolean" } }, required: ["account_id"] } },
  { name: "create_email_destination_address", description: "Add a new destination email address for Email Routing (sends verification email).", inputSchema: { type: "object", properties: { account_id: { type: "string" }, email: { type: "string" } }, required: ["account_id", "email"] } },
  { name: "get_email_destination_address", description: "Get details of a specific Email Routing destination address.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, destination_id: { type: "string" } }, required: ["account_id", "destination_id"] } },
  { name: "delete_email_destination_address", description: "Delete a destination email address from Email Routing.", inputSchema: { type: "object", properties: { account_id: { type: "string" }, destination_id: { type: "string" } }, required: ["account_id", "destination_id"] } },
];

const PAGES_MIME: Record<string, string> = { html: "text/html", htm: "text/html", css: "text/css", js: "application/javascript", mjs: "application/javascript", json: "application/json", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", svg: "image/svg+xml", webp: "image/webp", avif: "image/avif", ico: "image/x-icon", txt: "text/plain", md: "text/markdown", xml: "application/xml", pdf: "application/pdf", woff: "font/woff", woff2: "font/woff2", ttf: "font/ttf", otf: "font/otf", eot: "application/vnd.ms-fontobject", map: "application/json", webmanifest: "application/manifest+json", mp4: "video/mp4", webm: "video/webm", mp3: "audio/mpeg", wasm: "application/wasm" };

async function executeTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  const a = args;
  switch (name) {
    // Account
    case "list_accounts": return await cfRequest(`/accounts?page=${a.page||1}&per_page=${a.per_page||50}`);
    case "get_account": return await cfRequest(`/accounts/${a.account_id}`);
    case "get_account_settings": return await cfRequest(`/accounts/${a.account_id}/settings`);
    case "list_account_members": return await cfRequest(`/accounts/${a.account_id}/members?per_page=50`);
    // Users & Tokens
    case "get_user": return await cfRequest("/user");
    case "list_api_tokens": return await cfRequest("/user/tokens");
    case "get_api_token": return await cfRequest(`/user/tokens/${a.token_id}`);
    case "verify_api_token": return await cfRequest("/user/tokens/verify");
    case "list_token_permission_groups": return await bootstrapRequest("/user/tokens/permission_groups");
    case "create_api_token": {
      const groups = await bootstrapRequest("/user/tokens/permission_groups") as Array<{ id: string; name: string; scopes?: string[] }>;
      const pick = (scope: string) => new Map(groups.filter(g => (g.scopes || [])[0] === scope).map(g => [g.name, g.id]));
      const acctMap = pick("com.cloudflare.api.account");
      const zoneMap = pick("com.cloudflare.api.account.zone");
      const wantA = (a.account_permissions as string[] | undefined) || [];
      const wantZ = (a.zone_permissions as string[] | undefined) || [];
      const missA = wantA.filter(n => !acctMap.has(n));
      const missZ = wantZ.filter(n => !zoneMap.has(n));
      if (missA.length || missZ.length) throw new Error(`Unknown permission group names. account: ${JSON.stringify(missA)} zone: ${JSON.stringify(missZ)}. Call list_token_permission_groups for exact names.`);
      if (!wantA.length && !wantZ.length) throw new Error("Provide account_permissions and/or zone_permissions");
      let accountId = a.account_id as string | undefined;
      if (!accountId && wantA.length) {
        const accounts = await bootstrapRequest("/accounts?per_page=5") as Array<{ id: string }>;
        accountId = accounts[0]?.id;
        if (!accountId) throw new Error("Could not resolve account_id; pass it explicitly");
      }
      const policies: unknown[] = [];
      if (wantA.length) policies.push({ effect: "allow", resources: { [`com.cloudflare.api.account.${accountId}`]: "*" }, permission_groups: wantA.map(n => ({ id: acctMap.get(n), name: n })) });
      if (wantZ.length) policies.push({ effect: "allow", resources: { "com.cloudflare.api.account.zone.*": "*" }, permission_groups: wantZ.map(n => ({ id: zoneMap.get(n), name: n })) });
      if (a.dry_run) return { dry_run: true, name: a.name, policies };
      return await bootstrapRequest("/user/tokens", "POST", { name: a.name, policies, condition: {} });
    }
    // Zones
    case "list_zones": {
      let ep = `/zones?page=${a.page||1}&per_page=${a.per_page||50}`;
      if (a.name) ep += `&name=${encodeURIComponent(a.name as string)}`;
      if (a.status) ep += `&status=${a.status}`;
      return await cfRequest(ep);
    }
    case "get_zone": return await cfRequest(`/zones/${a.zone_id}`);
    case "get_zone_by_name": {
      const r = await cfRequest(`/zones?name=${encodeURIComponent(a.name as string)}`) as unknown[];
      if (!r?.length) throw new Error(`Zone not found: ${a.name}`);
      return r[0];
    }
    case "create_zone": return await cfRequest("/zones", "POST", { name: a.name, account: { id: a.account_id }, jump_start: a.jump_start??true, type: a.type||"full" });
    case "delete_zone": return await cfRequest(`/zones/${a.zone_id}`, "DELETE");
    case "pause_zone": return await cfRequest(`/zones/${a.zone_id}`, "PATCH", { paused: true });
    case "unpause_zone": return await cfRequest(`/zones/${a.zone_id}`, "PATCH", { paused: false });
    case "get_zone_analytics": return await cfRequest(`/zones/${a.zone_id}/analytics/dashboard?since=${a.since||"-10080"}&until=${a.until||"0"}`);
    case "get_zone_analytics_by_time": return await cfRequest(`/zones/${a.zone_id}/analytics/dashboard?since=${a.since||"-1440"}&until=${a.until||"0"}&time_delta=${a.time_delta||"hour"}`);
    // Zone Settings
    case "get_zone_settings": return await cfRequest(`/zones/${a.zone_id}/settings`);
    case "get_zone_setting": return await cfRequest(`/zones/${a.zone_id}/settings/${a.setting}`);
    case "update_zone_setting": return await cfRequest(`/zones/${a.zone_id}/settings/${a.setting}`, "PATCH", { value: a.value });
    // DNS
    case "list_dns_records": {
      let ep = `/zones/${a.zone_id}/dns_records?per_page=${a.per_page||100}&page=${a.page||1}`;
      if (a.type) ep += `&type=${a.type}`;
      if (a.name) ep += `&name=${encodeURIComponent(a.name as string)}`;
      if (a.content) ep += `&content=${encodeURIComponent(a.content as string)}`;
      return await cfRequest(ep);
    }
    case "get_dns_record": return await cfRequest(`/zones/${a.zone_id}/dns_records/${a.record_id}`);
    case "create_dns_record": {
      const b: Record<string, unknown> = { type: a.type, name: a.name, content: a.content, ttl: a.ttl||1, proxied: a.proxied??false };
      if (a.priority !== undefined) b.priority = a.priority;
      if (a.comment) b.comment = a.comment;
      return await cfRequest(`/zones/${a.zone_id}/dns_records`, "POST", b);
    }
    case "update_dns_record": {
      const b: Record<string, unknown> = {};
      ["type","name","content","ttl","proxied","comment"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/dns_records/${a.record_id}`, "PATCH", b);
    }
    case "delete_dns_record": return await cfRequest(`/zones/${a.zone_id}/dns_records/${a.record_id}`, "DELETE");
    case "export_dns_records": {
      const res = await fetch(`${CF_BASE_URL}/zones/${a.zone_id}/dns_records/export`, { headers: getAuthHeaders() });
      return await res.text();
    }
    case "get_dns_analytics": {
      const dims = (a.dimensions as string[]||["queryName"]).join(",");
      const mets = (a.metrics as string[]||["queryCount"]).join(",");
      return await cfRequest(`/zones/${a.zone_id}/dns_analytics/report?dimensions=${dims}&metrics=${mets}&since=${a.since||"-1440"}&until=${a.until||"0"}&limit=${a.limit||100}`);
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
      let ep = `/zones/${a.zone_id}/pagerules?order=${a.order||"priority"}&direction=${a.direction||"asc"}`;
      if (a.status) ep += `&status=${a.status}`;
      return await cfRequest(ep);
    }
    case "get_page_rule": return await cfRequest(`/zones/${a.zone_id}/pagerules/${a.rule_id}`);
    case "create_page_rule": return await cfRequest(`/zones/${a.zone_id}/pagerules`, "POST", { targets: a.targets, actions: a.actions, status: a.status||"active", priority: a.priority||1 });
    case "update_page_rule": {
      const b: Record<string, unknown> = {};
      ["targets","actions","status","priority"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/pagerules/${a.rule_id}`, "PATCH", b);
    }
    case "delete_page_rule": return await cfRequest(`/zones/${a.zone_id}/pagerules/${a.rule_id}`, "DELETE");
    // WAF Rulesets
    case "list_zone_rulesets": return await cfRequest(`/zones/${a.zone_id}/rulesets`);
    case "get_zone_ruleset": return await cfRequest(`/zones/${a.zone_id}/rulesets/${a.ruleset_id}`);
    case "get_zone_ruleset_phase": return await cfRequest(`/zones/${a.zone_id}/rulesets/phases/${a.phase}/entrypoint`);
    case "update_zone_ruleset_phase": return await cfRequest(`/zones/${a.zone_id}/rulesets/phases/${a.phase}/entrypoint`, "PUT", { rules: a.rules });
    case "list_account_rulesets": return await cfRequest(`/accounts/${a.account_id}/rulesets`);
    case "get_account_ruleset_phase": return await cfRequest(`/accounts/${a.account_id}/rulesets/phases/${a.phase}/entrypoint`);
    // Firewall (legacy)
    case "list_firewall_rules": return await cfRequest(`/zones/${a.zone_id}/firewall/rules?page=${a.page||1}&per_page=${a.per_page||50}`);
    case "get_firewall_rule": return await cfRequest(`/zones/${a.zone_id}/firewall/rules/${a.rule_id}`);
    case "create_firewall_rule": return await cfRequest(`/zones/${a.zone_id}/firewall/rules`, "POST", [{ filter: a.filter, action: a.action, description: a.description||"", priority: a.priority }]);
    case "update_firewall_rule": {
      const b: Record<string, unknown> = { id: a.rule_id };
      ["action","description","paused"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/firewall/rules/${a.rule_id}`, "PATCH", b);
    }
    case "delete_firewall_rule": return await cfRequest(`/zones/${a.zone_id}/firewall/rules/${a.rule_id}`, "DELETE");
    case "list_ip_access_rules": {
      let ep = `/zones/${a.zone_id}/firewall/access_rules/rules?per_page=${a.per_page||50}`;
      if (a.mode) ep += `&mode=${a.mode}`;
      return await cfRequest(ep);
    }
    case "create_ip_access_rule": return await cfRequest(`/zones/${a.zone_id}/firewall/access_rules/rules`, "POST", { mode: a.mode, configuration: a.configuration, notes: a.notes||"" });
    case "delete_ip_access_rule": return await cfRequest(`/zones/${a.zone_id}/firewall/access_rules/rules/${a.rule_id}`, "DELETE");
    case "list_waf_packages": return await cfRequest(`/zones/${a.zone_id}/firewall/waf/packages`);
    case "list_waf_rules": return await cfRequest(`/zones/${a.zone_id}/firewall/waf/packages/${a.package_id}/rules?per_page=${a.per_page||100}`);
    // Rate Limiting
    case "list_rate_limits": return await cfRequest(`/zones/${a.zone_id}/rate_limits?per_page=${a.per_page||50}`);
    case "get_rate_limit": return await cfRequest(`/zones/${a.zone_id}/rate_limits/${a.rule_id}`);
    case "create_rate_limit": return await cfRequest(`/zones/${a.zone_id}/rate_limits`, "POST", { match: a.match, threshold: a.threshold, period: a.period, action: a.action, description: a.description||"", disabled: a.disabled||false });
    case "delete_rate_limit": return await cfRequest(`/zones/${a.zone_id}/rate_limits/${a.rule_id}`, "DELETE");
    // Bot Management
    case "get_bot_management": return await cfRequest(`/zones/${a.zone_id}/bot_management`);
    case "update_bot_management": {
      const b: Record<string, unknown> = {};
      ["enable_js","fight_mode","session_score","auto_update_model"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/bot_management`, "PUT", b);
    }
    // Waiting Room
    case "list_waiting_rooms": return await cfRequest(`/zones/${a.zone_id}/waiting_rooms`);
    case "get_waiting_room": return await cfRequest(`/zones/${a.zone_id}/waiting_rooms/${a.waiting_room_id}`);
    case "create_waiting_room": {
      const b: Record<string, unknown> = { name: a.name, host: a.host, total_active_users: a.total_active_users, new_users_per_minute: a.new_users_per_minute };
      ["path","session_duration","enabled"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/waiting_rooms`, "POST", b);
    }
    case "update_waiting_room": {
      const b: Record<string, unknown> = {};
      ["name","host","path","total_active_users","new_users_per_minute","session_duration","enabled"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/waiting_rooms/${a.waiting_room_id}`, "PATCH", b);
    }
    case "delete_waiting_room": return await cfRequest(`/zones/${a.zone_id}/waiting_rooms/${a.waiting_room_id}`, "DELETE");
    case "get_waiting_room_status": return await cfRequest(`/zones/${a.zone_id}/waiting_rooms/${a.waiting_room_id}/status`);
    // Health Checks
    case "list_health_checks": return await cfRequest(`/zones/${a.zone_id}/healthchecks`);
    case "get_health_check": return await cfRequest(`/zones/${a.zone_id}/healthchecks/${a.health_check_id}`);
    case "create_health_check": {
      const b: Record<string, unknown> = { name: a.name, address: a.address, type: a.type||"HTTPS", enabled: a.enabled??true };
      ["path","port","interval","retries","timeout","method"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/healthchecks`, "POST", b);
    }
    case "update_health_check": {
      const b: Record<string, unknown> = {};
      ["name","address","type","enabled","path","port","interval","retries","timeout","method"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/healthchecks/${a.health_check_id}`, "PATCH", b);
    }
    case "delete_health_check": return await cfRequest(`/zones/${a.zone_id}/healthchecks/${a.health_check_id}`, "DELETE");
    // Load Balancers
    case "list_load_balancers": return await cfRequest(`/zones/${a.zone_id}/load_balancers`);
    case "get_load_balancer": return await cfRequest(`/zones/${a.zone_id}/load_balancers/${a.lb_id}`);
    case "list_lb_pools": return await cfRequest(`/accounts/${a.account_id}/load_balancers/pools`);
    case "get_lb_pool": return await cfRequest(`/accounts/${a.account_id}/load_balancers/pools/${a.pool_id}`);
    case "list_lb_monitors": return await cfRequest(`/accounts/${a.account_id}/load_balancers/monitors`);
    // Spectrum
    case "list_spectrum_apps": return await cfRequest(`/zones/${a.zone_id}/spectrum/apps`);
    case "get_spectrum_app": return await cfRequest(`/zones/${a.zone_id}/spectrum/apps/${a.app_id}`);
    case "create_spectrum_app": return await cfRequest(`/zones/${a.zone_id}/spectrum/apps`, "POST", { protocol: a.protocol, dns: a.dns, origin_dns: a.origin_dns, origin_port: a.origin_port, ip_firewall: a.ip_firewall??true, proxy_protocol: a.proxy_protocol||"off" });
    case "update_spectrum_app": {
      const b: Record<string, unknown> = {};
      ["protocol","dns","origin_dns","origin_port","ip_firewall","proxy_protocol"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/spectrum/apps/${a.app_id}`, "PUT", b);
    }
    case "delete_spectrum_app": return await cfRequest(`/zones/${a.zone_id}/spectrum/apps/${a.app_id}`, "DELETE");
    // Redirects
    case "list_redirect_rules": return await cfRequest(`/zones/${a.zone_id}/rulesets`);
    case "list_bulk_redirect_lists": return await cfRequest(`/accounts/${a.account_id}/rules/lists?per_page=100`);
    case "get_bulk_redirect_list": return await cfRequest(`/accounts/${a.account_id}/rules/lists/${a.list_id}`);
    case "list_bulk_redirect_items": return await cfRequest(`/accounts/${a.account_id}/rules/lists/${a.list_id}/items`);
    // Notifications
    case "list_notification_policies": return await cfRequest(`/accounts/${a.account_id}/alerting/v3/policies`);
    case "get_notification_policy": return await cfRequest(`/accounts/${a.account_id}/alerting/v3/policies/${a.policy_id}`);
    case "create_notification_policy": return await cfRequest(`/accounts/${a.account_id}/alerting/v3/policies`, "POST", { name: a.name, alert_type: a.alert_type, enabled: a.enabled??true, mechanisms: a.mechanisms, filters: a.filters||{} });
    case "update_notification_policy": {
      const b: Record<string, unknown> = {};
      ["name","enabled","mechanisms","filters"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/accounts/${a.account_id}/alerting/v3/policies/${a.policy_id}`, "PUT", b);
    }
    case "delete_notification_policy": return await cfRequest(`/accounts/${a.account_id}/alerting/v3/policies/${a.policy_id}`, "DELETE");
    case "list_notification_webhooks": return await cfRequest(`/accounts/${a.account_id}/alerting/v3/destinations/webhooks`);
    case "create_notification_webhook": return await cfRequest(`/accounts/${a.account_id}/alerting/v3/destinations/webhooks`, "POST", { name: a.name, url: a.url, ...(a.secret ? { secret: a.secret } : {}) });
    // Logpush
    case "list_logpush_jobs": return await cfRequest(`/zones/${a.zone_id}/logpush/jobs`);
    case "list_account_logpush_jobs": return await cfRequest(`/accounts/${a.account_id}/logpush/jobs`);
    case "get_logpush_job": return await cfRequest(`/zones/${a.zone_id}/logpush/jobs/${a.job_id}`);
    case "create_logpush_job": return await cfRequest(`/zones/${a.zone_id}/logpush/jobs`, "POST", { name: a.name, destination_conf: a.destination_conf, dataset: a.dataset, logpull_options: a.logpull_options||"", enabled: a.enabled??true });
    case "update_logpush_job": {
      const b: Record<string, unknown> = {};
      ["destination_conf","enabled","logpull_options"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/logpush/jobs/${a.job_id}`, "PUT", b);
    }
    case "delete_logpush_job": return await cfRequest(`/zones/${a.zone_id}/logpush/jobs/${a.job_id}`, "DELETE");
    // Workers
    case "list_workers": return await cfRequest(`/accounts/${a.account_id}/workers/scripts`);
    case "get_worker": return await cfRequest(`/accounts/${a.account_id}/workers/scripts/${a.script_name}`);
    case "delete_worker": return await cfRequest(`/accounts/${a.account_id}/workers/scripts/${a.script_name}`, "DELETE");
    case "list_worker_routes": return await cfRequest(`/zones/${a.zone_id}/workers/routes`);
    case "create_worker_route": return await cfRequest(`/zones/${a.zone_id}/workers/routes`, "POST", { pattern: a.pattern, script: a.script||null });
    case "delete_worker_route": return await cfRequest(`/zones/${a.zone_id}/workers/routes/${a.route_id}`, "DELETE");
    case "list_worker_secrets": return await cfRequest(`/accounts/${a.account_id}/workers/scripts/${a.script_name}/secrets`);
    case "put_worker_secret": return await cfRequest(`/accounts/${a.account_id}/workers/scripts/${a.script_name}/secrets`, "PUT", { name: a.secret_name, text: a.text, type: "secret_text" });
    case "delete_worker_secret": return await cfRequest(`/accounts/${a.account_id}/workers/scripts/${a.script_name}/secrets/${a.secret_name}`, "DELETE");
    case "list_worker_cron_triggers": return await cfRequest(`/accounts/${a.account_id}/workers/scripts/${a.script_name}/schedules`);
    case "update_worker_cron_triggers": return await cfRequest(`/accounts/${a.account_id}/workers/scripts/${a.script_name}/schedules`, "PUT", a.crons);
    case "get_worker_subdomain": return await cfRequest(`/accounts/${a.account_id}/workers/subdomain`);
    case "upload_worker_script": {
      const mainModule = (a.main_module as string) || "worker.js";
      const today = new Date().toISOString().slice(0, 10);
      const metadata: Record<string, unknown> = {
        main_module: mainModule,
        compatibility_date: a.compatibility_date || today,
      };
      if (a.compatibility_flags) metadata.compatibility_flags = a.compatibility_flags;
      if (a.bindings) metadata.bindings = a.bindings;
      const fd = new FormData();
      fd.append("metadata", new Blob([JSON.stringify(metadata)], { type: "application/json" }));
      fd.append(mainModule, new Blob([a.script as string], { type: "application/javascript+module" }), mainModule);
      const res = await fetch(`${CF_BASE_URL}/accounts/${a.account_id}/workers/scripts/${a.script_name}`, { method: "PUT", headers: getAuthHeadersNoCT(), body: fd });
      const data = await res.json() as { success: boolean; errors: unknown[]; result: unknown };
      if (!data.success) throw new Error(`Cloudflare API error: ${JSON.stringify(data.errors)}`);
      return data.result;
    }
    case "get_worker_content": {
      const res = await fetch(`${CF_BASE_URL}/accounts/${a.account_id}/workers/scripts/${a.script_name}`, { headers: getAuthHeadersNoCT() });
      return await res.text();
    }
    case "enable_worker_subdomain": return await cfRequest(`/accounts/${a.account_id}/workers/scripts/${a.script_name}/subdomain`, "POST", { enabled: a.enabled });
    // Durable Objects
    case "list_durable_object_namespaces": return await cfRequest(`/accounts/${a.account_id}/workers/durable_objects/namespaces`);
    case "list_durable_objects": {
      let ep = `/accounts/${a.account_id}/workers/durable_objects/namespaces/${a.namespace_id}/objects?limit=${a.limit||100}`;
      if (a.cursor) ep += `&cursor=${a.cursor}`;
      return await cfRequest(ep);
    }
    // KV Storage
    case "list_kv_namespaces": return await cfRequest(`/accounts/${a.account_id}/storage/kv/namespaces?per_page=${a.per_page||50}`);
    case "create_kv_namespace": return await cfRequest(`/accounts/${a.account_id}/storage/kv/namespaces`, "POST", { title: a.title });
    case "delete_kv_namespace": return await cfRequest(`/accounts/${a.account_id}/storage/kv/namespaces/${a.namespace_id}`, "DELETE");
    case "list_kv_keys": {
      let ep = `/accounts/${a.account_id}/storage/kv/namespaces/${a.namespace_id}/keys?limit=${a.limit||1000}`;
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
      const ep2 = a.expiration_ttl ? `?expiration_ttl=${a.expiration_ttl}` : "";
      const res = await fetch(url + ep2, { method: "PUT", headers: { ...getAuthHeaders(), "Content-Type": "text/plain" }, body: a.value as string });
      return await res.json();
    }
    case "delete_kv_key": return await cfRequest(`/accounts/${a.account_id}/storage/kv/namespaces/${a.namespace_id}/values/${encodeURIComponent(a.key as string)}`, "DELETE");
    // Queues
    case "list_queues": return await cfRequest(`/accounts/${a.account_id}/queues`);
    case "get_queue": return await cfRequest(`/accounts/${a.account_id}/queues/${a.queue_id}`);
    case "create_queue": return await cfRequest(`/accounts/${a.account_id}/queues`, "POST", { queue_name: a.queue_name });
    case "delete_queue": return await cfRequest(`/accounts/${a.account_id}/queues/${a.queue_id}`, "DELETE");
    case "send_queue_messages": return await cfRequest(`/accounts/${a.account_id}/queues/${a.queue_id}/messages`, "POST", { messages: a.messages });
    case "pull_queue_messages": return await cfRequest(`/accounts/${a.account_id}/queues/${a.queue_id}/messages/pull`, "POST", { batch_size: a.batch_size||10, visibility_timeout_ms: a.visibility_timeout_ms||30000 });
    case "ack_queue_messages": return await cfRequest(`/accounts/${a.account_id}/queues/${a.queue_id}/messages/ack`, "POST", { acks: a.acks||[], retries: a.retries||[] });
    // R2
    case "list_r2_buckets": return await cfRequest(`/accounts/${a.account_id}/r2/buckets`);
    case "get_r2_bucket": return await cfRequest(`/accounts/${a.account_id}/r2/buckets/${a.name}`);
    case "create_r2_bucket": return await cfRequest(`/accounts/${a.account_id}/r2/buckets`, "POST", { name: a.name, ...(a.location_hint ? { locationHint: a.location_hint } : {}) });
    case "delete_r2_bucket": return await cfRequest(`/accounts/${a.account_id}/r2/buckets/${a.name}`, "DELETE");
    // D1
    case "list_d1_databases": return await cfRequest(`/accounts/${a.account_id}/d1/database?per_page=${a.per_page||50}`);
    case "get_d1_database": return await cfRequest(`/accounts/${a.account_id}/d1/database/${a.database_id}`);
    case "create_d1_database": return await cfRequest(`/accounts/${a.account_id}/d1/database`, "POST", { name: a.name });
    case "delete_d1_database": return await cfRequest(`/accounts/${a.account_id}/d1/database/${a.database_id}`, "DELETE");
    case "query_d1_database": return await cfRequest(`/accounts/${a.account_id}/d1/database/${a.database_id}/query`, "POST", { sql: a.sql, params: a.params||[] });
    // Hyperdrive
    case "list_hyperdrive_configs": return await cfRequest(`/accounts/${a.account_id}/hyperdrive/configs`);
    case "get_hyperdrive_config": return await cfRequest(`/accounts/${a.account_id}/hyperdrive/configs/${a.config_id}`);
    case "create_hyperdrive_config": return await cfRequest(`/accounts/${a.account_id}/hyperdrive/configs`, "POST", { name: a.name, origin: a.origin, ...(a.caching ? { caching: a.caching } : {}) });
    case "update_hyperdrive_config": {
      const b: Record<string, unknown> = {};
      ["name","origin","caching"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/accounts/${a.account_id}/hyperdrive/configs/${a.config_id}`, "PUT", b);
    }
    case "delete_hyperdrive_config": return await cfRequest(`/accounts/${a.account_id}/hyperdrive/configs/${a.config_id}`, "DELETE");
    // Vectorize
    case "list_vectorize_indexes": return await cfRequest(`/accounts/${a.account_id}/vectorize/v2/indexes`);
    case "get_vectorize_index": return await cfRequest(`/accounts/${a.account_id}/vectorize/v2/indexes/${a.index_name}`);
    case "create_vectorize_index": return await cfRequest(`/accounts/${a.account_id}/vectorize/v2/indexes`, "POST", { name: a.name, config: a.config });
    case "delete_vectorize_index": return await cfRequest(`/accounts/${a.account_id}/vectorize/v2/indexes/${a.index_name}`, "DELETE");
    case "query_vectorize_index": return await cfRequest(`/accounts/${a.account_id}/vectorize/v2/indexes/${a.index_name}/query`, "POST", { vector: a.vector, topK: a.top_k||5, filter: a.filter, returnValues: a.return_values??false, returnMetadata: a.return_metadata||"none" });
    case "upsert_vectorize_vectors": {
      const ndjson = (a.vectors as Array<Record<string, unknown>>).map(v => JSON.stringify(v)).join("\n");
      const res = await fetch(`${CF_BASE_URL}/accounts/${a.account_id}/vectorize/v2/indexes/${a.index_name}/upsert`, { method: "POST", headers: { ...getAuthHeaders(), "Content-Type": "application/x-ndjson" }, body: ndjson });
      return await res.json();
    }
    case "delete_vectorize_vectors": return await cfRequest(`/accounts/${a.account_id}/vectorize/v2/indexes/${a.index_name}/delete-by-ids`, "POST", { ids: a.ids });
    // AI Gateway
    case "list_ai_gateways": return await cfRequest(`/accounts/${a.account_id}/ai-gateway/gateways`);
    case "get_ai_gateway": return await cfRequest(`/accounts/${a.account_id}/ai-gateway/gateways/${a.gateway_id}`);
    case "create_ai_gateway": return await cfRequest(`/accounts/${a.account_id}/ai-gateway/gateways`, "POST", { name: a.name, slug: a.slug, collect_logs: a.collect_logs??true, ...(a.cache_ttl ? { cache_ttl: a.cache_ttl } : {}) });
    case "update_ai_gateway": {
      const b: Record<string, unknown> = {};
      ["name","collect_logs","cache_ttl"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/accounts/${a.account_id}/ai-gateway/gateways/${a.gateway_id}`, "PUT", b);
    }
    case "delete_ai_gateway": return await cfRequest(`/accounts/${a.account_id}/ai-gateway/gateways/${a.gateway_id}`, "DELETE");
    case "list_ai_gateway_logs": {
      let ep = `/accounts/${a.account_id}/ai-gateway/gateways/${a.gateway_id}/logs?per_page=${a.per_page||25}&page=${a.page||1}`;
      if (a.cached !== undefined) ep += `&cached=${a.cached}`;
      if (a.provider) ep += `&provider=${a.provider}`;
      return await cfRequest(ep);
    }
    // Images
    case "list_images": return await cfRequest(`/accounts/${a.account_id}/images/v1?page=${a.page||1}&per_page=${a.per_page||50}`);
    case "get_image": return await cfRequest(`/accounts/${a.account_id}/images/v1/${a.image_id}`);
    case "update_image": {
      const b: Record<string, unknown> = {};
      if (a.require_signed_urls !== undefined) b.requireSignedURLs = a.require_signed_urls;
      if (a.metadata) b.metadata = a.metadata;
      return await cfRequest(`/accounts/${a.account_id}/images/v1/${a.image_id}`, "PATCH", b);
    }
    case "delete_image": return await cfRequest(`/accounts/${a.account_id}/images/v1/${a.image_id}`, "DELETE");
    case "get_images_usage": return await cfRequest(`/accounts/${a.account_id}/images/v1/stats`);
    case "list_image_variants": return await cfRequest(`/accounts/${a.account_id}/images/v1/variants`);
    case "create_image_variant": return await cfRequest(`/accounts/${a.account_id}/images/v1/variants`, "POST", { id: a.variant_id, options: a.options });
    case "delete_image_variant": return await cfRequest(`/accounts/${a.account_id}/images/v1/variants/${a.variant_id}`, "DELETE");
    // Stream
    case "list_stream_videos": {
      let ep = `/accounts/${a.account_id}/stream?per_page=${a.per_page||50}`;
      if (a.search) ep += `&search=${encodeURIComponent(a.search as string)}`;
      return await cfRequest(ep);
    }
    case "get_stream_video": return await cfRequest(`/accounts/${a.account_id}/stream/${a.video_id}`);
    case "delete_stream_video": return await cfRequest(`/accounts/${a.account_id}/stream/${a.video_id}`, "DELETE");
    case "upload_stream_video_url": return await cfRequest(`/accounts/${a.account_id}/stream/copy`, "POST", { url: a.url, meta: a.meta||{} });
    case "list_stream_live_inputs": return await cfRequest(`/accounts/${a.account_id}/stream/live_inputs`);
    case "create_stream_live_input": return await cfRequest(`/accounts/${a.account_id}/stream/live_inputs`, "POST", { meta: a.meta||{}, recording: a.recording||{} });
    // Pages
    case "list_pages_projects": return await cfRequest(`/accounts/${a.account_id}/pages/projects?per_page=25`);
    case "get_pages_project": return await cfRequest(`/accounts/${a.account_id}/pages/projects/${a.project_name}`);
    case "create_pages_project": {
      const b: Record<string, unknown> = { name: a.name, production_branch: a.production_branch || "main" };
      ["build_config","source","deployment_configs"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/accounts/${a.account_id}/pages/projects`, "POST", b);
    }
    case "update_pages_project": {
      const b: Record<string, unknown> = {};
      ["production_branch","build_config","source","deployment_configs"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/accounts/${a.account_id}/pages/projects/${a.project_name}`, "PATCH", b);
    }
    case "delete_pages_project": return await cfRequest(`/accounts/${a.account_id}/pages/projects/${a.project_name}`, "DELETE");
    case "list_pages_deployments": return await cfRequest(`/accounts/${a.account_id}/pages/projects/${a.project_name}/deployments?per_page=${a.per_page||25}`);
    case "get_pages_deployment": return await cfRequest(`/accounts/${a.account_id}/pages/projects/${a.project_name}/deployments/${a.deployment_id}`);
    case "create_pages_deployment": {
      const fd = new FormData();
      if (a.branch) fd.append("branch", a.branch as string);
      const res = await fetch(`${CF_BASE_URL}/accounts/${a.account_id}/pages/projects/${a.project_name}/deployments`, { method: "POST", headers: getAuthHeadersNoCT(), body: fd });
      const data = await res.json() as { success: boolean; errors: unknown[]; result: unknown };
      if (!data.success) throw new Error(`Cloudflare API error: ${JSON.stringify(data.errors)}`);
      return data.result;
    }
    case "deploy_pages_files": {
      const filesInput = a.files as Record<string, unknown>;
      if (!filesInput || Object.keys(filesInput).length === 0) throw new Error("files map is empty");
      const norm: Array<{ path: string; base64Content: string; contentType: string; hash: string }> = [];
      for (const [rawPath, v] of Object.entries(filesInput)) {
        const p = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;
        let base64Content: string;
        let contentType: string | undefined;
        if (typeof v === "string") {
          base64Content = Buffer.from(v, "utf8").toString("base64");
        } else {
          const o = v as { content: string; base64?: boolean; content_type?: string };
          if (typeof o.content !== "string") throw new Error(`file ${p}: missing content`);
          base64Content = o.base64 ? o.content : Buffer.from(o.content, "utf8").toString("base64");
          contentType = o.content_type;
        }
        const lastSeg = p.split("/").pop() || "";
        const ext = lastSeg.includes(".") ? lastSeg.split(".").pop()!.toLowerCase() : "";
        const ct = contentType || PAGES_MIME[ext] || "application/octet-stream";
        const fileHash = blake3hash(base64Content + ext).toString("hex").slice(0, 32);
        norm.push({ path: p, base64Content, contentType: ct, hash: fileHash });
      }
      const jwtResult = await cfRequest(`/accounts/${a.account_id}/pages/projects/${a.project_name}/upload-token`) as { jwt: string };
      const jwt = jwtResult.jwt;
      const jwtHeaders = { "Authorization": `Bearer ${jwt}`, "Content-Type": "application/json" };
      const missingRes = await fetch(`${CF_BASE_URL}/pages/assets/check-missing`, { method: "POST", headers: jwtHeaders, body: JSON.stringify({ hashes: norm.map(f => f.hash) }) });
      const missingData = await missingRes.json() as { success: boolean; result: string[]; errors: unknown[] };
      if (!missingData.success) throw new Error(`Pages check-missing failed: ${JSON.stringify(missingData.errors)}`);
      const missing = new Set(missingData.result || []);
      const toUpload = norm.filter(f => missing.has(f.hash));
      for (let i = 0; i < toUpload.length; i += 40) {
        const batch = toUpload.slice(i, i + 40).map(f => ({ key: f.hash, value: f.base64Content, metadata: { contentType: f.contentType }, base64: true }));
        const upRes = await fetch(`${CF_BASE_URL}/pages/assets/upload`, { method: "POST", headers: jwtHeaders, body: JSON.stringify(batch) });
        const upData = await upRes.json() as { success: boolean; errors: unknown[] };
        if (!upData.success) throw new Error(`Pages asset upload failed: ${JSON.stringify(upData.errors)}`);
      }
      await fetch(`${CF_BASE_URL}/pages/assets/upsert-hashes`, { method: "POST", headers: jwtHeaders, body: JSON.stringify({ hashes: norm.map(f => f.hash) }) }).catch(() => undefined);
      const manifest: Record<string, string> = {};
      norm.forEach(f => { manifest[f.path] = f.hash; });
      const fd = new FormData();
      fd.append("manifest", JSON.stringify(manifest));
      if (a.branch) fd.append("branch", a.branch as string);
      const depRes = await fetch(`${CF_BASE_URL}/accounts/${a.account_id}/pages/projects/${a.project_name}/deployments`, { method: "POST", headers: getAuthHeadersNoCT(), body: fd });
      const depData = await depRes.json() as { success: boolean; errors: unknown[]; result: unknown };
      if (!depData.success) throw new Error(`Pages deployment failed: ${JSON.stringify(depData.errors)}`);
      return depData.result;
    }
    case "purge_pages_build_cache": return await cfRequest(`/accounts/${a.account_id}/pages/projects/${a.project_name}/purge_build_cache`, "POST");
    case "retry_pages_deployment": return await cfRequest(`/accounts/${a.account_id}/pages/projects/${a.project_name}/deployments/${a.deployment_id}/retry`, "POST");
    case "rollback_pages_deployment": return await cfRequest(`/accounts/${a.account_id}/pages/projects/${a.project_name}/deployments/${a.deployment_id}/rollback`, "POST");
    case "list_pages_domains": return await cfRequest(`/accounts/${a.account_id}/pages/projects/${a.project_name}/domains`);
    case "add_pages_domain": return await cfRequest(`/accounts/${a.account_id}/pages/projects/${a.project_name}/domains`, "POST", { name: a.domain });
    case "delete_pages_domain": return await cfRequest(`/accounts/${a.account_id}/pages/projects/${a.project_name}/domains/${a.domain}`, "DELETE");
    // Registrar
    case "list_registrar_domains": return await cfRequest(`/accounts/${a.account_id}/registrar/domains`);
    case "get_registrar_domain": return await cfRequest(`/accounts/${a.account_id}/registrar/domains/${a.domain_name}`);
    case "update_registrar_domain": {
      const b: Record<string, unknown> = {};
      ["auto_renew","locked","privacy"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/accounts/${a.account_id}/registrar/domains/${a.domain_name}`, "PUT", b);
    }
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
    // Email Routing
    case "get_email_routing_settings": return await cfRequest(`/zones/${a.zone_id}/email/routing`);
    case "enable_email_routing": return await cfRequest(`/zones/${a.zone_id}/email/routing/enable`, "POST");
    case "disable_email_routing": return await cfRequest(`/zones/${a.zone_id}/email/routing/disable`, "POST");
    case "list_email_routing_rules": {
      let ep = `/zones/${a.zone_id}/email/routing/rules?per_page=${a.per_page||50}`;
      if (a.enabled !== undefined) ep += `&enabled=${a.enabled}`;
      return await cfRequest(ep);
    }
    case "get_email_routing_rule": return await cfRequest(`/zones/${a.zone_id}/email/routing/rules/${a.rule_id}`);
    case "create_email_routing_rule": {
      const b: Record<string, unknown> = { matchers: a.matchers, actions: a.actions, enabled: a.enabled??true };
      if (a.name) b.name = a.name;
      return await cfRequest(`/zones/${a.zone_id}/email/routing/rules`, "POST", b);
    }
    case "update_email_routing_rule": {
      const b: Record<string, unknown> = {};
      ["name","enabled","matchers","actions"].forEach(k => { if (a[k] !== undefined) b[k] = a[k]; });
      return await cfRequest(`/zones/${a.zone_id}/email/routing/rules/${a.rule_id}`, "PUT", b);
    }
    case "delete_email_routing_rule": return await cfRequest(`/zones/${a.zone_id}/email/routing/rules/${a.rule_id}`, "DELETE");
    case "get_catch_all_rule": return await cfRequest(`/zones/${a.zone_id}/email/routing/rules/catch_all`);
    case "update_catch_all_rule": {
      const b: Record<string, unknown> = { actions: a.actions, matchers: a.matchers||[{ type: "all" }] };
      if (a.enabled !== undefined) b.enabled = a.enabled;
      if (a.name) b.name = a.name;
      return await cfRequest(`/zones/${a.zone_id}/email/routing/rules/catch_all`, "PUT", b);
    }
    case "list_email_destination_addresses": {
      let ep = `/accounts/${a.account_id}/email/routing/addresses?per_page=${a.per_page||50}`;
      if (a.verified !== undefined) ep += `&verified=${a.verified}`;
      return await cfRequest(ep);
    }
    case "create_email_destination_address": return await cfRequest(`/accounts/${a.account_id}/email/routing/addresses`, "POST", { email: a.email });
    case "get_email_destination_address": return await cfRequest(`/accounts/${a.account_id}/email/routing/addresses/${a.destination_id}`);
    case "delete_email_destination_address": return await cfRequest(`/accounts/${a.account_id}/email/routing/addresses/${a.destination_id}`, "DELETE");
    default: throw new Error(`Unknown tool: ${name}`);
  }
}

async function handleMcpRequest(request: { jsonrpc: string; id?: unknown; method: string; params?: Record<string, unknown> }): Promise<unknown> {
  const { id, method, params } = request;
  try {
    let result;
    switch (method) {
      case "initialize": result = { protocolVersion: "2024-11-05", serverInfo: { name: "cloudflare-mcp-server", version: "3.4.0" }, capabilities: { tools: {} } }; break;
      case "notifications/initialized": return null;
      case "tools/list": result = { tools }; break;
      case "tools/call":
        if (!params) throw new Error("Missing params");
        result = { content: [{ type: "text", text: JSON.stringify(await executeTool(params.name as string, (params.arguments as Record<string, unknown>)||{}), null, 2) }] };
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
  res.json({ status: "ok", version: "3.4.0", auth: CF_AUTH_TYPE === "global_key" ? "Global API Key" : "API Token", tools: tools.length, sessions: sessions.size });
});

app.get("/", (_req: Request, res: Response) => {
  res.json({ name: "Cloudflare MCP Server", version: "3.4.0", tools: tools.map(t => t.name), total: tools.length });
});

app.listen(PORT, () => console.log(`Cloudflare MCP Server v3.3.0 on port ${PORT} [${tools.length} tools]`));
