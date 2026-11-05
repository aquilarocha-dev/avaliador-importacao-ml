// Edge Function: conexão OAuth com o JoomPulse MCP e busca de produtos no Mercado Livre.
// Rotas:
//   POST /start       (usuário logado)  -> devolve a URL de autorização do JoomPulse
//   GET  /callback    (redirect do JoomPulse) -> troca o code por tokens e volta ao app
//   POST /status      (usuário logado)  -> { connected }
//   POST /search      (usuário logado)  -> { columns, data } da busca meli_search_products
//   POST /disconnect  (usuário logado)  -> apaga os tokens
// Segredos necessários: JOOMPULSE_CLIENT_ID, JOOMPULSE_CLIENT_SECRET (opcional para cliente público)
import { createClient } from "npm:@supabase/supabase-js@2";

const MCP_URL = "https://joompulse.com/mcp";
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const FN_URL = `${SUPABASE_URL}/functions/v1/joompulse-oauth`;
const REDIRECT_URI = `${FN_URL}/callback`;
const CLIENT_ID = Deno.env.get("JOOMPULSE_CLIENT_ID") ?? "";
const CLIENT_SECRET = Deno.env.get("JOOMPULSE_CLIENT_SECRET") ?? "";
const ALLOWED_RETURN = [
  "https://avaliador-importacao.vercel.app",
  "http://localhost",
  "http://127.0.0.1",
];

function serviceKey(): string {
  const legacy = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (legacy) return legacy;
  try {
    const keys = JSON.parse(Deno.env.get("SUPABASE_SECRET_KEYS") ?? "{}");
    const first = Object.values(keys)[0];
    if (typeof first === "string") return first;
  } catch (_) { /* ignore */ }
  throw new Error("service key ausente");
}
const admin = createClient(SUPABASE_URL, serviceKey(), { auth: { persistSession: false } });

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });

// ---------- descoberta OAuth (RFC 9728 / RFC 8414) ----------
type AuthMeta = { authorization_endpoint: string; token_endpoint: string; scopes_supported?: string[] };
let metaCache: AuthMeta | null = null;

async function getJson(url: string): Promise<any | null> {
  try {
    const r = await fetch(url, { headers: { Accept: "application/json" } });
    if (!r.ok) return null;
    return await r.json();
  } catch (_) { return null; }
}

async function discover(): Promise<AuthMeta> {
  if (metaCache) return metaCache;
  const u = new URL(MCP_URL);
  const prCandidates = [
    `${u.origin}/.well-known/oauth-protected-resource${u.pathname}`,
    `${u.origin}/.well-known/oauth-protected-resource`,
  ];
  let issuers: string[] = [];
  for (const c of prCandidates) {
    const pr = await getJson(c);
    if (pr?.authorization_servers?.length) { issuers = pr.authorization_servers; break; }
  }
  if (!issuers.length) issuers = [u.origin];
  for (const iss of issuers) {
    const i = new URL(iss);
    const path = i.pathname === "/" ? "" : i.pathname;
    const candidates = [
      `${i.origin}/.well-known/oauth-authorization-server${path}`,
      `${i.origin}/.well-known/openid-configuration${path}`,
      `${iss.replace(/\/$/, "")}/.well-known/oauth-authorization-server`,
      `${iss.replace(/\/$/, "")}/.well-known/openid-configuration`,
    ];
    for (const c of candidates) {
      const m = await getJson(c);
      if (m?.authorization_endpoint && m?.token_endpoint) { metaCache = m; return m; }
    }
  }
  throw new Error("Não foi possível descobrir os endereços OAuth do JoomPulse");
}

// ---------- utilidades ----------
function b64url(bytes: Uint8Array): string {
  let s = ""; bytes.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randomString(n = 48): string { return b64url(crypto.getRandomValues(new Uint8Array(n))); }
async function sha256(s: string): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));
}

async function userFrom(req: Request): Promise<string | null> {
  const auth = req.headers.get("Authorization") ?? "";
  const jwt = auth.replace(/^Bearer\s+/i, "");
  if (!jwt) return null;
  const { data, error } = await admin.auth.getUser(jwt);
  if (error || !data?.user) return null;
  return data.user.id;
}

function safeReturn(r: string | null | undefined): string {
  if (r && ALLOWED_RETURN.some((a) => r === a || r.startsWith(a + "/") || r.startsWith(a + ":") || r.startsWith(a + "?"))) return r;
  return ALLOWED_RETURN[0];
}
function withParam(url: string, k: string, v: string): string {
  const u = new URL(url); u.searchParams.set(k, v); return u.toString();
}

async function tokenRequest(endpoint: string, params: Record<string, string>) {
  const body = new URLSearchParams({ ...params, client_id: CLIENT_ID });
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
  if (CLIENT_SECRET) body.set("client_secret", CLIENT_SECRET);
  const r = await fetch(endpoint, { method: "POST", headers, body });
  const text = await r.text();
  let data: any = null; try { data = JSON.parse(text); } catch (_) { /* */ }
  if (!r.ok || !data?.access_token) throw new Error(`token ${r.status}: ${text.slice(0, 300)}`);
  return data;
}

async function saveTokens(userId: string, t: any, tokenEndpoint: string, oldRefresh?: string | null) {
  const expires = t.expires_in ? new Date(Date.now() + (Number(t.expires_in) - 60) * 1000).toISOString() : null;
  await admin.from("joompulse_tokens").upsert({
    user_id: userId, access_token: t.access_token, refresh_token: t.refresh_token ?? oldRefresh ?? null,
    expires_at: expires, token_endpoint: tokenEndpoint, updated_at: new Date().toISOString(),
  });
}

async function accessToken(userId: string): Promise<string | null> {
  const { data } = await admin.from("joompulse_tokens").select("*").eq("user_id", userId).maybeSingle();
  if (!data) return null;
  if (!data.expires_at || new Date(data.expires_at).getTime() > Date.now()) return data.access_token;
  if (!data.refresh_token) return null;
  try {
    const t = await tokenRequest(data.token_endpoint, { grant_type: "refresh_token", refresh_token: data.refresh_token, resource: MCP_URL });
    await saveTokens(userId, t, data.token_endpoint, data.refresh_token);
    return t.access_token;
  } catch (_) {
    await admin.from("joompulse_tokens").delete().eq("user_id", userId);
    return null;
  }
}

// ---------- cliente MCP (Streamable HTTP) ----------
async function readRpc(r: Response, id: number): Promise<any> {
  const ct = r.headers.get("content-type") ?? "";
  const text = await r.text();
  if (ct.includes("text/event-stream")) {
    const msgs: any[] = [];
    for (const block of text.split(/\n\n/)) {
      const data = block.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).join("\n");
      if (!data) continue;
      try { msgs.push(JSON.parse(data)); } catch (_) { /* */ }
    }
    return msgs.find((m) => m.id === id) ?? msgs[msgs.length - 1] ?? null;
  }
  try { return JSON.parse(text); } catch (_) { return { error: { message: text.slice(0, 300) } }; }
}

async function mcpCall(token: string, tool: string, args: Record<string, unknown>) {
  const base: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };
  const init = await fetch(MCP_URL, {
    method: "POST", headers: base,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {
      protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "avaliador-importacao", version: "1.0" } } }),
  });
  if (init.status === 401 || init.status === 403) return { unauthorized: true };
  const initMsg = await readRpc(init, 1);
  if (initMsg?.error) throw new Error("initialize: " + JSON.stringify(initMsg.error).slice(0, 300));
  const session = init.headers.get("mcp-session-id");
  const headers = { ...base, ...(session ? { "Mcp-Session-Id": session } : {}),
    ...(initMsg?.result?.protocolVersion ? { "MCP-Protocol-Version": initMsg.result.protocolVersion } : {}) };
  await fetch(MCP_URL, { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) })
    .then((r) => r.body?.cancel()).catch(() => {});
  const call = await fetch(MCP_URL, {
    method: "POST", headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: tool, arguments: args } }),
  });
  if (call.status === 401 || call.status === 403) return { unauthorized: true };
  const msg = await readRpc(call, 2);
  if (session) fetch(MCP_URL, { method: "DELETE", headers }).then((r) => r.body?.cancel()).catch(() => {});
  if (msg?.error) throw new Error("tools/call: " + JSON.stringify(msg.error).slice(0, 300));
  return { result: msg?.result };
}

// procura recursivamente um objeto { columns: [...], data: [...] }
function findTable(x: any, depth = 0): any | null {
  if (!x || depth > 6) return null;
  if (typeof x === "string") { try { return findTable(JSON.parse(x), depth + 1); } catch (_) { return null; } }
  if (Array.isArray(x)) { for (const v of x) { const f = findTable(v, depth + 1); if (f) return f; } return null; }
  if (typeof x === "object") {
    if (Array.isArray(x.columns) && Array.isArray(x.data)) return { columns: x.columns, data: x.data };
    for (const v of Object.values(x)) { const f = findTable(v, depth + 1); if (f) return f; }
  }
  return null;
}

// ---------- rotas ----------
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  const url = new URL(req.url);
  const route = url.pathname.split("/").filter(Boolean).pop();

  try {
    if (route === "callback") {
      const state = url.searchParams.get("state") ?? "";
      const code = url.searchParams.get("code");
      const { data: st } = await admin.from("joompulse_oauth_states").select("*").eq("state", state).maybeSingle();
      if (!st) return new Response("Sessão de conexão inválida ou expirada. Volte ao app e tente de novo.", { status: 400 });
      await admin.from("joompulse_oauth_states").delete().eq("state", state);
      const back = safeReturn(st.return_to);
      if (!code) return Response.redirect(withParam(back, "joompulse", "erro"), 302);
      try {
        const meta = await discover();
        const t = await tokenRequest(meta.token_endpoint, {
          grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI, code_verifier: st.code_verifier, resource: MCP_URL,
        });
        await saveTokens(st.user_id, t, meta.token_endpoint);
        return Response.redirect(withParam(back, "joompulse", "ok"), 302);
      } catch (e) {
        console.error("callback", e);
        return Response.redirect(withParam(back, "joompulse", "erro"), 302);
      }
    }

    if (req.method !== "POST") return json({ error: "método não permitido" }, 405);
    const userId = await userFrom(req);
    if (!userId) return json({ error: "não autenticado" }, 401);
    const body = await req.json().catch(() => ({}));

    if (route === "start") {
      if (!CLIENT_ID) return json({ error: "Segredo JOOMPULSE_CLIENT_ID não configurado" }, 500);
      const meta = await discover();
      const state = randomString(24);
      const verifier = randomString(48);
      await admin.from("joompulse_oauth_states").delete().lt("created_at", new Date(Date.now() - 3600_000).toISOString());
      await admin.from("joompulse_oauth_states").insert({ state, user_id: userId, code_verifier: verifier, return_to: safeReturn(body.returnTo) });
      const a = new URL(meta.authorization_endpoint);
      a.searchParams.set("response_type", "code");
      a.searchParams.set("client_id", CLIENT_ID);
      a.searchParams.set("redirect_uri", REDIRECT_URI);
      a.searchParams.set("state", state);
      a.searchParams.set("code_challenge", await sha256(verifier));
      a.searchParams.set("code_challenge_method", "S256");
      a.searchParams.set("resource", MCP_URL);
      if (meta.scopes_supported?.length) a.searchParams.set("scope", meta.scopes_supported.join(" "));
      return json({ url: a.toString() });
    }

    if (route === "status") {
      const t = await accessToken(userId);
      return json({ connected: !!t });
    }

    if (route === "disconnect") {
      await admin.from("joompulse_tokens").delete().eq("user_id", userId);
      return json({ ok: true });
    }

    if (route === "search") {
      const q = String(body.q ?? "").trim().slice(0, 120);
      if (!q) return json({ error: "busca vazia" }, 400);
      const token = await accessToken(userId);
      if (!token) return json({ needs_connect: true });
      const r = await mcpCall(token, "meli_search_products", {
        country: "BR", queries: [q], group: "product", sort_by: "revenue1m", limit: 20, preset: "full_info",
      });
      if ((r as any).unauthorized) {
        await admin.from("joompulse_tokens").delete().eq("user_id", userId);
        return json({ needs_connect: true });
      }
      const result = (r as any).result ?? {};
      if (result.isError) {
        const msg = (result.content ?? []).map((c: any) => c.text).filter(Boolean).join(" ").slice(0, 300);
        return json({ error: msg || "A busca foi recusada pelo JoomPulse" }, 502);
      }
      const table = findTable(result.structuredContent) ?? findTable(result.content) ?? findTable(result);
      if (!table) return json({ error: "Resposta do JoomPulse em formato inesperado" }, 502);
      // tipo de anúncio (Premium/Clássico) do item do buy box, via meli_get_item (a busca não traz a coluna)
      const iBB = table.columns.indexOf("buyBoxItemId");
      if (iBB >= 0) {
        const ids = [...new Set(table.data.map((d: any[]) => d[iBB]).filter(Boolean))].slice(0, 100) as string[];
        const types: Record<string, string> = {};
        if (ids.length) {
          try {
            const x: any = await mcpCall(token, "meli_get_item", { country: "BR", ids, preset: "full_info" });
            const t = findTable(x.result?.structuredContent) ?? findTable(x.result?.content);
            if (t) {
              const ii = t.columns.indexOf("itemId"), il = t.columns.indexOf("listingType");
              if (ii >= 0 && il >= 0) for (const row of t.data) types[row[ii]] = row[il];
            }
          } catch (_) { /* tipo fica em branco */ }
        }
        table.columns = [...table.columns, "listingType"];
        table.data = table.data.map((d: any[]) => [...d, types[d[iBB]] ?? null]);
      }
      return json(table);
    }

    return json({ error: "rota desconhecida" }, 404);
  } catch (e) {
    console.error(route, e);
    return json({ error: String((e as Error).message ?? e).slice(0, 300) }, 500);
  }
});
