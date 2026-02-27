import { getIP, checkBan, trackAbuse, checkRateLimit, notify } from "../_shared.js";

const checkBody = (body, cfg) => {
  if (cfg.rP && cfg.pV && !body.includes(cfg.pV)) return "missing prefix";
  if (cfg.bE && /@everyone/.test(body)) return "@everyone blocked";
  if (cfg.bH && /@here/.test(body)) return "@here blocked";
  if (cfg.bM && (/<@!?\d+>/.test(body) || /<@&\d+>/.test(body))) return "mentions blocked";
  if (cfg.bA && /@/.test(body)) return "@ symbol blocked";
  if (cfg.bD && /discord/i.test(body)) return "discord keyword blocked";
  return null;
};

export async function onRequest({ request, params, env }) {
  const token = params.catchall;
  const ip = getIP(request);

  if (request.method === "GET")
    return new Response("webhook protect proxy — POST only", { status: 200 });

  if (request.method !== "POST")
    return new Response("POST only", { status: 405 });

  const banned = await checkBan(env, ip);
  if (banned !== null)
    return new Response(`banned, retry in ${banned.remaining}s`, { status: 403 });

  const rl = await checkRateLimit(env, ip, "proxy", 30);
  if (rl.blocked) {
    await notify("ratelimit", ip, { tier: rl.tier, remaining: rl.remaining, endpoint: "/webhook/" });
    await trackAbuse(env, ip, "abuse", { endpoint: "/webhook/" });
    return new Response(`rate limited (tier ${rl.tier}), retry in ${rl.remaining}s`, { status: 429 });
  }

  if (!/^[a-f0-9]{128}$/.test(token)) {
    await trackAbuse(env, ip, "invalid_token", { token });
    return new Response("invalid token", { status: 400 });
  }

  const raw = await env.WH.get(`wh:${token}`);
  if (!raw) {
    await trackAbuse(env, ip, "invalid_token", { token });
    return new Response("not found", { status: 404 });
  }

  const { u: webhookUrl, c: cfg } = JSON.parse(raw);
  const body = await request.text();
  const blocked = checkBody(body, cfg);
  if (blocked) return new Response("blocked: " + blocked, { status: 403 });

  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": request.headers.get("Content-Type") || "application/json" },
    body,
  });

  return new Response(await res.text(), { status: res.status });
}
