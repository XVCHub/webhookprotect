const getIP = (request) =>
  request.headers.get("CF-Connecting-IP") ||
  request.headers.get("X-Forwarded-For")?.split(",")[0].trim() ||
  "unknown";

const checkBody = (body, cfg) => {
  if (cfg.rP && cfg.pV && !body.includes(cfg.pV)) return "missing prefix";
  if (cfg.bE && /@everyone/.test(body)) return "@everyone blocked";
  if (cfg.bH && /@here/.test(body)) return "@here blocked";
  if (cfg.bM && (/<@!?\d+>/.test(body) || /<@&\d+>/.test(body))) return "mentions blocked";
  if (cfg.bA && /@/.test(body)) return "@ symbol blocked";
  if (cfg.bD && /discord/i.test(body)) return "discord keyword blocked";
  return null;
};

export async function onRequestPost({ request, params, env }) {
  const token = params.token;
  const ip = getIP(request);

  if (!/^[a-f0-9]{128}$/.test(token)) {
    await trackAbuse(env, ip);
    return new Response("invalid token", { status: 400 });
  }

  const banKey = `ban:${ip}`;
  const banned = await env.WH.get(banKey);
  if (banned) return new Response("too many invalid requests", { status: 403 });

  const rlKey = `ratelimit:proxy:${ip}`;
  const rlRaw = await env.WH.get(rlKey);
  const rl = rlRaw ? JSON.parse(rlRaw) : { count: 0, ts: Date.now() };

  if (Date.now() - rl.ts > 60_000) {
    rl.count = 0;
    rl.ts = Date.now();
  }

  if (rl.count >= 30)
    return new Response("rate limited", { status: 429 });

  rl.count++;
  await env.WH.put(rlKey, JSON.stringify(rl), { expirationTtl: 120 });

  const raw = await env.WH.get(`wh:${token}`);
  if (!raw) {
    await trackAbuse(env, ip);
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

const trackAbuse = async (env, ip) => {
  const abuseKey = `abuse:${ip}`;
  const raw = await env.WH.get(abuseKey);
  const abuse = raw ? JSON.parse(raw) : { count: 0, ts: Date.now() };

  if (Date.now() - abuse.ts > 300_000) {
    abuse.count = 0;
    abuse.ts = Date.now();
  }

  abuse.count++;
  await env.WH.put(abuseKey, JSON.stringify(abuse), { expirationTtl: 600 });

  if (abuse.count >= 5) {
    await env.WH.put(`ban:${ip}`, "1", { expirationTtl: 3600 });
  }
};

export async function onRequestGet() {
  return new Response("webhook protect proxy — POST only", { status: 200 });
}
