const getIP = (req) =>
  req.headers.get("CF-Connecting-IP") ||
  req.headers.get("X-Forwarded-For")?.split(",")[0].trim() ||
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

const trackAbuse = async (env, ip) => {
  const key = `abuse:${ip}`;
  const raw = await env.WH.get(key);
  const a = raw ? JSON.parse(raw) : { n: 0, t: Date.now() };
  if (Date.now() - a.t > 300_000) { a.n = 0; a.t = Date.now(); }
  a.n++;
  await env.WH.put(key, JSON.stringify(a), { expirationTtl: 600 });
  if (a.n >= 5) await env.WH.put(`ban:${ip}`, "1", { expirationTtl: 3600 });
};

export async function onRequest({ request, params, env }) {
  const token = params.catchall;
  const ip = getIP(request);

  if (request.method === "GET")
    return new Response("webhook protect proxy — POST only", { status: 200 });

  if (request.method !== "POST")
    return new Response("POST only", { status: 405 });

  if (!/^[a-f0-9]{128}$/.test(token)) {
    await trackAbuse(env, ip);
    return new Response("invalid token", { status: 400 });
  }

  if (await env.WH.get(`ban:${ip}`))
    return new Response("banned", { status: 403 });

  const rlRaw = await env.WH.get(`rl:proxy:${ip}`);
  const rl = rlRaw ? JSON.parse(rlRaw) : { n: 0, t: Date.now() };
  if (Date.now() - rl.t > 60_000) { rl.n = 0; rl.t = Date.now(); }
  if (rl.n >= 30) return new Response("rate limited", { status: 429 });
  rl.n++;
  await env.WH.put(`rl:proxy:${ip}`, JSON.stringify(rl), { expirationTtl: 120 });

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
