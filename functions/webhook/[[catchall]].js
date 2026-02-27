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

const RL_DURATIONS = [120, 240, 360];

const checkRateLimit = async (env, ip) => {
  const now = Date.now();

  const punishRaw = await env.WH.get(`rlpunish:proxy:${ip}`);
  if (punishRaw) {
    const p = JSON.parse(punishRaw);
    const remaining = Math.ceil((p.until - now) / 1000);
    if (now < p.until) return { blocked: true, remaining, tier: p.tier };
    await env.WH.delete(`rlpunish:proxy:${ip}`);
  }

  const rlRaw = await env.WH.get(`rl:proxy:${ip}`);
  const rl = rlRaw ? JSON.parse(rlRaw) : { n: 0, t: now };
  if (now - rl.t > 60_000) { rl.n = 0; rl.t = now; }

  if (rl.n >= 30) {
    const histRaw = await env.WH.get(`rlhist:proxy:${ip}`);
    const hist = histRaw ? JSON.parse(histRaw) : { hits: 0, last: now };
    if (now - hist.last > 600_000) hist.hits = 0;
    hist.hits++;
    hist.last = now;
    await env.WH.put(`rlhist:proxy:${ip}`, JSON.stringify(hist), { expirationTtl: 700 });

    const tier = Math.min(hist.hits, 3);
    const dur = RL_DURATIONS[tier - 1];
    await env.WH.put(`rlpunish:proxy:${ip}`, JSON.stringify({ until: now + dur * 1000, tier }), { expirationTtl: dur + 10 });
    await env.WH.delete(`rl:proxy:${ip}`);
    return { blocked: true, remaining: dur, tier };
  }

  rl.n++;
  await env.WH.put(`rl:proxy:${ip}`, JSON.stringify(rl), { expirationTtl: 65 });
  return { blocked: false };
};

const trackAbuse = async (env, ip) => {
  const now = Date.now();
  const key = `abuse:${ip}`;
  const banKey = `ban:${ip}`;

  const raw = await env.WH.get(key);
  const a = raw ? JSON.parse(raw) : { n: 0, t: now };
  if (now - a.t > 300_000) { a.n = 0; a.t = now; }
  a.n++;
  await env.WH.put(key, JSON.stringify(a), { expirationTtl: 600 });

  if (a.n >= 5) {
    const banRaw = await env.WH.get(banKey);
    if (banRaw) {
      const ban = JSON.parse(banRaw);
      ban.count = (ban.count || 1) + 1;
      const newDur = Math.min(3600 * ban.count, 86400);
      ban.until = now + newDur * 1000;
      await env.WH.put(banKey, JSON.stringify(ban), { expirationTtl: newDur + 10 });
    } else {
      await env.WH.put(banKey, JSON.stringify({ until: now + 3600_000, count: 1 }), { expirationTtl: 3610 });
    }
    await env.WH.delete(key);
  }
};

export async function onRequest({ request, params, env }) {
  const token = params.catchall;
  const ip = getIP(request);
  const now = Date.now();

  if (request.method === "GET")
    return new Response("webhook protect proxy — POST only", { status: 200 });

  if (request.method !== "POST")
    return new Response("POST only", { status: 405 });

  const banRaw = await env.WH.get(`ban:${ip}`);
  if (banRaw) {
    const ban = JSON.parse(banRaw);
    if (now < ban.until) {
      const remaining = Math.ceil((ban.until - now) / 1000);
      return new Response(`banned for ${remaining}s`, { status: 403 });
    }
    await env.WH.delete(`ban:${ip}`);
  }

  const rl = await checkRateLimit(env, ip);
  if (rl.blocked)
    return new Response(`rate limited (tier ${rl.tier}), retry in ${rl.remaining}s`, { status: 429 });

  if (!/^[a-f0-9]{128}$/.test(token)) {
    await trackAbuse(env, ip);
    return new Response("invalid token", { status: 400 });
  }

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
