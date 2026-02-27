const genToken = () => {
  const arr = new Uint8Array(64);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, "0")).join("");
};

const getIP = (req) =>
  req.headers.get("CF-Connecting-IP") ||
  req.headers.get("X-Forwarded-For")?.split(",")[0].trim() ||
  "unknown";

const RL_DURATIONS = [120, 240, 360];

const checkRateLimit = async (env, ip, max, windowMs) => {
  const now = Date.now();
  const rlKey = `rl:create:${ip}`;
  const histKey = `rlhist:create:${ip}`;

  const punishRaw = await env.WH.get(`rlpunish:create:${ip}`);
  if (punishRaw) {
    const p = JSON.parse(punishRaw);
    const remaining = Math.ceil((p.until - now) / 1000);
    if (now < p.until) return { blocked: true, remaining, tier: p.tier };
    await env.WH.delete(`rlpunish:create:${ip}`);
  }

  const rlRaw = await env.WH.get(rlKey);
  const rl = rlRaw ? JSON.parse(rlRaw) : { n: 0, t: now };
  if (now - rl.t > windowMs) { rl.n = 0; rl.t = now; }

  if (rl.n >= max) {
    const histRaw = await env.WH.get(histKey);
    const hist = histRaw ? JSON.parse(histRaw) : { hits: 0, last: now };
    if (now - hist.last > 600_000) hist.hits = 0;
    hist.hits++;
    hist.last = now;
    await env.WH.put(histKey, JSON.stringify(hist), { expirationTtl: 700 });

    const tier = Math.min(hist.hits, 3);
    const dur = RL_DURATIONS[tier - 1];
    await env.WH.put(`rlpunish:create:${ip}`, JSON.stringify({ until: now + dur * 1000, tier }), { expirationTtl: dur + 10 });
    await env.WH.delete(rlKey);
    return { blocked: true, remaining: dur, tier };
  }

  rl.n++;
  await env.WH.put(rlKey, JSON.stringify(rl), { expirationTtl: Math.ceil(windowMs / 1000) + 5 });
  return { blocked: false };
};

export async function onRequestPost({ request, env }) {
  const ip = getIP(request);
  const rl = await checkRateLimit(env, ip, 5, 60_000);
  if (rl.blocked)
    return new Response(JSON.stringify({ error: `rate limited (tier ${rl.tier}), retry in ${rl.remaining}s` }), {
      status: 429, headers: { "Content-Type": "application/json" }
    });

  const body = await request.json();
  if (!body.u?.startsWith("https://discord.com/api/webhooks/"))
    return new Response(JSON.stringify({ error: "invalid webhook url" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });

  const check = await fetch(body.u, { method: "GET" });
  if (!check.ok)
    return new Response(JSON.stringify({ error: "webhook not found or deleted" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });

  const token = genToken();
  await env.WH.put(`wh:${token}`, JSON.stringify({ u: body.u, c: body.c }));
  return new Response(JSON.stringify({ token }), {
    headers: { "Content-Type": "application/json" }
  });
}
