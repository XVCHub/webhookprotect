import { getIP, checkBan, trackAbuse, checkRateLimit, notify } from "../_shared.js";

const genToken = () => {
  const arr = new Uint8Array(64);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, "0")).join("");
};

export async function onRequestPost({ request, env }) {
  const ip = getIP(request);

  const banned = await checkBan(env, ip);
  if (banned !== null)
    return new Response(JSON.stringify({ error: `banned, retry in ${banned.remaining}s` }), {
      status: 403, headers: { "Content-Type": "application/json" }
    });

  const rl = await checkRateLimit(env, ip, "create", 5);
  if (rl.blocked) {
    await notify("ratelimit", ip, { tier: rl.tier, remaining: rl.remaining, endpoint: "/api/create" });
    await trackAbuse(env, ip, "abuse", { endpoint: "/api/create" });
    return new Response(JSON.stringify({ error: `rate limited (tier ${rl.tier}), retry in ${rl.remaining}s` }), {
      status: 429, headers: { "Content-Type": "application/json" }
    });
  }

  let body;
  try { body = await request.json(); } catch {
    await trackAbuse(env, ip, "invalid_webhook", { url: "invalid json" });
    return new Response(JSON.stringify({ error: "invalid request body" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });
  }

  if (!body.u?.startsWith("https://discord.com/api/webhooks/")) {
    await trackAbuse(env, ip, "invalid_webhook", { url: body.u || "none" });
    return new Response(JSON.stringify({ error: "invalid webhook url" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });
  }

  const dupKey = `dup:${ip}:${body.u}`;
  if (await env.WH.get(dupKey)) {
    await trackAbuse(env, ip, "duplicate_webhook", { url: body.u });
    return new Response(JSON.stringify({ error: "webhook already protected, use existing url" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });
  }

  let check;
  try { check = await fetch(body.u, { method: "GET" }); } catch {
    await trackAbuse(env, ip, "invalid_webhook", { url: body.u });
    return new Response(JSON.stringify({ error: "could not verify webhook" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });
  }

  if (!check.ok) {
    await trackAbuse(env, ip, "invalid_webhook", { url: body.u });
    return new Response(JSON.stringify({ error: "webhook not found or deleted" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });
  }

  const token = genToken();
  await env.WH.put(`wh:${token}`, JSON.stringify({ u: body.u, c: body.c }));
  await env.WH.put(dupKey, token, { expirationTtl: 86400 });

  return new Response(JSON.stringify({ token }), {
    headers: { "Content-Type": "application/json" }
  });
}
