const genToken = () => {
  const chars = "abcdef0123456789";
  const arr = new Uint8Array(128);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => chars[b % 16]).join("");
};

const getIP = (request) =>
  request.headers.get("CF-Connecting-IP") ||
  request.headers.get("X-Forwarded-For")?.split(",")[0].trim() ||
  "unknown";

export async function onRequestPost({ request, env }) {
  const ip = getIP(request);
  const ipKey = `ratelimit:create:${ip}`;

  const raw = await env.WH.get(ipKey);
  const rl = raw ? JSON.parse(raw) : { count: 0, ts: Date.now() };

  if (Date.now() - rl.ts > 60_000) {
    rl.count = 0;
    rl.ts = Date.now();
  }

  if (rl.count >= 5)
    return new Response(JSON.stringify({ error: "rate limited, try again later" }), {
      status: 429, headers: { "Content-Type": "application/json" }
    });

  rl.count++;
  await env.WH.put(ipKey, JSON.stringify(rl), { expirationTtl: 120 });

  const body = await request.json();
  const webhookUrl = body.u;

  if (!webhookUrl?.startsWith("https://discord.com/api/webhooks/"))
    return new Response(JSON.stringify({ error: "invalid webhook url" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });

  try {
    const check = await fetch(webhookUrl, { method: "GET" });
    if (!check.ok)
      return new Response(JSON.stringify({ error: "webhook not found or invalid" }), {
        status: 400, headers: { "Content-Type": "application/json" }
      });
  } catch {
    return new Response(JSON.stringify({ error: "could not verify webhook" }), {
      status: 400, headers: { "Content-Type": "application/json" }
    });
  }

  const token = genToken();
  await env.WH.put(`wh:${token}`, JSON.stringify({ u: webhookUrl, c: body.c }));

  return new Response(JSON.stringify({ token }), {
    headers: { "Content-Type": "application/json" }
  });
}
