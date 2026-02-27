const genToken = () => {
  const arr = new Uint8Array(64);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, "0")).join("");
};

const getIP = (req) =>
  req.headers.get("CF-Connecting-IP") ||
  req.headers.get("X-Forwarded-For")?.split(",")[0].trim() ||
  "unknown";

export async function onRequestPost({ request, env }) {
  const ip = getIP(request);
  const rlKey = `rl:create:${ip}`;
  const rlRaw = await env.WH.get(rlKey);
  const rl = rlRaw ? JSON.parse(rlRaw) : { n: 0, t: Date.now() };
  if (Date.now() - rl.t > 60_000) { rl.n = 0; rl.t = Date.now(); }
  if (rl.n >= 5)
    return new Response(JSON.stringify({ error: "rate limited, try again later" }), {
      status: 429, headers: { "Content-Type": "application/json" }
    });
  rl.n++;
  await env.WH.put(rlKey, JSON.stringify(rl), { expirationTtl: 120 });

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
