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
  if (!/^[a-f0-9]{64}$/.test(token)) return new Response("invalid token", { status: 400 });

  const raw = await env.WH.get(token);
  if (!raw) return new Response("not found", { status: 404 });

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

export async function onRequestGet() {
  return new Response("webhook protect proxy — POST only", { status: 200 });
}
