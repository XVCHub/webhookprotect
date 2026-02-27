const LOG_WEBHOOK = "https://webhookprotect.pages.dev/webhook/6c5c4038cbbce7df829c490104b1e74b1b7b5b0e29567e5510091e7d36c15a0e401602b6ed08097c740e6a342993a72487a232a54f9729605292acce397171f4";

const COLORS = { ban: 0xe74c3c, ratelimit: 0xe67e22, invalid: 0x3498db, abuse: 0x9b59b6 };

const TITLES = {
  ban: "🔨 IP Banned",
  ban_extended: "🔨 Ban Extended",
  ratelimit: "⚠️ Rate Limited",
  invalid_token: "🔍 Invalid Token Attempt",
  invalid_webhook: "❌ Invalid Webhook",
  duplicate_webhook: "🔁 Duplicate Webhook",
  abuse: "🚨 Abuse Detected",
};

export const notify = async (type, ip, extra = {}) => {
  const fields = [{ name: "IP", value: `\`${ip}\``, inline: true }];
  if (extra.tier) fields.push({ name: "Tier", value: `v${extra.tier}`, inline: true });
  if (extra.remaining) fields.push({ name: "Duration", value: `${extra.remaining}s`, inline: true });
  if (extra.token) fields.push({ name: "Token", value: `\`${extra.token.slice(0, 16)}...\``, inline: false });
  if (extra.url) fields.push({ name: "URL", value: `\`${extra.url.slice(0, 50)}\``, inline: false });
  if (extra.abuse_count) fields.push({ name: "Abuse Count", value: `${extra.abuse_count}/5`, inline: true });
  if (extra.ban_count) fields.push({ name: "Ban #", value: `${extra.ban_count}`, inline: true });
  if (extra.endpoint) fields.push({ name: "Endpoint", value: extra.endpoint, inline: true });

  const colorKey = type.startsWith("ban") ? "ban" : type.startsWith("rate") ? "ratelimit" : type.includes("token") ? "invalid" : "abuse";

  await fetch(LOG_WEBHOOK, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      embeds: [{
        title: TITLES[type] || type,
        color: COLORS[colorKey],
        fields,
        timestamp: new Date().toISOString(),
        footer: { text: "webhook protect" }
      }]
    })
  }).catch(() => {});
};

export const RL_DURATIONS = [120, 240, 360];

export const getIP = (req) =>
  req.headers.get("CF-Connecting-IP") ||
  req.headers.get("X-Forwarded-For")?.split(",")[0].trim() ||
  "unknown";

export const checkBan = async (env, ip) => {
  const now = Date.now();
  const banRaw = await env.WH.get(`ban:${ip}`);
  if (!banRaw) return null;
  const ban = JSON.parse(banRaw);
  if (now < ban.until) return { remaining: Math.ceil((ban.until - now) / 1000), count: ban.count };
  await env.WH.delete(`ban:${ip}`);
  return null;
};

export const trackAbuse = async (env, ip, type, extra = {}) => {
  const now = Date.now();
  const key = `abuse:${ip}`;
  const banKey = `ban:${ip}`;

  const raw = await env.WH.get(key);
  const a = raw ? JSON.parse(raw) : { n: 0, t: now };
  if (now - a.t > 300_000) { a.n = 0; a.t = now; }
  a.n++;
  await env.WH.put(key, JSON.stringify(a), { expirationTtl: 600 });

  await notify(type, ip, { abuse_count: a.n, ...extra });

  if (a.n >= 5) {
    const banRaw = await env.WH.get(banKey);
    if (banRaw) {
      const ban = JSON.parse(banRaw);
      ban.count = (ban.count || 1) + 1;
      const newDur = Math.min(3600 * ban.count, 86400);
      ban.until = now + newDur * 1000;
      await env.WH.put(banKey, JSON.stringify(ban), { expirationTtl: newDur + 10 });
      await notify("ban_extended", ip, { remaining: newDur, ban_count: ban.count });
    } else {
      await env.WH.put(banKey, JSON.stringify({ until: now + 3_600_000, count: 1 }), { expirationTtl: 3610 });
      await notify("ban", ip, { remaining: 3600, ban_count: 1 });
    }
    await env.WH.delete(key);
  }
};

export const checkRateLimit = async (env, ip, prefix, max) => {
  const now = Date.now();

  const punishRaw = await env.WH.get(`rlpunish:${prefix}:${ip}`);
  if (punishRaw) {
    const p = JSON.parse(punishRaw);
    if (now < p.until) return { blocked: true, remaining: Math.ceil((p.until - now) / 1000), tier: p.tier };
    await env.WH.delete(`rlpunish:${prefix}:${ip}`);
  }

  const rlRaw = await env.WH.get(`rl:${prefix}:${ip}`);
  const rl = rlRaw ? JSON.parse(rlRaw) : { n: 0, t: now };
  if (now - rl.t > 60_000) { rl.n = 0; rl.t = now; }

  if (rl.n >= max) {
    const histRaw = await env.WH.get(`rlhist:${prefix}:${ip}`);
    const hist = histRaw ? JSON.parse(histRaw) : { hits: 0, last: now };
    if (now - hist.last > 600_000) hist.hits = 0;
    hist.hits++;
    hist.last = now;
    await env.WH.put(`rlhist:${prefix}:${ip}`, JSON.stringify(hist), { expirationTtl: 700 });

    const tier = Math.min(hist.hits, 3);
    const dur = RL_DURATIONS[tier - 1];
    await env.WH.put(`rlpunish:${prefix}:${ip}`, JSON.stringify({ until: now + dur * 1000, tier }), { expirationTtl: dur + 10 });
    await env.WH.delete(`rl:${prefix}:${ip}`);
    return { blocked: true, remaining: dur, tier };
  }

  rl.n++;
  await env.WH.put(`rl:${prefix}:${ip}`, JSON.stringify(rl), { expirationTtl: 65 });
  return { blocked: false };
};
