const genToken = () => {
  const chars = "abcdef0123456789";
  const arr = new Uint8Array(64);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => chars[b % 16]).join("");
};

export async function onRequestPost({ request, env }) {
  const body = await request.json();
  if (!body.u?.startsWith("https://discord.com/api/webhooks/"))
    return new Response(JSON.stringify({ error: "invalid webhook" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });

  const token = genToken();
  await env.WH.put(token, JSON.stringify({ u: body.u, c: body.c }));
  return new Response(JSON.stringify({ token }), {
    headers: { "Content-Type": "application/json" }
  });
}
