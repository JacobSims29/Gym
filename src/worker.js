/* Gym Log — backup and model endpoints.
 *
 * Everything except /api/* is served straight from the static files in the repo and
 * never reaches this code, so the app itself costs nothing to serve.
 *
 * POST /api/backup                 body = the same JSON an export produces
 * GET  /api/backup                 -> { backups: [ {date, bytes, at}, ... ] }
 * GET  /api/backup?date=YYYY-MM-DD -> that day's backup, verbatim
 * POST /api/ai                     body = an Anthropic /v1/messages request, forwarded
 *                                  with the key held here, capped per day
 *
 * The access code arrives in the x-gym-code header and must appear in ALLOWED_CODES.
 * It is hashed before being used as a key, so the stored key names cannot be read back
 * into the code itself.
 *
 * Secrets to set (Workers -> Settings -> Variables and Secrets, type Secret):
 *   ANTHROPIC_API_KEY   your Anthropic key
 *   ALLOWED_CODES       comma-separated access codes, one per person
 */

const KEEP_DAYS = 14;
const MAX_BODY  = 6 * 1024 * 1024;   // far above a realistic D; a wrong-shaped request stops here
const MIN_CODE  = 12;
const AI_PER_DAY = 60;               // hard ceiling on model calls per code per day

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" }
  });

async function codeHash(code) {
  const bytes = new TextEncoder().encode("gymlog:v1:" + code);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

/* Only codes you have listed may use this Worker at all. Backups written under an
   unknown code would only waste storage, but model calls under an unknown code spend
   real money, so the same gate covers both and there is one place to revoke someone. */
function allowed(code, env) {
  const list = (env.ALLOWED_CODES || "").split(",").map(s => s.trim()).filter(Boolean);
  return list.includes(code);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const isAi = url.pathname === "/api/ai";
    if (url.pathname !== "/api/backup" && !isAi) return json({ error: "Not found" }, 404);

    const code = (request.headers.get("x-gym-code") || "").trim();
    if (code.length < MIN_CODE) return json({ error: "Missing or too-short access code" }, 401);
    if (!/^[A-Za-z0-9._-]{12,80}$/.test(code)) return json({ error: "Bad access code" }, 401);
    if (!allowed(code, env)) return json({ error: "That access code is not recognised" }, 403);

    const h = await codeHash(code);
    const prefix = `bk:${h}:`;

    /* ---- model calls ---- */
    if (isAi) {
      if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
      if (!env.ANTHROPIC_API_KEY) return json({ error: "No API key configured on the server" }, 500);

      /* A daily ceiling per code, so a code that leaks cannot drain the account before
         you notice. KV is eventually consistent, so this counts approximately — it is a
         spend guard, not an accounting record. */
      const day = new Date().toISOString().slice(0, 10);
      const capKey = `ai:${h}:${day}`;
      const used = Number(await env.BACKUPS.get(capKey)) || 0;
      if (used >= AI_PER_DAY) {
        return json({ error: `Daily limit of ${AI_PER_DAY} model calls reached for this access code.` }, 429);
      }
      await env.BACKUPS.put(capKey, String(used + 1), { expirationTtl: 2 * 86400 });

      /* The body is passed straight through rather than read into memory: a meal scan
         carries several megabytes of base64 image, and parsing that here would blow the
         free plan's 10 ms of CPU. Streaming it costs almost nothing. */
      const upstream = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": env.ANTHROPIC_API_KEY,
          "anthropic-version": "2023-06-01"
        },
        body: request.body
      });
      return new Response(upstream.body, {
        status: upstream.status,
        headers: { "content-type": "application/json", "cache-control": "no-store" }
      });
    }

    /* ---- backups ---- */
    if (request.method === "POST") {
      const body = await request.text();
      if (body.length > MAX_BODY) return json({ error: "Backup too large" }, 413);

      /* A cheap shape check on the first slice rather than a full JSON.parse. Parsing a
         multi-megabyte blob can exceed the free plan's 10 ms of CPU per request, and the
         app is the thing that guarantees the contents anyway — this only needs to reject
         a request that plainly is not a gym backup. */
      if (!body.slice(0, 300).includes('"app":"gymlog"')) {
        return json({ error: "Not a gym backup" }, 400);
      }

      const date = new Date().toISOString().slice(0, 10);
      /* One key per day, expiring on its own after a fortnight. Today's key is rewritten
         through the day; earlier days are frozen. That is what makes a bad migration
         survivable: it can only spoil today. */
      await env.BACKUPS.put(prefix + date, body, {
        expirationTtl: KEEP_DAYS * 86400,
        metadata: { bytes: body.length, at: new Date().toISOString() }
      });
      return json({ ok: true, date, bytes: body.length });
    }

    if (request.method === "GET") {
      const date = url.searchParams.get("date");
      if (date) {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return json({ error: "Bad date" }, 400);
        const value = await env.BACKUPS.get(prefix + date);
        if (value === null) return json({ error: "No backup for that date" }, 404);
        return new Response(value, {
          headers: { "content-type": "application/json", "cache-control": "no-store" }
        });
      }
      const listed = await env.BACKUPS.list({ prefix });
      const backups = listed.keys
        .map(k => ({
          date:  k.name.slice(prefix.length),
          bytes: (k.metadata && k.metadata.bytes) || null,
          at:    (k.metadata && k.metadata.at) || null
        }))
        .sort((a, b) => (a.date < b.date ? 1 : -1));
      return json({ backups });
    }

    return json({ error: "Method not allowed" }, 405);
  }
};
