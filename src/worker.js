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

/* Only codes listed in the ALLOWED_CODES secret may use this Worker at all. Backups
   written under an unknown code would only waste storage, but model calls under an
   unknown code spend real money, so one gate covers both routes and there is a single
   place to revoke someone. Comma-separated, no quotes, exact match. */

/* The device sends its own local date. Filing by UTC put an evening backup in Mountain
   time under tomorrow's date and split a single day across two keys. Anything more than
   a day away from UTC is ignored, so a wrong clock cannot scatter keys across the store. */
function localDay(request) {
  const utc = new Date();
  const claimed = (request.headers.get("x-gym-date") || "").trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(claimed)) {
    const drift = Math.abs(new Date(claimed + "T12:00:00Z") - utc);
    if (drift < 36 * 3600 * 1000) return claimed;
  }
  return utc.toISOString().slice(0, 10);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const isAi = url.pathname === "/api/ai";
    if (url.pathname !== "/api/backup" && !isAi) return json({ error: "Not found" }, 404);

    const code = (request.headers.get("x-gym-code") || "").trim();
    if (code.length < MIN_CODE) return json({ error: "Missing or too-short access code" }, 401);
    if (!/^[A-Za-z0-9._-]{12,80}$/.test(code)) return json({ error: "Bad access code" }, 401);
    /* Two different faults, two different messages: an empty allowlist means the secret
       was never set, which looks identical to a wrong code unless it says so. */
    const list = (env.ALLOWED_CODES || "").split(",").map(s => s.trim()).filter(Boolean);
    if (!list.length) return json({ error: "No ALLOWED_CODES secret is set on the server" }, 403);
    if (!list.includes(code)) {
      return json({ error: `That access code is not on the list (server has ${list.length} code(s) configured)` }, 403);
    }

    const h = await codeHash(code);
    const prefix = `bk:${h}:`;

    /* ---- model calls ---- */
    if (isAi) {
      if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
      if (!env.ANTHROPIC_API_KEY) return json({ error: "No API key configured on the server" }, 500);

      /* A daily ceiling per code, so a code that leaks cannot drain the account before
         you notice. KV is eventually consistent, so this counts approximately — it is a
         spend guard, not an accounting record. */
      const capKey = `ai:${h}:${localDay(request)}`;
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
      /* A 2xx is streamed straight through untouched — that is the hot path and the body
         may be large. Anything else is read and relabelled, because the app looks for
         Anthropic's {error:{message}} and would otherwise report a blank reply. */
      if (upstream.ok) {
        return new Response(upstream.body, {
          status: upstream.status,
          headers: { "content-type": "application/json", "cache-control": "no-store" }
        });
      }
      const detail = (await upstream.text()).slice(0, 600);
      let message = `Anthropic returned ${upstream.status}`;
      try {
        const parsed = JSON.parse(detail);
        if (parsed && parsed.error && parsed.error.message) message += ": " + parsed.error.message;
      } catch (e) {
        if (detail) message += ": " + detail;
      }
      return new Response(JSON.stringify({ error: { message }, message }), {
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

      const date = localDay(request);

      /* Refuse a copy that is drastically smaller than the one already filed for the
         same day, unless the caller insists. A backup shrinking by half is almost always
         a reset or half-installed device rather than a real edit — and because same-day
         copies share a key, that write is destructive. The daily keys protect yesterday;
         this protects today. */
      if (request.headers.get("x-gym-force") !== "yes") {
        const existing = (await env.BACKUPS.list({ prefix })).keys
          .find(k => k.name === prefix + date);
        const had = existing && existing.metadata && existing.metadata.bytes;
        if (had && had > 20000 && body.length < had * 0.6) {
          return json({
            error: `Refused: this copy is ${Math.round(body.length/1024)} KB but today's stored copy is ${Math.round(had/1024)} KB. That much shrinkage usually means a device with no history. Send again with force if it is intentional.`,
            refused: "shrink", had, got: body.length
          }, 409);
        }
      }
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
