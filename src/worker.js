/* Gym Log — backup endpoint.
 *
 * Everything except /api/backup is served straight from the static files in the repo
 * and never reaches this code, so the app itself costs nothing to serve.
 *
 * POST /api/backup                 body = the same JSON an export produces
 * GET  /api/backup                 -> { backups: [ {date, bytes, at}, ... ] }
 * GET  /api/backup?date=YYYY-MM-DD -> that day's backup, verbatim
 *
 * The access code arrives in the x-gym-code header. It is hashed before being used as
 * a key, so the stored key names cannot be read back into the code itself.
 */

const KEEP_DAYS = 14;
const MAX_BODY  = 6 * 1024 * 1024;   // far above a realistic D; a wrong-shaped request stops here
const MIN_CODE  = 12;

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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/api/backup") return json({ error: "Not found" }, 404);

    const code = (request.headers.get("x-gym-code") || "").trim();
    if (code.length < MIN_CODE) return json({ error: "Missing or too-short access code" }, 401);
    if (!/^[A-Za-z0-9._-]{12,80}$/.test(code)) return json({ error: "Bad access code" }, 401);

    const h = await codeHash(code);
    const prefix = `bk:${h}:`;

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
