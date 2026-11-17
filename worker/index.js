
const SESSION_SECONDS = 7 * 24 * 60 * 60;
const COOKIE_NAME = "atmosphere_session";

function unauthorized() {
  return Response.json(
    { detail: "Authentication required" },
    { status: 401, headers: { "Cache-Control": "no-store" } }
  );
}

function loginPage(message = "") {
  const safeMessage = message
    ? "<p style='color:#fca5a5'>Incorrect password</p>"
    : "";

  return new Response(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Atmosphere · Sign in</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;
background:#090e17;color:#f1f5fa;font-family:system-ui,sans-serif}
main{width:min(390px,calc(100% - 32px));padding:36px;
background:#121b29;border:1px solid #243246;border-radius:20px}
h1{margin:0 0 8px;font-size:28px}
p{color:#94a3b8;font-size:14px}
input,button{width:100%;padding:14px;border-radius:10px;font:inherit}
input{background:#090e17;color:white;border:1px solid #35455b;
margin:18px 0 12px}
button{background:#66e1ba;color:#07111c;border:0;font-weight:700;
cursor:pointer}
</style>
</head>
<body>
<main>
<h1>Atmosphere.</h1>
<p>Your personal command center.</p>
${safeMessage}
<form action="/login" method="POST">
<input type="password" name="password" placeholder="Dashboard password"
required autofocus>
<button type="submit">Sign in</button>
</form>
</main>
</body>
</html>`, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-")
    .replace(/\//g, "_").replace(/=+$/, "");
}

async function signature(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const result = await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(payload)
  );

  return base64url(new Uint8Array(result));
}

async function validSession(request, env) {
  if (!env.SESSION_SECRET) return false;

  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(
    /(?:^|;\s*)atmosphere_session=([^;]+)/
  );

  if (!match) return false;

  const token = match[1];
  const separator = token.lastIndexOf(".");
  if (separator < 1) return false;

  const payload = token.slice(0, separator);
  const supplied = token.slice(separator + 1);
  const expected = await signature(payload, env.SESSION_SECRET);

  if (supplied.length !== expected.length) return false;

  let difference = 0;
  for (let i = 0; i < expected.length; i++) {
    difference |= supplied.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  if (difference !== 0) return false;

  const expiry = Number(payload);
  return Number.isSafeInteger(expiry) &&
    expiry > Math.floor(Date.now() / 1000);
}

function sameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (origin) return origin === new URL(request.url).origin;

  const referer = request.headers.get("Referer");
  return Boolean(referer) &&
    new URL(referer).origin === new URL(request.url).origin;
}

function secureHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "no-referrer");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/api/proxy-health") {
      return Response.json({
        status: "ok",
        service: "atmosphere-proxy"
      });
    }

    // Fail closed if required secrets are missing.
    if (!env.DASHBOARD_PASSWORD || !env.SESSION_SECRET) {
      return new Response("Dashboard authentication not configured", {
        status: 503
      });
    }

    if (path === "/login" && request.method === "GET") {
      return loginPage();
    }

    if (path === "/login" && request.method === "POST") {
      if (!sameOrigin(request)) {
        return new Response("Forbidden", { status: 403 });
      }

      const form = await request.formData();
      const password = String(form.get("password") || "");

      if (password !== env.DASHBOARD_PASSWORD) {
        return loginPage("invalid");
      }

      const expiry = Math.floor(Date.now() / 1000) +
        SESSION_SECONDS;
      const payload = String(expiry);
      const sig = await signature(payload, env.SESSION_SECRET);

      return new Response(null, {
        status: 303,
        headers: {
          "Location": "/",
          "Set-Cookie":
            `${COOKIE_NAME}=${payload}.${sig}; ` +
            `Path=/; HttpOnly; Secure; SameSite=Lax; ` +
            `Max-Age=${SESSION_SECONDS}`,
          "Cache-Control": "no-store"
        }
      });
    }

    if (path === "/logout") {
      return new Response(null, {
        status: 303,
        headers: {
          "Location": "/login",
          "Set-Cookie":
            `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; ` +
            "SameSite=Lax; Max-Age=0",
          "Cache-Control": "no-store"
        }
      });
    }

    if (!(await validSession(request, env))) {
      if (path.startsWith("/api/")) return unauthorized();
      return Response.redirect(new URL("/login", request.url), 302);
    }

    if (path.startsWith("/api/")) {
      if (request.method !== "GET") {
        return new Response("Method not allowed", { status: 405 });
      }

      if (!["/api/devices", "/api/history"].includes(path)) {
        return new Response("Not found", { status: 404 });
      }

      if (!env.API_BASE_URL || !env.DASHBOARD_API_KEY) {
        return new Response("Backend not configured", { status: 503 });
      }

      const upstream = new URL(
        path + url.search, env.API_BASE_URL
      );

      if (upstream.protocol !== "https:") {
        return new Response("Invalid backend URL", { status: 503 });
      }

      try {
        const result = await fetch(upstream.toString(), {
          method: "GET",
          headers: {
            "Authorization": `Bearer ${env.DASHBOARD_API_KEY}`,
            "Accept": "application/json"
          },
          redirect: "manual"
        });

        return secureHeaders(result);
      } catch {
        return Response.json(
          { detail: "Backend unavailable" },
          { status: 502 }
        );
      }
    }

    return secureHeaders(await env.ASSETS.fetch(request));
  }
};
