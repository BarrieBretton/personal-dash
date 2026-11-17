
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/proxy-health") {
      return Response.json({
        status: "ok",
        service: "atmosphere-proxy"
      });
    }

    if (url.pathname.startsWith("/api/")) {
      if (request.method !== "GET") {
        return new Response("Method not allowed", { status: 405 });
      }

      if (!env.API_BASE_URL || !env.DASHBOARD_API_KEY) {
        return new Response("Proxy not configured", { status: 503 });
      }

      const upstream = new URL(
        url.pathname + url.search,
        env.API_BASE_URL
      );

      const headers = new Headers({
        "x-api-key": env.DASHBOARD_API_KEY,
        "Accept": "application/json"
      });

      try {
        return await fetch(upstream, {
          method: "GET",
          headers,
          redirect: "manual"
        });
      } catch {
        return Response.json(
          { error: "Backend unavailable" },
          { status: 502 }
        );
      }
    }

    return env.ASSETS.fetch(request);
  }
};
