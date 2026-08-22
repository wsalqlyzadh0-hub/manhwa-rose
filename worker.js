export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/test-secret") {
      return new Response(
        JSON.stringify({
          username: Boolean(env.ADMIN_USERNAME),
          password: Boolean(env.ADMIN_PASSWORD)
        }),
        {
          headers: {
            "Content-Type": "application/json"
          }
        }
      );
    }

    return env.ASSETS.fetch(request);
  }
};
