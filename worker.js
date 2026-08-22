export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/test") {
      return new Response("Worker OK", {
        headers: {
          "Content-Type": "text/plain; charset=UTF-8"
        }
      });
    }

    return env.ASSETS.fetch(request);
  }
};
