const COOKIE_NAME = "mr_admin";
const SESSION_TIME = 24 * 60 * 60;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // تست اتصال Secretها
    if (url.pathname === "/api/test-secret") {
      return Response.json({
        usernameConfigured: Boolean(env.ADMIN_USERNAME),
        passwordConfigured: Boolean(env.ADMIN_PASSWORD),
        usernameLength: env.ADMIN_USERNAME
          ? env.ADMIN_USERNAME.length
          : 0,
        passwordLength: env.ADMIN_PASSWORD
          ? env.ADMIN_PASSWORD.length
          : 0
      });
    }

    // ورود
    if (
      url.pathname === "/api/login" &&
      request.method === "POST"
    ) {
      try {
        const body = await request.json();

        const username = String(body.username || "");
        const password = String(body.password || "");

        // فقط طول‌ها را برمی‌گرداند؛ خود اطلاعات حساس را نشان نمی‌دهد
        return Response.json({
          usernameLength: username.length,
          passwordLength: password.length,
          savedUsernameLength: env.ADMIN_USERNAME
            ? env.ADMIN_USERNAME.length
            : 0,
          savedPasswordLength: env.ADMIN_PASSWORD
            ? env.ADMIN_PASSWORD.length
            : 0
        });

      } catch {
        return Response.json(
          {
            success: false,
            message: "درخواست نامعتبر است."
          },
          { status: 400 }
        );
      }
    }

    return env.ASSETS.fetch(request);
  }
};
