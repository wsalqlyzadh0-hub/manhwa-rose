const COOKIE_NAME = "mr_admin";
const SESSION_TIME = 24 * 60 * 60;

async function makeToken(username, password) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_TIME;
  const data = `${username}|${expires}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  const bytes = new Uint8Array(signature);

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  const encoded = btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return `${btoa(data)}.${encoded}`;
}

async function checkToken(token, username, password) {
  try {
    const parts = token.split(".");

    if (parts.length !== 2) return false;

    const data = atob(parts[0]);
    const [tokenUsername, expiresText] = data.split("|");

    if (tokenUsername !== username) return false;

    const expires = Number(expiresText);

    if (!expires || expires < Math.floor(Date.now() / 1000)) {
      return false;
    }

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(data)
    );

    const bytes = new Uint8Array(signature);

    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }

    const expected = btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    return expected === parts[1];

  } catch {
    return false;
  }
}

function getCookie(request) {
  const cookies = request.headers.get("Cookie") || "";

  const match = cookies.match(
    new RegExp(`${COOKIE_NAME}=([^;]+)`)
  );

  return match ? match[1] : null;
}

export default {
  async fetch(request, env) {

    const url = new URL(request.url);if (url.pathname === "/api/test-secret") {
  return Response.json({
    username: Boolean(env.ADMIN_USERNAME),
    password: Boolean(env.ADMIN_PASSWORD)
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

        if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD) {
          return Response.json(
            {
              success: false,
              message: "Admin secrets are not configured."
            },
            { status: 500 }
          );
        }

        if (
          username !== env.ADMIN_USERNAME ||
          password !== env.ADMIN_PASSWORD
        ) {
          return Response.json(
            {
              success: false,
              message: "نام کاربری یا رمز عبور اشتباه است."
            },
            { status: 401 }
          );
        }

        const token = await makeToken(
          env.ADMIN_USERNAME,
          env.ADMIN_PASSWORD
        );

        return Response.json(
          { success: true },
          {
            headers: {
              "Set-Cookie":
                `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TIME}`
            }
          }
        );

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

    // بررسی ورود
    if (url.pathname === "/api/check-auth") {

      const token = getCookie(request);

      if (!token) {
        return Response.json({
          authenticated: false
        });
      }

      const valid = await checkToken(
        token,
        env.ADMIN_USERNAME,
        env.ADMIN_PASSWORD
      );

      return Response.json({
        authenticated: valid
      });
    }

    // محافظت از پنل
    if (url.pathname === "/admin-panel.html") {

      const token = getCookie(request);

      const valid = token
        ? await checkToken(
            token,
            env.ADMIN_USERNAME,
            env.ADMIN_PASSWORD
          )
        : false;

      if (!valid) {
        return Response.redirect(
          `${url.origin}/admin.html`,
          302
        );
      }
    }

    // فایل‌های سایت
    return env.ASSETS.fetch(request);
  }
};
