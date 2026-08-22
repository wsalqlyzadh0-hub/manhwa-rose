const COOKIE_NAME = "mr_admin";

async function createToken(username, password) {
  const data = `${username}:${Date.now()}`;

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
  const encoded = btoa(String.fromCharCode(...bytes));

  return btoa(`${data}.${encoded}`);
}

async function verifyToken(token, password) {
  try {
    const decoded = atob(token);
    const [data, signature] = decoded.split(".");

    if (!data || !signature) return false;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const expected = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(data)
    );

    const bytes = new Uint8Array(expected);
    const encoded = btoa(String.fromCharCode(...bytes));

    return signature === encoded;
  } catch {
    return false;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ورود ادمین
    if (url.pathname === "/api/login" && request.method === "POST") {
      const body = await request.json();

      if (
        body.username !== env.ADMIN_USERNAME ||
        body.password !== env.ADMIN_PASSWORD
      ) {
        return Response.json(
          { success: false, message: "نام کاربری یا رمز اشتباه است." },
          { status: 401 }
        );
      }

      const token = await createToken(
        env.ADMIN_USERNAME,
        env.ADMIN_PASSWORD
      );

      return new Response(
        JSON.stringify({ success: true }),
        {
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie":
              `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`
          }
        }
      );
    }

    // بررسی ورود
    if (url.pathname === "/api/check-auth") {
      const cookies = request.headers.get("Cookie") || "";
      const match = cookies.match(
        new RegExp(`${COOKIE_NAME}=([^;]+)`)
      );

      if (!match) {
        return Response.json(
          { authenticated: false },
          { status: 401 }
        );
      }

      const valid = await verifyToken(
        match[1],
        env.ADMIN_PASSWORD
      );

      return Response.json({
        authenticated: valid
      });
    }

    // نمایش فایل‌های سایت
    return env.ASSETS.fetch(request);
  }
};
