const COOKIE_NAME = "mr_admin";
const SESSION_TIME = 24 * 60 * 60;

function getCookie(request) {
  const cookies = request.headers.get("Cookie") || "";

  for (const cookie of cookies.split(";")) {
    const [name, ...parts] = cookie.trim().split("=");

    if (name === COOKIE_NAME) {
      return parts.join("=");
    }
  }

  return null;
}

async function createToken(username, password) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_TIME;
  const data = `${username}|${expires}`;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
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

  const signatureText = btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return `${btoa(data)}.${signatureText}`;
}

async function verifyToken(token, username, password) {
  try {
    const [encodedData, receivedSignature] = token.split(".");

    if (!encodedData || !receivedSignature) {
      return false;
    }

    const data = atob(encodedData);
    const [tokenUsername, expiresText] = data.split("|");

    if (tokenUsername !== username) {
      return false;
    }

    const expires = Number(expiresText);

    if (!expires || expires < Math.floor(Date.now() / 1000)) {
      return false;
    }

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );

    const signature = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(data)
    );

    let binary = "";

    for (const byte of new Uint8Array(signature)) {
      binary += String.fromCharCode(byte);
    }

    const expectedSignature = btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    return expectedSignature === receivedSignature;

  } catch {
    return false;
  }
}

export default {
  async fetch(request, env) {

    const url = new URL(request.url);

    // -------------------------
    // LOGIN
    // -------------------------

    if (
      url.pathname === "/api/login" &&
      request.method === "POST"
    ) {
      try {

        if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD) {
          return Response.json(
            {
              success: false,
              message: "Admin secrets are not configured."
            },
            { status: 500 }
          );
        }

        const body = await request.json();

        const username = String(body.username || "");
        const password = String(body.password || "");

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

        const token = await createToken(
          env.ADMIN_USERNAME,
          env.ADMIN_PASSWORD
        );

        return new Response(
          JSON.stringify({
            success: true
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
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

    // -------------------------
    // CHECK AUTH
    // -------------------------

    if (url.pathname === "/api/check-auth") {

      const token = getCookie(request);

      if (!token) {
        return Response.json({
          authenticated: false
        });
      }

      const authenticated = await verifyToken(
        token,
        env.ADMIN_USERNAME,
        env.ADMIN_PASSWORD
      );

      return Response.json({
        authenticated
      });
    }

    // -------------------------
    // LOGOUT
    // -------------------------

    if (
      url.pathname === "/api/logout" &&
      request.method === "POST"
    ) {

      return new Response(
        JSON.stringify({
          success: true
        }),
        {
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie":
              `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
          }
        }
      );
    }

    // -------------------------
    // PROTECT ADMIN PANEL
    // -------------------------

    if (url.pathname === "/admin-panel.html") {

      const token = getCookie(request);

      if (!token) {
        return Response.redirect(
          `${url.origin}/admin.html`,
          302
        );
      }

      const authenticated = await verifyToken(
        token,
        env.ADMIN_USERNAME,
        env.ADMIN_PASSWORD
      );

      if (!authenticated) {
        return Response.redirect(
          `${url.origin}/admin.html`,
          302
        );
      }
    }

    // -------------------------
    // WEBSITE FILES
    // -------------------------

    return env.ASSETS.fetch(request);
  }
};
