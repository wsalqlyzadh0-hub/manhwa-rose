const COOKIE_NAME = "mr_admin";
const SESSION_TIME = 24 * 60 * 60; // 24 ساعت

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(value) {
  value = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  while (value.length % 4) {
    value += "=";
  }

  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function getKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );
}

async function createSession(username, password) {
  const expires = Math.floor(Date.now() / 1000) + SESSION_TIME;

  const data = `${username}|${expires}`;

  const key = await getKey(password);

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data)
  );

  return `${btoa(data)}.${toBase64Url(new Uint8Array(signature))}`;
}

async function verifySession(token, password, username) {
  try {
    const parts = token.split(".");

    if (parts.length !== 2) {
      return false;
    }

    const data = atob(parts[0]);
    const [tokenUsername, expiresText] = data.split("|");

    if (!tokenUsername || !expiresText) {
      return false;
    }

    if (tokenUsername !== username) {
      return false;
    }

    const expires = Number(expiresText);

    if (!Number.isFinite(expires) || expires < Math.floor(Date.now() / 1000)) {
      return false;
    }

    const key = await getKey(password);

    const expected = await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(data)
    );

    const actual = fromBase64Url(parts[1]);

    if (actual.length !== expected.byteLength) {
      return false;
    }

    const expectedBytes = new Uint8Array(expected);

    let difference = 0;

    for (let i = 0; i < expectedBytes.length; i++) {
      difference |= expectedBytes[i] ^ actual[i];
    }

    return difference === 0;

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

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...headers
    }
  });
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

        const body = await request.json();

        const username = String(body.username || "");
        const password = String(body.password || "");

        if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD) {
          return json(
            {
              success: false,
              message: "Admin secrets are not configured."
            },
            500
          );
        }

        if (
          username !== env.ADMIN_USERNAME ||
          password !== env.ADMIN_PASSWORD
        ) {
          return json(
            {
              success: false,
              message: "نام کاربری یا رمز عبور اشتباه است."
            },
            401
          );
        }

        const session = await createSession(
          env.ADMIN_USERNAME,
          env.ADMIN_PASSWORD
        );

        return json(
          {
            success: true
          },
          200,
          {
            "Set-Cookie":
              `${COOKIE_NAME}=${session}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TIME}`
          }
        );

      } catch {
        return json(
          {
            success: false,
            message: "درخواست نامعتبر است."
          },
          400
        );
      }
    }

    // -------------------------
    // CHECK AUTH
    // -------------------------

    if (url.pathname === "/api/check-auth") {

      const token = getCookie(request);

      if (!token) {
        return json({
          authenticated: false
        });
      }

      const valid = await verifySession(
        token,
        env.ADMIN_PASSWORD,
        env.ADMIN_USERNAME
      );

      return json({
        authenticated: valid
      });
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

      const valid = await verifySession(
        token,
        env.ADMIN_PASSWORD,
        env.ADMIN_USERNAME
      );

      if (!valid) {
        return Response.redirect(
          `${url.origin}/admin.html`,
          302
        );
      }
    }

    // -------------------------
    // SERVE WEBSITE FILES
    // -------------------------

    return env.ASSETS.fetch(request);
  }
};
