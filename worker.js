const COOKIE_NAME = "mr_admin";
const SESSION_TIME = 86400;

function getCookie(request) {
  const cookieHeader = request.headers.get("Cookie") || "";

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const parts = cookie.trim().split("=");

    if (parts[0] === COOKIE_NAME) {
      return parts.slice(1).join("=");
    }
  }

  return null;
}

async function createToken(username, password) {

  const expires =
    Math.floor(Date.now() / 1000) + SESSION_TIME;

  const data =
    username + "|" + expires;

  const key =
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["sign"]
    );

  const signature =
    await crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(data)
    );

  let binary = "";

  for (
    const byte of new Uint8Array(signature)
  ) {
    binary += String.fromCharCode(byte);
  }

  const hash =
    btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

  return (
    btoa(data) +
    "." +
    hash
  );
}


async function verifyToken(
  token,
  username,
  password
) {

  try {

    const parts =
      token.split(".");

    if (parts.length !== 2) {
      return false;
    }

    const data =
      atob(parts[0]);

    const dataParts =
      data.split("|");

    const tokenUsername =
      dataParts[0];

    const expires =
      Number(dataParts[1]);

    if (
      tokenUsername !== username ||
      !expires ||
      expires < Math.floor(Date.now() / 1000)
    ) {
      return false;
    }

    const key =
      await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        {
          name: "HMAC",
          hash: "SHA-256"
        },
        false,
        ["sign"]
      );

    const signature =
      await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(data)
      );

    let binary = "";

    for (
      const byte of new Uint8Array(signature)
    ) {
      binary += String.fromCharCode(byte);
    }

    const expected =
      btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");

    return expected === parts[1];

  } catch {

    return false;

  }
}


export default {

  async fetch(request, env) {

    const url =
      new URL(request.url);


    /* =========================
       LOGIN
    ========================= */

    if (
      url.pathname === "/api/login" &&
      request.method === "POST"
    ) {

      try {

        if (
          !env.ADMIN_USERNAME ||
          !env.ADMIN_PASSWORD
        ) {

          return Response.json(
            {
              success: false,
              message:
                "Admin secrets are not configured."
            },
            { status: 500 }
          );

        }


        const body =
          await request.json();

        const username =
          String(body.username || "");

        const password =
          String(body.password || "");


        if (
          username !== env.ADMIN_USERNAME ||
          password !== env.ADMIN_PASSWORD
        ) {

          return Response.json(
            {
              success: false,
              message:
                "نام کاربری یا رمز عبور اشتباه است."
            },
            { status: 401 }
          );

        }


        const token =
          await createToken(
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
              "Content-Type":
                "application/json",

              "Set-Cookie":
                `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TIME}`
            }
          }
        );

      } catch {

        return Response.json(
          {
            success: false,
            message:
              "درخواست نامعتبر است."
          },
          { status: 400 }
        );

      }

    }


    /* =========================
       CHECK LOGIN
    ========================= */

    if (
      url.pathname === "/api/check-auth"
    ) {

      const token =
        getCookie(request);

      if (!token) {

        return Response.json({
          authenticated: false
        });

      }


      const valid =
        await verifyToken(
          token,
          env.ADMIN_USERNAME,
          env.ADMIN_PASSWORD
        );


      return Response.json({
        authenticated: valid
      });

    }


    /* =========================
       LOGOUT
    ========================= */

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

            "Content-Type":
              "application/json",

            "Set-Cookie":
              `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`

          }
        }
      );

    }


    /* =========================
       WEBSITE
    ========================= */

    return env.ASSETS.fetch(request);

  }

};
