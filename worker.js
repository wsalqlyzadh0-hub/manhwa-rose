// ============================================================
// MANHWA ROSE - CLOUDFLARE WORKER
// Admin Panel + Google Login + User Accounts + Manga API
// ============================================================

const ADMIN_COOKIE = "mr_admin";
const USER_COOKIE = "mr_user";
const STATE_COOKIE = "mr_google_state";

const ADMIN_SESSION_TIME = 24 * 60 * 60;
const USER_SESSION_TIME = 30 * 24 * 60 * 60;
const GOOGLE_STATE_TIME = 10 * 60;

// ------------------------------------------------------------
// BASIC HELPERS
// ------------------------------------------------------------

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      ...extraHeaders,
    },
  });
}

function unauthorized(message = "Unauthorized") {
  return json(
    {
      success: false,
      error: message,
    },
    401
  );
}

function badRequest(message = "Bad Request") {
  return json(
    {
      success: false,
      error: message,
    },
    400
  );
}

function notFound(message = "Not Found") {
  return json(
    {
      success: false,
      error: message,
    },
    404
  );
}

function serverError(message = "Server Error") {
  return json(
    {
      success: false,
      error: message,
    },
    500
  );
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...valueParts] = cookie.trim().split("=");

    if (key === name) {
      return decodeURIComponent(valueParts.join("="));
    }
  }

  return null;
}

function randomString(length = 32) {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  const array = new Uint8Array(length);

  crypto.getRandomValues(array);

  let result = "";

  for (let i = 0; i < array.length; i++) {
    result += chars[array[i] % chars.length];
  }

  return result;
}

function base64UrlEncode(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");

  while (str.length % 4) {
    str += "=";
  }

  const binary = atob(str);

  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function sha256(text) {
  const data = new TextEncoder().encode(text);

  const hash = await crypto.subtle.digest("SHA-256", data);

  return base64UrlEncode(new Uint8Array(hash));
}

// ------------------------------------------------------------
// CORS
// ------------------------------------------------------------

function getAllowedOrigin(request, env) {
  const origin = request.headers.get("Origin");

  const frontend =
    env.FRONTEND_URL ||
    "https://wsalqlyzadh0-hub.github.io/manhwa-rose/";

  if (!origin) {
    return frontend.replace(/\/$/, "");
  }

  if (
    origin === "https://wsalqlyzadh0-hub.github.io" ||
    origin === "https://wsalqlyzadh0-hub.github.io/manhwa-rose" ||
    origin === "http://localhost:3000" ||
    origin === "http://127.0.0.1:5500"
  ) {
    return origin;
  }

  return frontend.replace(/\/$/, "");
}

function corsHeaders(request, env) {
  return {
    "Access-Control-Allow-Origin": getAllowedOrigin(request, env),
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, X-Requested-With",
    "Access-Control-Allow-Methods":
      "GET, POST, PUT, DELETE, OPTIONS",
    "Vary": "Origin",
  };
}

function withCors(response, request, env) {
  const headers = new Headers(response.headers);

  const cors = corsHeaders(request, env);

  for (const [key, value] of Object.entries(cors)) {
    headers.set(key, value);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// ------------------------------------------------------------
// ADMIN AUTH
// ------------------------------------------------------------

function createAdminToken() {
  return randomString(64);
}

async function isAdminAuthenticated(request, env) {
  const token = getCookie(request, ADMIN_COOKIE);

  if (!token) {
    return false;
  }

  // Admin token is stored inside the cookie.
  // We validate it against a signed token generated from the
  // configured admin credentials.
  const expected = await sha256(
    `${env.ADMIN_USERNAME || ""}:${env.ADMIN_PASSWORD || ""}:manhwa-rose-admin`
  );

  return token === expected;
}

async function createAdminSessionToken(env) {
  return await sha256(
    `${env.ADMIN_USERNAME || ""}:${env.ADMIN_PASSWORD || ""}:manhwa-rose-admin`
  );
}

function adminCookie(token) {
  return [
    `${ADMIN_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
    `Max-Age=${ADMIN_SESSION_TIME}`,
  ].join("; ");
}

function clearAdminCookie() {
  return [
    `${ADMIN_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=None",
    "Max-Age=0",
  ].join("; ");
}

// ------------------------------------------------------------
// USER SESSION
// ------------------------------------------------------------

async function createUserSession(env, userId) {
  const sessionId = randomString(64);

  const expiresAt = new Date(
    Date.now() + USER_SESSION_TIME * 1000
  ).toISOString();

  await env.DB.prepare(
    `
      INSERT INTO sessions
      (id, user_id, expires_at)
      VALUES (?, ?, ?)
    `
  )
    .bind(sessionId, userId, expiresAt)
    .run();

  return {
    sessionId,
    expiresAt,
  };
}

async function getCurrentUser(request, env) {
  const sessionId = getCookie(request, USER_COOKIE);

  if (!sessionId) {
    return null;
  }

  const result = await env.DB.prepare(
    `
      SELECT
        users.id,
        users.google_sub,
        users.email,
        users.username,
        users.name,
        users.avatar_url,
        users.plan,
        users.vip_expires_at,
        users.rose_coins,
        users.xp,
        users.level,
        users.created_at,
        users.last_login_at,
        sessions.expires_at
      FROM sessions
      INNER JOIN users
        ON users.id = sessions.user_id
      WHERE sessions.id = ?
      LIMIT 1
    `
  )
    .bind(sessionId)
    .first();

  if (!result) {
    return null;
  }

  if (new Date(result.expires_at).getTime() <= Date.now()) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE id = ?"
    )
      .bind(sessionId)
      .run();

    return null;
  }

  return result;
}

function userCookie(sessionId) {
  return [
    `${USER_COOKIE}=${encodeURIComponent(sessionId)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${USER_SESSION_TIME}`,
  ].join("; ");
}

function clearUserCookie() {
  return [
    `${USER_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0",
  ].join("; ");
}

// ------------------------------------------------------------
// GOOGLE OAUTH
// ------------------------------------------------------------

function googleAuthorizeUrl(env, state) {
  const params = new URLSearchParams();

  params.set(
    "client_id",
    env.GOOGLE_CLIENT_ID
  );

  params.set(
    "redirect_uri",
    "https://manhwa-rose.wsalqlyzadh0.workers.dev/auth/google/callback"
  );

  params.set(
    "response_type",
    "code"
  );

  params.set(
    "scope",
    "openid email profile"
  );

  params.set(
    "state",
    state
  );

  params.set(
    "access_type",
    "online"
  );

  params.set(
    "prompt",
    "select_account"
  );

  return (
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    params.toString()
  );
}

function googleStateCookie(state) {
  return [
    `${STATE_COOKIE}=${encodeURIComponent(state)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${GOOGLE_STATE_TIME}`,
  ].join("; ");
}

function clearGoogleStateCookie() {
  return [
    `${STATE_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0",
  ].join("; ");
}

async function exchangeGoogleCode(code, env) {
  const body = new URLSearchParams();

  body.set("code", code);
  body.set("client_id", env.GOOGLE_CLIENT_ID);
  body.set("client_secret", env.GOOGLE_CLIENT_SECRET);
  body.set(
    "redirect_uri",
    "https://manhwa-rose.wsalqlyzadh0.workers.dev/auth/google/callback"
  );
  body.set("grant_type", "authorization_code");

  const response = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded",
      },
      body,
    }
  );

  if (!response.ok) {
    const text = await response.text();

    throw new Error(
      `Google token exchange failed: ${text}`
    );
  }

  return await response.json();
}

async function getGoogleUser(accessToken) {
  const response = await fetch(
    "https://www.googleapis.com/oauth2/v3/userinfo",
    {
      headers: {
        Authorization:
          `Bearer ${accessToken}`,
      },
    }
  );

  if (!response.ok) {
    const text = await response.text();

    throw new Error(
      `Google userinfo failed: ${text}`
    );
  }

  return await response.json();
}

// ------------------------------------------------------------
// GOOGLE LOGIN
// ------------------------------------------------------------

async function handleGoogleLogin(request, env) {
  if (
    !env.GOOGLE_CLIENT_ID ||
    !env.GOOGLE_CLIENT_SECRET
  ) {
    return json(
      {
        success: false,
        error:
          "Google OAuth is not configured.",
      },
      500
    );
  }

  const state = randomString(32);

  const url = googleAuthorizeUrl(
    env,
    state
  );

  return new Response(null, {
    status: 302,
    headers: {
      Location: url,
      "Set-Cookie":
        googleStateCookie(state),
    },
  });
}

// ------------------------------------------------------------
// GOOGLE CALLBACK
// ------------------------------------------------------------

async function handleGoogleCallback(
  request,
  env
) {
  const url = new URL(request.url);

  const code = url.searchParams.get(
    "code"
  );

  const state = url.searchParams.get(
    "state"
  );

  const error = url.searchParams.get(
    "error"
  );

  if (error) {
    return new Response(
      `Google login failed: ${error}`,
      {
        status: 400,
        headers: {
          "Content-Type":
            "text/plain; charset=UTF-8",
        },
      }
    );
  }

  if (!code || !state) {
    return new Response(
      "Missing Google OAuth parameters.",
      {
        status: 400,
      }
    );
  }

  const savedState = getCookie(
    request,
    STATE_COOKIE
  );

  if (
    !savedState ||
    savedState !== state
  ) {
    return new Response(
      "Invalid OAuth state.",
      {
        status: 400,
      }
    );
  }

  try {
    const tokenData =
      await exchangeGoogleCode(
        code,
        env
      );

    if (!tokenData.access_token) {
      throw new Error(
        "Google did not return an access token."
      );
    }

    const googleUser =
      await getGoogleUser(
        tokenData.access_token
      );

    if (!googleUser.sub) {
      throw new Error(
        "Google account ID was not returned."
      );
    }

    if (
      !googleUser.email
    ) {
      throw new Error(
        "Google account email was not returned."
      );
    }

    const googleSub =
      googleUser.sub;

    const email =
      googleUser.email;

    const name =
      googleUser.name ||
      googleUser.given_name ||
      "Manhwa Rose User";

    const avatar =
      googleUser.picture ||
      null;

    let user =
      await env.DB.prepare(
        `
          SELECT *
          FROM users
          WHERE google_sub = ?
          LIMIT 1
        `
      )
        .bind(googleSub)
        .first();

    if (!user) {
      user =
        await env.DB.prepare(
          `
            SELECT *
            FROM users
            WHERE email = ?
            LIMIT 1
          `
        )
          .bind(email)
          .first();
    }

    if (user) {
      await env.DB.prepare(
        `
          UPDATE users
          SET
            google_sub = ?,
            name = ?,
            avatar_url = ?,
            last_login_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `
      )
        .bind(
          googleSub,
          name,
          avatar,
          user.id
        )
        .run();
    } else {
      let username =
        email
          .split("@")[0]
          .replace(
            /[^a-zA-Z0-9_]/g,
            ""
          )
          .slice(0, 30);

      if (!username) {
        username =
          "rose_" +
          randomString(8).toLowerCase();
      }

      const insert =
        await env.DB.prepare(
          `
            INSERT INTO users
            (
              google_sub,
              email,
              username,
              name,
              avatar_url,
              plan,
              rose_coins,
              xp,
              level,
              last_login_at
            )
            VALUES
            (?, ?, ?, ?, ?, 'normal', 0, 0, 1, CURRENT_TIMESTAMP)
          `
        )
          .bind(
            googleSub,
            email,
            username,
            name,
            avatar
          )
          .run();

      user =
        await env.DB.prepare(
          `
            SELECT *
            FROM users
            WHERE id = ?
            LIMIT 1
          `
        )
          .bind(
            insert.meta.last_row_id
          )
          .first();
    }

    const session =
      await createUserSession(
        env,
        user.id
      );

    const frontend =
      env.FRONTEND_URL ||
      "https://wsalqlyzadh0-hub.github.io/manhwa-rose/";

    const redirectUrl =
      new URL(frontend);

    redirectUrl.searchParams.set(
      "login",
      "success"
    );

    const response =
      new Response(null, {
        status: 302,
        headers: {
          Location:
            redirectUrl.toString(),
        },
      });

    response.headers.append(
      "Set-Cookie",
      userCookie(
        session.sessionId
      )
    );

    response.headers.append(
      "Set-Cookie",
      clearGoogleStateCookie()
    );

    return response;
  } catch (error) {
    return new Response(
      "Google login error: " +
        error.message,
      {
        status: 500,
        headers: {
          "Content-Type":
            "text/plain; charset=UTF-8",
        },
      }
    );
  }
}

// ------------------------------------------------------------
// USER API
// ------------------------------------------------------------

async function handleUserMe(
  request,
  env
) {
  const user =
    await getCurrentUser(
      request,
      env
    );

  if (!user) {
    return unauthorized(
      "Not logged in."
    );
  }

  return json({
    success: true,
    user: {
      id: user.id,
      email: user.email,
      username: user.username,
      name: user.name,
      avatar_url:
        user.avatar_url,
      plan: user.plan,
      vip_expires_at:
        user.vip_expires_at,
      rose_coins:
        user.rose_coins,
      xp: user.xp,
      level: user.level,
      created_at:
        user.created_at,
      last_login_at:
        user.last_login_at,
    },
  });
}

async function handleUserLogout(
  request,
  env
) {
  const sessionId =
    getCookie(
      request,
      USER_COOKIE
    );

  if (sessionId) {
    await env.DB.prepare(
      "DELETE FROM sessions WHERE id = ?"
    )
      .bind(sessionId)
      .run();
  }

  return json(
    {
      success: true,
      message:
        "Logged out.",
    },
    200,
    {
      "Set-Cookie":
        clearUserCookie(),
    }
  );
}

// ------------------------------------------------------------
// ADMIN LOGIN
// ------------------------------------------------------------

async function handleAdminLogin(
  request,
  env
) {
  let body;

  try {
    body =
      await request.json();
  } catch {
    return badRequest(
      "Invalid JSON."
    );
  }

  const username =
    String(
      body.username || ""
    );

  const password =
    String(
      body.password || ""
    );

  if (
    !env.ADMIN_USERNAME ||
    !env.ADMIN_PASSWORD
  ) {
    return serverError(
      "Admin secrets are not configured."
    );
  }

  if (
    username !==
      env.ADMIN_USERNAME ||
    password !==
      env.ADMIN_PASSWORD
  ) {
    return unauthorized(
      "Invalid username or password."
    );
  }

  const token =
    await createAdminSessionToken(
      env
    );

  return json(
    {
      success: true,
      message:
        "Login successful.",
    },
    200,
    {
      "Set-Cookie":
        adminCookie(token),
    }
  );
}

async function handleAdminCheckAuth(
  request,
  env
) {
  const authenticated =
    await isAdminAuthenticated(
      request,
      env
    );

  return json({
    authenticated,
    success: authenticated,
  });
}

async function handleAdminLogout() {
  return json(
    {
      success: true,
      message:
        "Logged out.",
    },
    200,
    {
      "Set-Cookie":
        clearAdminCookie(),
    }
  );
}

// ------------------------------------------------------------
// ADMIN MANGA API
// ------------------------------------------------------------

async function getManga(request, env) {
  const authenticated =
    await isAdminAuthenticated(
      request,
      env
    );

  if (!authenticated) {
    return unauthorized();
  }

  try {
    const { results } =
      await env.DB.prepare(
        "SELECT * FROM manga ORDER BY created_at DESC"
      ).all();

    return json({
      success: true,
      manga: results || [],
      results: results || [],
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

async function createManga(
  request,
  env
) {
  const authenticated =
    await isAdminAuthenticated(
      request,
      env
    );

  if (!authenticated) {
    return unauthorized();
  }

  let body;

  try {
    body =
      await request.json();
  } catch {
    return badRequest(
      "Invalid JSON."
    );
  }

  const title =
    String(
      body.title || ""
    ).trim();

  const description =
    String(
      body.description || ""
    );

  const coverUrl =
    String(
      body.cover_url ||
        body.coverUrl ||
        ""
    );

  const genre =
    String(
      body.genre || ""
    );

  const status =
    String(
      body.status || "ongoing"
    );

  if (!title) {
    return badRequest(
      "Title is required."
    );
  }

  try {
    const result =
      await env.DB.prepare(
        `
          INSERT INTO manga
          (
            title,
            description,
            cover_url,
            genre,
            status
          )
          VALUES (?, ?, ?, ?, ?)
        `
      )
        .bind(
          title,
          description,
          coverUrl,
          genre,
          status
        )
        .run();

    const manga =
      await env.DB.prepare(
        `
          SELECT *
          FROM manga
          WHERE id = ?
          LIMIT 1
        `
      )
        .bind(
          result.meta.last_row_id
        )
        .first();

    return json({
      success: true,
      manga,
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

async function updateManga(
  request,
  env,
  id
) {
  const authenticated =
    await isAdminAuthenticated(
      request,
      env
    );

  if (!authenticated) {
    return unauthorized();
  }

  let body;

  try {
    body =
      await request.json();
  } catch {
    return badRequest(
      "Invalid JSON."
    );
  }

  const title =
    String(
      body.title || ""
    ).trim();

  const description =
    String(
      body.description || ""
    );

  const coverUrl =
    String(
      body.cover_url ||
        body.coverUrl ||
        ""
    );

  const genre =
    String(
      body.genre || ""
    );

  const status =
    String(
      body.status || "ongoing"
    );

  if (!title) {
    return badRequest(
      "Title is required."
    );
  }

  try {
    const result =
      await env.DB.prepare(
        `
          UPDATE manga
          SET
            title = ?,
            description = ?,
            cover_url = ?,
            genre = ?,
            status = ?
          WHERE id = ?
        `
      )
        .bind(
          title,
          description,
          coverUrl,
          genre,
          status,
          id
        )
        .run();

    if (
      result.meta.changes === 0
    ) {
      return notFound(
        "Manga not found."
      );
    }

    const manga =
      await env.DB.prepare(
        `
          SELECT *
          FROM manga
          WHERE id = ?
          LIMIT 1
        `
      )
        .bind(id)
        .first();

    return json({
      success: true,
      manga,
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

async function deleteManga(
  request,
  env,
  id
) {
  const authenticated =
    await isAdminAuthenticated(
      request,
      env
    );

  if (!authenticated) {
    return unauthorized();
  }

  try {
    await env.DB.prepare(
      "DELETE FROM chapters WHERE manga_id = ?"
    )
      .bind(id)
      .run();

    const result =
      await env.DB.prepare(
        "DELETE FROM manga WHERE id = ?"
      )
        .bind(id)
        .run();

    if (
      result.meta.changes === 0
    ) {
      return notFound(
        "Manga not found."
      );
    }

    return json({
      success: true,
      message:
        "Manga deleted.",
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

// ------------------------------------------------------------
// ADMIN CHAPTER API
// ------------------------------------------------------------

async function getChapters(
  request,
  env
) {
  const authenticated =
    await isAdminAuthenticated(
      request,
      env
    );

  if (!authenticated) {
    return unauthorized();
  }

  try {
    const { results } =
      await env.DB.prepare(
        `
          SELECT *
          FROM chapters
          ORDER BY
            manga_id ASC,
            chapter_number ASC
        `
      ).all();

    return json({
      success: true,
      chapters:
        results || [],
      results:
        results || [],
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

async function createChapter(
  request,
  env
) {
  const authenticated =
    await isAdminAuthenticated(
      request,
      env
    );

  if (!authenticated) {
    return unauthorized();
  }

  let body;

  try {
    body =
      await request.json();
  } catch {
    return badRequest(
      "Invalid JSON."
    );
  }

  const mangaId =
    Number(
      body.manga_id ||
        body.mangaId
    );

  const chapterNumber =
    Number(
      body.chapter_number ||
        body.chapterNumber ||
        1
    );

  const title =
    String(
      body.title ||
        `Chapter ${chapterNumber}`
    );

  const pages =
    body.pages ?? "";

  if (!mangaId) {
    return badRequest(
      "manga_id is required."
    );
  }

  try {
    const manga =
      await env.DB.prepare(
        `
          SELECT id
          FROM manga
          WHERE id = ?
          LIMIT 1
        `
      )
        .bind(mangaId)
        .first();

    if (!manga) {
      return notFound(
        "Manga not found."
      );
    }

    const result =
      await env.DB.prepare(
        `
          INSERT INTO chapters
          (
            manga_id,
            chapter_number,
            title,
            pages
          )
          VALUES (?, ?, ?, ?)
        `
      )
        .bind(
          mangaId,
          chapterNumber,
          title,
          typeof pages ===
            "string"
            ? pages
            : JSON.stringify(pages)
        )
        .run();

    const chapter =
      await env.DB.prepare(
        `
          SELECT *
          FROM chapters
          WHERE id = ?
          LIMIT 1
        `
      )
        .bind(
          result.meta.last_row_id
        )
        .first();

    return json({
      success: true,
      chapter,
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

async function updateChapter(
  request,
  env,
  id
) {
  const authenticated =
    await isAdminAuthenticated(
      request,
      env
    );

  if (!authenticated) {
    return unauthorized();
  }

  let body;

  try {
    body =
      await request.json();
  } catch {
    return badRequest(
      "Invalid JSON."
    );
  }

  const mangaId =
    Number(
      body.manga_id ||
        body.mangaId
    );

  const chapterNumber =
    Number(
      body.chapter_number ||
        body.chapterNumber ||
        1
    );

  const title =
    String(
      body.title ||
        `Chapter ${chapterNumber}`
    );

  const pages =
    body.pages ?? "";

  if (!mangaId) {
    return badRequest(
      "manga_id is required."
    );
  }

  try {
    const result =
      await env.DB.prepare(
        `
          UPDATE chapters
          SET
            manga_id = ?,
            chapter_number = ?,
            title = ?,
            pages = ?
          WHERE id = ?
        `
      )
        .bind(
          mangaId,
          chapterNumber,
          title,
          typeof pages ===
            "string"
            ? pages
            : JSON.stringify(pages),
          id
        )
        .run();

    if (
      result.meta.changes === 0
    ) {
      return notFound(
        "Chapter not found."
      );
    }

    const chapter =
      await env.DB.prepare(
        `
          SELECT *
          FROM chapters
          WHERE id = ?
          LIMIT 1
        `
      )
        .bind(id)
        .first();

    return json({
      success: true,
      chapter,
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

async function deleteChapter(
  request,
  env,
  id
) {
  const authenticated =
    await isAdminAuthenticated(
      request,
      env
    );

  if (!authenticated) {
    return unauthorized();
  }

  try {
    const result =
      await env.DB.prepare(
        "DELETE FROM chapters WHERE id = ?"
      )
        .bind(id)
        .run();

    if (
      result.meta.changes === 0
    ) {
      return notFound(
        "Chapter not found."
      );
    }

    return json({
      success: true,
      message:
        "Chapter deleted.",
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

// ------------------------------------------------------------
// PUBLIC MANGA API
// ------------------------------------------------------------

async function publicManga(
  env
) {
  try {
    const { results } =
      await env.DB.prepare(
        `
          SELECT
            id,
            title,
            description,
            cover_url,
            genre,
            status,
            created_at
          FROM manga
          ORDER BY created_at DESC
        `
      ).all();

    return json({
      success: true,
      manga:
        results || [],
      results:
        results || [],
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

async function publicMangaById(
  env,
  id
) {
  try {
    const manga =
      await env.DB.prepare(
        `
          SELECT *
          FROM manga
          WHERE id = ?
          LIMIT 1
        `
      )
        .bind(id)
        .first();

    if (!manga) {
      return notFound(
        "Manga not found."
      );
    }

    const { results } =
      await env.DB.prepare(
        `
          SELECT
            id,
            manga_id,
            chapter_number,
            title,
            created_at
          FROM chapters
          WHERE manga_id = ?
          ORDER BY chapter_number ASC
        `
      )
        .bind(id)
        .all();

    return json({
      success: true,
      manga,
      chapters:
        results || [],
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

async function publicChapters(
  env,
  chapterId
) {
  try {
    const chapter =
      await env.DB.prepare(
        `
          SELECT *
          FROM chapters
          WHERE id = ?
          LIMIT 1
        `
      )
        .bind(chapterId)
        .first();

    if (!chapter) {
      return notFound(
        "Chapter not found."
      );
    }

    let pages = [];

    try {
      pages =
        typeof chapter.pages ===
        "string"
          ? JSON.parse(
              chapter.pages
            )
          : chapter.pages;
    } catch {
      pages = [];
    }

    if (
      !Array.isArray(pages)
    ) {
      pages = [];
    }

    const { results: siblings } =
      await env.DB.prepare(
        `
          SELECT
            id,
            chapter_number
          FROM chapters
          WHERE manga_id = ?
          ORDER BY chapter_number ASC
        `
      )
        .bind(chapter.manga_id)
        .all();

    return json({
      success: true,
      chapter: {
        ...chapter,
        pages,
      },
      siblings:
        siblings || [],
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

// ------------------------------------------------------------
// PUBLIC SUPPORT
// ------------------------------------------------------------

async function publicSupport(
  request,
  env
) {
  let body;

  try {
    body =
      await request.json();
  } catch {
    return badRequest(
      "Invalid JSON."
    );
  }

  const name =
    String(
      body.name || ""
    ).trim();

  const email =
    String(
      body.email || ""
    ).trim();

  const message =
    String(
      body.message || ""
    ).trim();

  if (!message) {
    return badRequest(
      "Message is required."
    );
  }

  try {
    await env.DB.prepare(
      `
        INSERT INTO support_messages
        (name, email, message)
        VALUES (?, ?, ?)
      `
    )
      .bind(
        name,
        email,
        message
      )
      .run();

    return json({
      success: true,
      message:
        "Support message sent.",
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

// ------------------------------------------------------------
// ADMIN SUPPORT
// ------------------------------------------------------------

async function adminSupport(
  request,
  env
) {
  const authenticated =
    await isAdminAuthenticated(
      request,
      env
    );

  if (!authenticated) {
    return unauthorized();
  }

  try {
    const { results } =
      await env.DB.prepare(
        `
          SELECT *
          FROM support_messages
          ORDER BY id DESC
        `
      ).all();

    return json({
      success: true,
      messages:
        results || [],
      results:
        results || [],
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

async function deleteSupport(
  request,
  env,
  id
) {
  const authenticated =
    await isAdminAuthenticated(
      request,
      env
    );

  if (!authenticated) {
    return unauthorized();
  }

  try {
    const result =
      await env.DB.prepare(
        `
          DELETE FROM support_messages
          WHERE id = ?
        `
      )
        .bind(id)
        .run();

    if (
      result.meta.changes === 0
    ) {
      return notFound(
        "Support message not found."
      );
    }

    return json({
      success: true,
      message:
        "Support message deleted.",
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

// ------------------------------------------------------------
// TEST FILES
// ------------------------------------------------------------

async function publicTestFiles(
  env
) {
  try {
    const { results } =
      await env.DB.prepare(
        `
          SELECT *
          FROM test_files
          ORDER BY id DESC
        `
      ).all();

    return json({
      success: true,
      files:
        results || [],
      results:
        results || [],
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

async function adminTestFiles(
  request,
  env
) {
  const authenticated =
    await isAdminAuthenticated(
      request,
      env
    );

  if (!authenticated) {
    return unauthorized();
  }

  try {
    const { results } =
      await env.DB.prepare(
        `
          SELECT *
          FROM test_files
          ORDER BY id DESC
        `
      ).all();

    return json({
      success: true,
      files:
        results || [],
      results:
        results || [],
    });
  } catch (error) {
    return serverError(
      error.message
    );
  }
}

// ------------------------------------------------------------
// ROOT / HEALTH
// ------------------------------------------------------------

async function workerStatus() {
  return json({
    success: true,
    message:
      "Manhwa Rose Worker is running.",
    version:
      "Google OAuth + User Accounts",
  });
}

// ------------------------------------------------------------
// MAIN FETCH
// ------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    const path =
      url.pathname;

    const method =
      request.method.toUpperCase();

    // --------------------------------------------------------
    // CORS PREFLIGHT
    // --------------------------------------------------------

    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers:
          corsHeaders(
            request,
            env
          ),
      });
    }

    let response;

    try {
      // ------------------------------------------------------
      // GOOGLE LOGIN
      // ------------------------------------------------------

      if (
        path ===
        "/auth/google" &&
        method === "GET"
      ) {
        response =
          await handleGoogleLogin(
            request,
            env
          );

        return response;
      }

      // ------------------------------------------------------
      // GOOGLE CALLBACK
      // ------------------------------------------------------

      if (
        path ===
        "/auth/google/callback" &&
        method === "GET"
      ) {
        response =
          await handleGoogleCallback(
            request,
            env
          );

        return response;
      }

      // ------------------------------------------------------
      // USER ACCOUNT
      // ------------------------------------------------------

      if (
        path ===
        "/api/user/me" &&
        method === "GET"
      ) {
        response =
          await handleUserMe(
            request,
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      if (
        path ===
        "/api/user/logout" &&
        method === "POST"
      ) {
        response =
          await handleUserLogout(
            request,
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      // ------------------------------------------------------
      // ADMIN LOGIN
      // ------------------------------------------------------

      if (
        path ===
        "/api/login" &&
        method === "POST"
      ) {
        response =
          await handleAdminLogin(
            request,
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      if (
        path ===
        "/api/check-auth" &&
        method === "GET"
      ) {
        response =
          await handleAdminCheckAuth(
            request,
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      if (
        path ===
        "/api/logout" &&
        method === "POST"
      ) {
        response =
          await handleAdminLogout();

        return withCors(
          response,
          request,
          env
        );
      }

      // ------------------------------------------------------
      // ADMIN MANGA
      // ------------------------------------------------------

      if (
        path ===
        "/api/manga" &&
        method === "GET"
      ) {
        response =
          await getManga(
            request,
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      if (
        path ===
        "/api/manga" &&
        method === "POST"
      ) {
        response =
          await createManga(
            request,
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      const mangaMatch =
        path.match(
          /^\/api\/manga\/(\d+)$/
        );

      if (
        mangaMatch &&
        method === "PUT"
      ) {
        response =
          await updateManga(
            request,
            env,
            mangaMatch[1]
          );

        return withCors(
          response,
          request,
          env
        );
      }

      if (
        mangaMatch &&
        method === "DELETE"
      ) {
        response =
          await deleteManga(
            request,
            env,
            mangaMatch[1]
          );

        return withCors(
          response,
          request,
          env
        );
      }

      // ------------------------------------------------------
      // ADMIN CHAPTERS
      // ------------------------------------------------------

      if (
        path ===
        "/api/chapters" &&
        method === "GET"
      ) {
        response =
          await getChapters(
            request,
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      if (
        path ===
        "/api/chapters" &&
        method === "POST"
      ) {
        response =
          await createChapter(
            request,
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      const chapterMatch =
        path.match(
          /^\/api\/chapters\/(\d+)$/
        );

      if (
        chapterMatch &&
        method === "PUT"
      ) {
        response =
          await updateChapter(
            request,
            env,
            chapterMatch[1]
          );

        return withCors(
          response,
          request,
          env
        );
      }

      if (
        chapterMatch &&
        method === "DELETE"
      ) {
        response =
          await deleteChapter(
            request,
            env,
            chapterMatch[1]
          );

        return withCors(
          response,
          request,
          env
        );
      }

      // ------------------------------------------------------
      // PUBLIC MANGA
      // ------------------------------------------------------

      if (
        path ===
        "/api/public/manga" &&
        method === "GET"
      ) {
        response =
          await publicManga(
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      const publicMangaMatch =
        path.match(
          /^\/api\/public\/manga\/(\d+)$/
        );

      if (
        publicMangaMatch &&
        method === "GET"
      ) {
        response =
          await publicMangaById(
            env,
            publicMangaMatch[1]
          );

        return withCors(
          response,
          request,
          env
        );
      }

      // ------------------------------------------------------
      // PUBLIC CHAPTERS
      // ------------------------------------------------------

      const publicChapterMatch =
        path.match(
          /^\/api\/public\/chapters\/(\d+)$/
        );

      if (
        publicChapterMatch &&
        method === "GET"
      ) {
        response =
          await publicChapters(
            env,
            publicChapterMatch[1]
          );

        return withCors(
          response,
          request,
          env
        );
      }

      // ------------------------------------------------------
      // PUBLIC SUPPORT
      // ------------------------------------------------------

      if (
        path ===
        "/api/public/support" &&
        method === "POST"
      ) {
        response =
          await publicSupport(
            request,
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      // ------------------------------------------------------
      // ADMIN SUPPORT
      // ------------------------------------------------------

      if (
        path ===
        "/api/support" &&
        method === "GET"
      ) {
        response =
          await adminSupport(
            request,
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      const supportMatch =
        path.match(
          /^\/api\/support\/(\d+)$/
        );

      if (
        supportMatch &&
        method === "DELETE"
      ) {
        response =
          await deleteSupport(
            request,
            env,
            supportMatch[1]
          );

        return withCors(
          response,
          request,
          env
        );
      }

      // ------------------------------------------------------
      // PUBLIC TEST FILES
      // ------------------------------------------------------

      if (
        path ===
        "/api/public/test-files" &&
        method === "GET"
      ) {
        response =
          await publicTestFiles(
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      // ------------------------------------------------------
      // ADMIN TEST FILES
      // ------------------------------------------------------

      if (
        path ===
        "/api/test-files" &&
        method === "GET"
      ) {
        response =
          await adminTestFiles(
            request,
            env
          );

        return withCors(
          response,
          request,
          env
        );
      }

      // ------------------------------------------------------
      // WORKER STATUS
      // ------------------------------------------------------

      if (
        path === "/" ||
        path === ""
      ) {
        response =
          await workerStatus();

        return withCors(
          response,
          request,
          env
        );
      }

      // ------------------------------------------------------
      // CLOUDFLARE ASSETS
      // ------------------------------------------------------

      if (env.ASSETS) {
        try {
          return await env.ASSETS.fetch(
            request
          );
        } catch {
          // Continue to 404 below.
        }
      }

      return new Response(
        "Not Found",
        {
          status: 404,
          headers: {
            "Content-Type":
              "text/plain; charset=UTF-8",
          },
        }
      );
    } catch (error) {
      console.error(
        "Worker error:",
        error
      );

      response =
        serverError(
          error.message ||
            "Internal Server Error"
        );

      return withCors(
        response,
        request,
        env
      );
    }
  },
};
