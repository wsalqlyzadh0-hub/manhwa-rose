const COOKIE_NAME = "mr_admin";
const SESSION_TIME = 86400;

function getCookie(request) {
  const header = request.headers.get("Cookie") || "";

  for (const item of header.split(";")) {
    const [name, ...value] = item.trim().split("=");

    if (name === COOKIE_NAME) {
      return value.join("=");
    }
  }

  return null;
}

async function createToken(username, password) {
  const expires =
    Math.floor(Date.now() / 1000) + SESSION_TIME;

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

  let binary = "";

  for (const byte of new Uint8Array(signature)) {
    binary += String.fromCharCode(byte);
  }

  const hash = btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");

  return `${btoa(data)}.${hash}`;
}

async function verifyToken(token, username, password) {
  try {
    const parts = token.split(".");

    if (parts.length !== 2) return false;

    const data = atob(parts[0]);
    const [tokenUsername, expiresText] = data.split("|");
    const expires = Number(expiresText);

    if (
      tokenUsername !== username ||
      !expires ||
      expires < Math.floor(Date.now() / 1000)
    ) {
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

    let binary = "";

    for (const byte of new Uint8Array(signature)) {
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

async function isAuthenticated(request, env) {
  if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD) return false;
  const token = getCookie(request);
  if (!token) return false;
  return await verifyToken(token, env.ADMIN_USERNAME, env.ADMIN_PASSWORD);
}

function json(data, status = 200, headers = {}) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type": "application/json",
        ...headers
      }
    }
  );
}

function unauthorized() {
  return json({ success: false, message: "دسترسی غیرمجاز است." }, 401);
}

export default {

  async fetch(request, env) {

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    /* ---------- AUTH ---------- */

    if (path === "/api/login" && method === "POST") {

      if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD) {
        return json({ success: false, message: "Admin secrets are not configured." }, 500);
      }

      try {
        const body = await request.json();
        const username = String(body.username || "");
        const password = String(body.password || "");

        if (username !== env.ADMIN_USERNAME || password !== env.ADMIN_PASSWORD) {
          return json({ success: false, message: "نام کاربری یا رمز عبور اشتباه است." }, 401);
        }

        const token = await createToken(env.ADMIN_USERNAME, env.ADMIN_PASSWORD);

        return json(
          { success: true },
          200,
          {
            "Set-Cookie":
              `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TIME}`
          }
        );

      } catch {
        return json({ success: false, message: "درخواست نامعتبر است." }, 400);
      }
    }

    if (path === "/api/check-auth" && method === "GET") {

      if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD) {
        return json({ authenticated: false, message: "Admin secrets are not configured." }, 500);
      }

      const authed = await isAuthenticated(request, env);
      return json({ authenticated: authed });
    }

    if (path === "/api/logout" && method === "POST") {
      return json(
        { success: true },
        200,
        {
          "Set-Cookie":
            `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
        }
      );
    }


    /* ---------- MANGA CRUD ---------- */

    if (path === "/api/manga" && method === "GET") {
      if (!(await isAuthenticated(request, env))) return unauthorized();

      const { results } = await env.DB.prepare(
        "SELECT * FROM manga ORDER BY created_at DESC"
      ).all();

      return json({ success: true, manga: results });
    }

    if (path === "/api/manga" && method === "POST") {
      if (!(await isAuthenticated(request, env))) return unauthorized();

      try {
        const body = await request.json();
        const title = String(body.title || "").trim();
        if (!title) return json({ success: false, message: "عنوان الزامی است." }, 400);

        const description = String(body.description || "");
        const cover_url = String(body.cover_url || "");
        const genre = String(body.genre || "");
        const status = String(body.status || "ongoing");

        const result = await env.DB.prepare(
          `INSERT INTO manga (title, description, cover_url, genre, status)
           VALUES (?, ?, ?, ?, ?)`
        ).bind(title, description, cover_url, genre, status).run();

        return json({ success: true, id: result.meta.last_row_id });

      } catch (e) {
        return json({ success: false, message: "خطا در ثبت مانهوا." }, 500);
      }
    }

    if (path.match(/^\/api\/manga\/\d+$/) && method === "PUT") {
      if (!(await isAuthenticated(request, env))) return unauthorized();

      const id = path.split("/").pop();

      try {
        const body = await request.json();
        const title = String(body.title || "").trim();
        if (!title) return json({ success: false, message: "عنوان الزامی است." }, 400);

        const description = String(body.description || "");
        const cover_url = String(body.cover_url || "");
        const genre = String(body.genre || "");
        const status = String(body.status || "ongoing");

        await env.DB.prepare(
          `UPDATE manga SET title = ?, description = ?, cover_url = ?, genre = ?, status = ?
           WHERE id = ?`
        ).bind(title, description, cover_url, genre, status, id).run();

        return json({ success: true });

      } catch {
        return json({ success: false, message: "خطا در بروزرسانی مانهوا." }, 500);
      }
    }

    if (path.match(/^\/api\/manga\/\d+$/) && method === "DELETE") {
      if (!(await isAuthenticated(request, env))) return unauthorized();

      const id = path.split("/").pop();

      await env.DB.prepare("DELETE FROM chapters WHERE manga_id = ?").bind(id).run();
      await env.DB.prepare("DELETE FROM manga WHERE id = ?").bind(id).run();

      return json({ success: true });
    }


    /* ---------- CHAPTERS CRUD ---------- */

    if (path === "/api/chapters" && method === "GET") {
      if (!(await isAuthenticated(request, env))) return unauthorized();

      const mangaId = url.searchParams.get("manga_id");

      let query;
      if (mangaId) {
        query = env.DB.prepare(
          "SELECT * FROM chapters WHERE manga_id = ? ORDER BY chapter_number ASC"
        ).bind(mangaId);
      } else {
        query = env.DB.prepare(
          "SELECT * FROM chapters ORDER BY created_at DESC"
        );
      }

      const { results } = await query.all();

      const chapters = results.map(ch => ({
        ...ch,
        pages: JSON.parse(ch.pages || "[]")
      }));

      return json({ success: true, chapters });
    }

    if (path === "/api/chapters" && method === "POST") {
      if (!(await isAuthenticated(request, env))) return unauthorized();

      try {
        const body = await request.json();
        const manga_id = Number(body.manga_id);
        const chapter_number = Number(body.chapter_number);
        const title = String(body.title || "");
        const pages = Array.isArray(body.pages) ? body.pages : [];

        if (!manga_id || !chapter_number) {
          return json({ success: false, message: "مانهوا و شماره قسمت الزامی است." }, 400);
        }

        const result = await env.DB.prepare(
          `INSERT INTO chapters (manga_id, chapter_number, title, pages)
           VALUES (?, ?, ?, ?)`
        ).bind(manga_id, chapter_number, title, JSON.stringify(pages)).run();

        return json({ success: true, id: result.meta.last_row_id });

      } catch {
        return json({ success: false, message: "خطا در ثبت قسمت." }, 500);
      }
    }

    if (path.match(/^\/api\/chapters\/\d+$/) && method === "PUT") {
      if (!(await isAuthenticated(request, env))) return unauthorized();

      const id = path.split("/").pop();

      try {
        const body = await request.json();
        const chapter_number = Number(body.chapter_number);
        const title = String(body.title || "");
        const pages = Array.isArray(body.pages) ? body.pages : [];

        await env.DB.prepare(
          `UPDATE chapters SET chapter_number = ?, title = ?, pages = ?
           WHERE id = ?`
        ).bind(chapter_number, title, JSON.stringify(pages), id).run();

        return json({ success: true });

      } catch {
        return json({ success: false, message: "خطا در بروزرسانی قسمت." }, 500);
      }
    }

    if (path.match(/^\/api\/chapters\/\d+$/) && method === "DELETE") {
      if (!(await isAuthenticated(request, env))) return unauthorized();

      const id = path.split("/").pop();
      await env.DB.prepare("DELETE FROM chapters WHERE id = ?").bind(id).run();

      return json({ success: true });
    }


    /* ---------- PUBLIC (no auth needed, for the public website) ---------- */

    if (path === "/api/public/support" && method === "POST") {
      try {
        const body = await request.json();
        const name = String(body.name || "").trim();
        const message = String(body.message || "").trim();

        if (!name || !message) {
          return json({ success: false, message: "نام و پیام الزامی است." }, 400);
        }

        await env.DB.prepare(
          `INSERT INTO support_messages (name, message) VALUES (?, ?)`
        ).bind(name, message).run();

        return json({ success: true });

      } catch {
        return json({ success: false, message: "خطا در ارسال پیام." }, 500);
      }
    }

    if (path === "/api/public/test-files" && method === "GET") {
      const { results } = await env.DB.prepare(
        "SELECT type, file_url FROM test_files"
      ).all();

      const map = {};
      results.forEach(r => { map[r.type] = r.file_url; });

      return json({ success: true, files: map });
    }


    /* ---------- ADMIN: SUPPORT MESSAGES ---------- */

    if (path === "/api/support" && method === "GET") {
      if (!(await isAuthenticated(request, env))) return unauthorized();

      const { results } = await env.DB.prepare(
        "SELECT * FROM support_messages ORDER BY created_at DESC"
      ).all();

      return json({ success: true, messages: results });
    }

    if (path.match(/^\/api\/support\/\d+$/) && method === "DELETE") {
      if (!(await isAuthenticated(request, env))) return unauthorized();

      const id = path.split("/").pop();
      await env.DB.prepare("DELETE FROM support_messages WHERE id = ?").bind(id).run();

      return json({ success: true });
    }


    /* ---------- ADMIN: TEST FILES ---------- */

    if (path === "/api/test-files" && method === "GET") {
      if (!(await isAuthenticated(request, env))) return unauthorized();

      const { results } = await env.DB.prepare(
        "SELECT type, file_url FROM test_files"
      ).all();

      const map = {};
      results.forEach(r => { map[r.type] = r.file_url; });

      return json({ success: true, files: map });
    }

    if (path === "/api/test-files" && method === "PUT") {
      if (!(await isAuthenticated(request, env))) return unauthorized();

      try {
        const body = await request.json();
        const type = String(body.type || "");
        const file_url = String(body.file_url || "");

        if (!["translate", "clean", "type"].includes(type)) {
          return json({ success: false, message: "نوع نامعتبر است." }, 400);
        }

        await env.DB.prepare(
          `UPDATE test_files SET file_url = ? WHERE type = ?`
        ).bind(file_url, type).run();

        return json({ success: true });

      } catch {
        return json({ success: false, message: "خطا در بروزرسانی." }, 500);
      }
    }

    if (path === "/api/public/manga" && method === "GET") {
      const { results } = await env.DB.prepare(
        "SELECT id, title, description, cover_url, genre, status FROM manga ORDER BY created_at DESC"
      ).all();

      return json({ success: true, manga: results });
    }

    if (path.match(/^\/api\/public\/manga\/\d+$/) && method === "GET") {
      const id = path.split("/").pop();

      const manga = await env.DB.prepare(
        "SELECT id, title, description, cover_url, genre, status FROM manga WHERE id = ?"
      ).bind(id).first();

      if (!manga) {
        return json({ success: false, message: "مانهوا پیدا نشد." }, 404);
      }

      const { results: chapters } = await env.DB.prepare(
        "SELECT id, chapter_number, title FROM chapters WHERE manga_id = ? ORDER BY chapter_number ASC"
      ).bind(id).all();

      return json({ success: true, manga, chapters });
    }

    if (path.match(/^\/api\/public\/chapters\/\d+$/) && method === "GET") {
      const id = path.split("/").pop();

      const chapter = await env.DB.prepare(
        "SELECT * FROM chapters WHERE id = ?"
      ).bind(id).first();

      if (!chapter) {
        return json({ success: false, message: "قسمت پیدا نشد." }, 404);
      }

      chapter.pages = JSON.parse(chapter.pages || "[]");

      const { results: siblings } = await env.DB.prepare(
        "SELECT id, chapter_number FROM chapters WHERE manga_id = ? ORDER BY chapter_number ASC"
      ).bind(chapter.manga_id).all();

      return json({ success: true, chapter, siblings });
    }


    /* ---------- WEBSITE / ASSETS ---------- */

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("Worker is running.", {
      status: 200,
      headers: { "Content-Type": "text/plain" }
    });
  }
};
