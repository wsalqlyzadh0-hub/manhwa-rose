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

  let binary = "";

  for (const byte of new Uint8Array(signature)) {
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

    if (parts.length !== 2) {
      return false;
    }

    const data = atob(parts[0]);
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

function getCookie(request) {
  const cookies = request.headers.get("Cookie") || "";

  const match = cookies.match(
    new RegExp(`${COOKIE_NAME}=([^;]+)`)
  );

  return match ? match[1] : null;
}

export default {
  async fetch(request, env) {

    const url = new URL(request.url);

    // ورود ادمین
    if (
      url.pathname === "/api/login" &&
      request.method === "POST"
    ) {
      try {
        const
