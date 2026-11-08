// Admin authentication for the /setup pages.
//
// - Password is POSTed once (never in a URL), compared in constant time.
// - Optional second factor: a 6-digit authenticator-app code (TOTP, RFC 6238)
//   when ADMIN_TOTP_SECRET is set.
// - A successful login sets a signed, HttpOnly, Secure session cookie (2 hours).
// - Failed logins are rate-limited per IP and globally (Upstash Redis when
//   configured, otherwise in memory).
// - Every state-changing form carries a CSRF token bound to the session.

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { Request, Response, NextFunction } from "express";
import { Redis } from "@upstash/redis";

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const TOTP_SECRET = (process.env.ADMIN_TOTP_SECRET || "").replace(/\s+/g, "").toUpperCase();
const SIGNING_SALT = process.env.MCP_SECRET || "";

export const MIN_PASSWORD_LENGTH = 20;
const SESSION_COOKIE = "__Host-gmcp_admin";
const STATE_COOKIE = "__Host-gmcp_oauth";
const SESSION_TTL_S = 2 * 60 * 60;
const STATE_TTL_S = 10 * 60;

const IP_LIMIT = 5; // failed attempts per IP...
const IP_WINDOW_S = 15 * 60; // ...per 15 minutes
const GLOBAL_LIMIT = 30; // failed attempts from everyone...
const GLOBAL_WINDOW_S = 60 * 60; // ...per hour

export const totpEnabled = TOTP_SECRET.length > 0;
export const passwordConfigured = ADMIN_PASSWORD.length > 0;
export const passwordIsWeak = ADMIN_PASSWORD.length < MIN_PASSWORD_LENGTH;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function safeEqual(a: string, b: string): boolean {
  // Hash first so lengths always match and nothing leaks through timing.
  const ha = createHash("sha256").update(a).digest();
  const hb = createHash("sha256").update(b).digest();
  return timingSafeEqual(ha, hb);
}

function signingKey(): Buffer {
  // Changing ADMIN_PASSWORD (or MCP_SECRET) invalidates every existing session.
  return createHash("sha256")
    .update(`gmail-mcp-session\0${ADMIN_PASSWORD}\0${SIGNING_SALT}`)
    .digest();
}

function sign(payload: string): string {
  return b64url(createHmac("sha256", signingKey()).update(payload).digest());
}

function parseCookies(req: Request): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function setCookie(res: Response, name: string, value: string, maxAge: number): void {
  res.append(
    "Set-Cookie",
    `${name}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`
  );
}

export function clientIp(req: Request): string {
  const real = req.headers["x-real-ip"];
  if (typeof real === "string" && real) return real;
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string" && fwd) return fwd.split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

export interface AdminSession {
  csrf: string;
  expires: number;
}

export function readSession(req: Request): AdminSession | null {
  if (!passwordConfigured) return null;
  const raw = parseCookies(req)[SESSION_COOKIE];
  if (!raw) return null;
  const parts = raw.split(".");
  if (parts.length !== 3) return null;
  const [exp, csrf, sig] = parts;
  if (!safeEqual(sig, sign(`${exp}.${csrf}`))) return null;
  const expires = Number(exp);
  if (!Number.isFinite(expires) || expires < Date.now() / 1000) return null;
  return { csrf, expires };
}

export function startSession(res: Response): void {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_S;
  const csrf = b64url(randomBytes(18));
  setCookie(res, SESSION_COOKIE, `${exp}.${csrf}.${sign(`${exp}.${csrf}`)}`, SESSION_TTL_S);
}

export function endSession(res: Response): void {
  setCookie(res, SESSION_COOKIE, "", 0);
}

/** Pages: redirect to the login form. Anything else: 401. */
export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
  const session = readSession(req);
  if (!session) {
    if (req.method === "GET") res.redirect(303, "/setup/login");
    else res.status(401).send("Unauthorized");
    return;
  }
  res.locals.adminSession = session;
  next();
}

/** For POST routes: the form's csrf field must match the session. */
export function requireCsrf(req: Request, res: Response, next: NextFunction): void {
  const session = res.locals.adminSession as AdminSession | undefined;
  const given = typeof req.body?.csrf === "string" ? req.body.csrf : "";
  if (!session || !given || !safeEqual(given, session.csrf)) {
    res.status(403).send("Invalid or expired form. Go back, reload the page and try again.");
    return;
  }
  next();
}

// ---------------------------------------------------------------------------
// OAuth state (protects the Google callback from forged requests)
// ---------------------------------------------------------------------------

export function newOAuthState(res: Response): string {
  const state = b64url(randomBytes(24));
  setCookie(res, STATE_COOKIE, state, STATE_TTL_S);
  return state;
}

export function checkOAuthState(req: Request, res: Response): boolean {
  const expected = parseCookies(req)[STATE_COOKIE];
  setCookie(res, STATE_COOKIE, "", 0);
  const given = typeof req.query.state === "string" ? req.query.state : "";
  return !!expected && !!given && safeEqual(given, expected);
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

const redis = (() => {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  return url && token ? new Redis({ url, token }) : null;
})();

const memory = new Map<string, { count: number; until: number }>();

async function getCount(key: string): Promise<number> {
  if (redis) return Number((await redis.get<number>(key)) ?? 0);
  const e = memory.get(key);
  return e && e.until > Date.now() ? e.count : 0;
}

async function bump(key: string, windowS: number): Promise<void> {
  if (redis) {
    const n = await redis.incr(key);
    if (n === 1) await redis.expire(key, windowS);
    return;
  }
  const e = memory.get(key);
  if (e && e.until > Date.now()) e.count++;
  else memory.set(key, { count: 1, until: Date.now() + windowS * 1000 });
}

async function clear(key: string): Promise<void> {
  if (redis) await redis.del(key);
  else memory.delete(key);
}

const ipKey = (ip: string) => `gmail-mcp:login-fail:ip:${createHash("sha256").update(ip).digest("hex").slice(0, 32)}`;
const GLOBAL_KEY = "gmail-mcp:login-fail:global";

export async function isLockedOut(ip: string): Promise<boolean> {
  const [byIp, global] = await Promise.all([getCount(ipKey(ip)), getCount(GLOBAL_KEY)]);
  return byIp >= IP_LIMIT || global >= GLOBAL_LIMIT;
}

async function recordFailure(ip: string): Promise<void> {
  await Promise.all([bump(ipKey(ip), IP_WINDOW_S), bump(GLOBAL_KEY, GLOBAL_WINDOW_S)]);
}

// ---------------------------------------------------------------------------
// TOTP (authenticator app codes)
// ---------------------------------------------------------------------------

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(s: string): Buffer {
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of s.replace(/=+$/, "")) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error("Invalid base32");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function hotp(key: Buffer, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", key).update(msg).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1_000_000).padStart(6, "0");
}

/** Returns the matching time-step (±30 s window), or null. */
export function matchTotp(code: string, secretB32: string, now = Date.now()): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  let key: Buffer;
  try {
    key = base32Decode(secretB32);
  } catch {
    return null;
  }
  if (key.length < 10) return null;
  const step = Math.floor(now / 30_000);
  for (const s of [step - 1, step, step + 1]) {
    if (safeEqual(hotp(key, s), code)) return s;
  }
  return null;
}

export function newTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

// A code can be used once only (stops someone replaying a code they watched you type).
const TOTP_LAST_KEY = "gmail-mcp:totp-last-step";
let memoryLastStep = 0;

async function claimTotpStep(step: number): Promise<boolean> {
  if (redis) {
    const last = Number((await redis.get<number>(TOTP_LAST_KEY)) ?? 0);
    if (step <= last) return false;
    await redis.set(TOTP_LAST_KEY, step, { ex: 300 });
    return true;
  }
  if (step <= memoryLastStep) return false;
  memoryLastStep = step;
  return true;
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

export type LoginResult = "ok" | "locked" | "bad" | "not-configured";

export async function attemptLogin(req: Request, password: string, code: string): Promise<LoginResult> {
  if (!passwordConfigured) return "not-configured";
  const ip = clientIp(req);
  if (await isLockedOut(ip)) return "locked";

  let ok = safeEqual(password, ADMIN_PASSWORD);
  if (totpEnabled) {
    const step = matchTotp(code.trim(), TOTP_SECRET);
    ok = ok && step !== null && (await claimTotpStep(step));
  }

  if (!ok) {
    await recordFailure(ip);
    // Slow down guessing a little more.
    await new Promise((r) => setTimeout(r, 800 + Math.random() * 700));
    return "bad";
  }
  await clear(ipKey(ip));
  return "ok";
}

// ---------------------------------------------------------------------------
// Security headers for admin pages
// ---------------------------------------------------------------------------

export function adminHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.set({
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy":
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; " +
      "form-action 'self' https://accounts.google.com; frame-ancestors 'none'; base-uri 'none'",
  });
  next();
}
