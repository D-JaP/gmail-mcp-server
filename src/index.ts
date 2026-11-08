import express, { Request, Response, NextFunction } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { google } from "googleapis";
import { z } from "zod";
import { timingSafeEqual } from "node:crypto";
import { GmailService } from "./gmail-service.js";
import { TokenStore } from "./token-store.js";
import { legalRouter } from "./legal.js";
import {
  AdminSession,
  LoginResult,
  MIN_PASSWORD_LENGTH,
  adminHeaders,
  attemptLogin,
  checkOAuthState,
  clientIp,
  endSession,
  matchTotp,
  newOAuthState,
  newTotpSecret,
  passwordConfigured,
  passwordIsWeak,
  readSession,
  requireAdmin,
  requireCsrf,
  startSession,
  totpEnabled,
} from "./admin-auth.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.PORT || "3000", 10);
const SERVER_URL = process.env.SERVER_URL || `http://localhost:${PORT}`;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
// The MCP endpoint lives at /mcp/<MCP_SECRET>. Claude custom connectors cannot
// send a header, so the secret in the path is what keeps the mailbox private.
const MCP_SECRET = process.env.MCP_SECRET!;
const SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/userinfo.email",
];

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

const tokenStore = new TokenStore();

// ---------------------------------------------------------------------------
// Gmail service factory — exchanges stored refresh token for access token
// ---------------------------------------------------------------------------

function makeOAuth2Client() {
  return new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    `${SERVER_URL}/oauth/callback`
  );
}

async function getGmailServiceForAccount(email: string): Promise<GmailService> {
  const refreshToken = tokenStore.getRefreshToken(email);
  if (!refreshToken) {
    throw new Error(
      `Account "${email}" is not connected. Use list_accounts to see connected accounts, or add it via the /setup page.`
    );
  }

  const oauth2 = makeOAuth2Client();
  oauth2.setCredentials({ refresh_token: refreshToken });

  const { token } = await oauth2.getAccessToken();
  if (!token) {
    throw new Error(
      `Failed to get access token for "${email}". The account may need to be re-authorized via /setup.`
    );
  }

  return new GmailService(token);
}

function resolveAccounts(account: string): string[] {
  if (account.toLowerCase() === "all") {
    const all = tokenStore.listAccounts().map((a) => a.email);
    if (all.length === 0) {
      throw new Error("No accounts connected. Add accounts via the /setup page.");
    }
    return all;
  }
  if (!tokenStore.hasAccount(account)) {
    const available = tokenStore.listAccounts().map((a) => a.email);
    throw new Error(
      `Account "${account}" is not connected. Available accounts: ${available.join(", ") || "none"}`
    );
  }
  return [account];
}

// ---------------------------------------------------------------------------
// MCP server factory — registers all tools
// ---------------------------------------------------------------------------

function createMcpServer(): McpServer {
  const server = new McpServer({
    name: "gmail-mcp-server",
    version: "1.0.0",
  });

  // ---- list_accounts ----
  server.tool(
    "list_accounts",
    "List all connected Gmail accounts. Use the email addresses returned here as the 'account' parameter in other tools.",
    {},
    async () => {
      const accounts = tokenStore.listAccounts();
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                connected_accounts: accounts,
                usage_hint:
                  "Use any email address as the 'account' parameter, or use 'all' to query every account.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  // ---- list_emails ----
  server.tool(
    "list_emails",
    "Search and list emails. Supports Gmail search syntax (is:unread, from:, newer_than:7d, etc). Use account='all' to search across all connected accounts.",
    {
      account: z
        .string()
        .describe(
          "Email address of the account to search, or 'all' for every connected account"
        ),
      query: z
        .string()
        .optional()
        .describe(
          "Gmail search query (e.g. 'is:unread', 'from:user@example.com newer_than:2d', 'subject:invoice')"
        ),
      max_results: z
        .number()
        .min(1)
        .max(100)
        .default(20)
        .describe("Maximum number of emails to return per account (1-100)"),
    },
    async ({ account, query, max_results }) => {
      const accounts = resolveAccounts(account);
      const allResults: Array<{ account: string; emails: any[] }> = [];

      for (const email of accounts) {
        try {
          const gmail = await getGmailServiceForAccount(email);
          const emails = await gmail.listEmails(query, max_results);
          allResults.push({ account: email, emails });
        } catch (err: any) {
          allResults.push({
            account: email,
            emails: [],
          });
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(allResults, null, 2),
          },
        ],
      };
    }
  );

  // ---- get_email ----
  server.tool(
    "get_email",
    "Get the full content of a specific email including body, headers, and any unsubscribe links found.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const email = await gmail.getEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account, ...email }, null, 2),
          },
        ],
      };
    }
  );

  // ---- archive_email ----
  server.tool(
    "archive_email",
    "Archive an email by removing it from the inbox. The email remains accessible via search or All Mail.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID to archive"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.archiveEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              account,
              ...result,
              message: `Email ${message_id} archived successfully.`,
            }),
          },
        ],
      };
    }
  );

  // ---- apply_label ----
  server.tool(
    "apply_label",
    "Apply a label to an email. Creates the label if it does not already exist.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z.string().describe("The Gmail message ID"),
      label_name: z
        .string()
        .describe(
          "Label name to apply (e.g. 'Receipts', 'Follow Up'). Created automatically if it does not exist."
        ),
    },
    async ({ account, message_id, label_name }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.applyLabel(message_id, label_name);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              account,
              ...result,
              message: `Label "${label_name}" applied to email ${message_id}.`,
            }),
          },
        ],
      };
    }
  );

  // ---- unsubscribe_email ----
  server.tool(
    "unsubscribe_email",
    "Unsubscribe from a mailing list. Uses RFC 8058 one-click POST when offered, else sends the List-Unsubscribe mailto from this account. Returns status: confirmed | sent | needs_manual_click (links in manualLinks) | failed. Only confirmed/sent count as done.",
    {
      account: z
        .string()
        .describe("Email address of the account this message belongs to"),
      message_id: z
        .string()
        .describe("The Gmail message ID to unsubscribe from"),
    },
    async ({ account, message_id }) => {
      const gmail = await getGmailServiceForAccount(account);
      const result = await gmail.unsubscribeEmail(message_id);
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account, ...result }, null, 2),
          },
        ],
      };
    }
  );

  // ---- compose fields shared by create_draft and send_email ----
  const addressList = z
    .array(z.string())
    .optional();
  const composeFields = {
    account: z
      .string()
      .describe("Email address of the connected account to write from (not 'all')"),
    to: addressList.describe(
      "Recipients, e.g. ['jane@example.com', 'Bob <bob@example.com>']. Optional when replying: defaults to the original sender."
    ),
    cc: addressList.describe("Cc recipients"),
    bcc: addressList.describe("Bcc recipients"),
    subject: z
      .string()
      .optional()
      .describe("Subject line. Optional when replying: defaults to 'Re: <original subject>'."),
    body: z.string().describe("Plain text body"),
    html_body: z
      .string()
      .optional()
      .describe("Optional HTML version of the body. The plain text body is still sent as the fallback."),
    reply_to_message_id: z
      .string()
      .optional()
      .describe("Gmail message ID to reply to. Keeps the message in the same thread with proper reply headers."),
    reply_all: z
      .boolean()
      .default(false)
      .describe("When replying without 'to', also include the original To and Cc recipients (except yourself)."),
  };

  const toCompose = (a: any) => ({
    to: a.to,
    cc: a.cc,
    bcc: a.bcc,
    subject: a.subject,
    body: a.body,
    htmlBody: a.html_body,
    replyToMessageId: a.reply_to_message_id,
    replyAll: a.reply_all,
  });

  const singleAccount = (account: string) => {
    if (account.toLowerCase() === "all") {
      throw new Error("Pick one account to write from; 'all' is only for reading.");
    }
    return resolveAccounts(account)[0];
  };

  // ---- create_draft ----
  server.tool(
    "create_draft",
    "Create a draft email in a connected Gmail account. Nothing is sent. The draft appears in that account's Drafts folder, where it can be reviewed, edited or sent (also with send_email and draft_id). Supports replies in a thread via reply_to_message_id.",
    composeFields,
    async (args) => {
      const email = singleAccount(args.account);
      const gmail = await getGmailServiceForAccount(email);
      const draft = await gmail.createDraft(toCompose(args));
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account: email, status: "draft_created", ...draft }, null, 2),
          },
        ],
      };
    }
  );

  // ---- send_email ----
  server.tool(
    "send_email",
    "Send an email from a connected Gmail account. This delivers immediately and cannot be undone. Either compose a new message (to, subject, body) or pass draft_id to send an existing draft as saved. Supports replies in a thread via reply_to_message_id.",
    {
      ...composeFields,
      body: z
        .string()
        .optional()
        .describe("Plain text body. Required unless draft_id is given."),
      draft_id: z
        .string()
        .optional()
        .describe("Send this existing draft exactly as saved. When set, all other compose fields must be left out."),
    },
    async (args) => {
      const email = singleAccount(args.account);
      const gmail = await getGmailServiceForAccount(email);
      let sent;
      if (args.draft_id) {
        const composed = ["to", "cc", "bcc", "subject", "body", "html_body", "reply_to_message_id"].filter(
          (k) => (args as any)[k] !== undefined
        );
        if (composed.length) {
          throw new Error(`draft_id sends the draft as saved; remove ${composed.join(", ")} or edit the draft first.`);
        }
        sent = await gmail.sendDraft(args.draft_id);
      } else {
        if (args.body === undefined) throw new Error("body is required when not sending a draft.");
        sent = await gmail.sendEmail(toCompose(args));
      }
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ account: email, status: "sent", ...sent }, null, 2),
          },
        ],
      };
    }
  );

  // ---- batch_process ----
  server.tool(
    "batch_process",
    "Fetch a batch of emails matching a query for triage. Returns structured data so you can decide which actions to take on each email. Use account='all' to scan all accounts.",
    {
      account: z
        .string()
        .describe(
          "Email address of the account to search, or 'all' for every connected account"
        ),
      query: z
        .string()
        .describe(
          "Gmail search query (e.g. 'is:unread category:promotions', 'newer_than:7d')"
        ),
      max_results: z
        .number()
        .min(1)
        .max(100)
        .default(20)
        .describe("Maximum number of emails to fetch per account"),
    },
    async ({ account, query, max_results }) => {
      const accounts = resolveAccounts(account);
      const allResults: Array<{ account: string; emails: any[] }> = [];

      for (const email of accounts) {
        try {
          const gmail = await getGmailServiceForAccount(email);
          const emails = await gmail.batchProcess(query, max_results);
          allResults.push({ account: email, emails });
        } catch (err: any) {
          allResults.push({ account: email, emails: [] });
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                total: allResults.reduce((n, r) => n + r.emails.length, 0),
                query,
                results: allResults,
                hint: "Review each email and decide whether to archive, label, unsubscribe, or skip. Use the individual tools with the correct account parameter.",
              },
              null,
              2
            ),
          },
        ],
      };
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Public pages for Google's OAuth consent screen (no auth, no token store).
app.use(legalRouter);

// Serverless instances do not share memory, so read the accounts fresh.
app.use(async (_req, _res, next) => {
  try {
    await tokenStore.refresh();
    next();
  } catch (err) {
    next(err);
  }
});

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function secretMatches(given: string | undefined): boolean {
  if (!MCP_SECRET || !given) return false;
  const a = Buffer.from(given);
  const b = Buffer.from(MCP_SECRET);
  return a.length === b.length && timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------------
// Admin login (see admin-auth.ts)
// ---------------------------------------------------------------------------

app.use(["/setup", "/oauth"], adminHeaders);

const PAGE_STYLE = `
  body { font-family: system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; }
  h1 { font-size: 1.5rem; }
  table { width: 100%; border-collapse: collapse; margin: 20px 0; }
  th, td { text-align: left; padding: 10px; border-bottom: 1px solid #eee; }
  th { font-weight: 600; border-bottom: 2px solid #ddd; }
  input { padding: 10px; width: 100%; box-sizing: border-box; margin-bottom: 12px; font-size: 15px; }
  .btn { display: inline-block; padding: 10px 24px; background: #4285f4; color: white; border: 0; text-decoration: none; border-radius: 6px; font-size: 14px; cursor: pointer; }
  .btn:hover { background: #3367d6; }
  .link { background: none; border: 0; color: #4285f4; cursor: pointer; padding: 0; font-size: 13px; }
  .msg { padding: 12px; background: #e8f5e9; border-radius: 6px; margin-bottom: 16px; }
  .msg.error { background: #fce4ec; }
  .warn { padding: 12px; background: #fff8e1; border-radius: 6px; margin-bottom: 16px; }
  code { word-break: break-all; }
`;

function shell(title: string, body: string): string {
  return `<!DOCTYPE html><html><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex" /><title>${title}</title><style>${PAGE_STYLE}</style></head><body>${body}</body></html>`;
}

function loginPage(error?: string): string {
  return shell("Gmail MCP — Admin Login", `
    <div style="max-width:360px;margin:60px auto">
      <h1>Admin Login</h1>
      ${error ? `<div class="msg error">${escapeHtml(error)}</div>` : ""}
      ${passwordConfigured ? `
      <form method="POST" action="/setup/login" autocomplete="on">
        <input type="password" name="password" placeholder="Admin password" autocomplete="current-password" required autofocus />
        ${totpEnabled ? `<input type="text" name="code" placeholder="6-digit authenticator code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required />` : ""}
        <button class="btn" type="submit" style="width:100%">Log in</button>
      </form>` : `<div class="msg error">ADMIN_PASSWORD is not set on the server, so the admin page is disabled.</div>`}
    </div>`);
}

app.get("/setup/login", (req: Request, res: Response) => {
  if (readSession(req)) {
    res.redirect(303, "/setup");
    return;
  }
  res.send(loginPage());
});

app.post("/setup/login", async (req: Request, res: Response) => {
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  const code = typeof req.body?.code === "string" ? req.body.code : "";
  const result = await attemptLogin(req, password, code);

  if (result === "ok") {
    startSession(res);
    res.redirect(303, "/setup");
    return;
  }
  const messages: Record<Exclude<LoginResult, "ok">, [number, string]> = {
    locked: [429, "Too many failed attempts. Try again in 15 minutes."],
    bad: [401, totpEnabled ? "Wrong password or code." : "Wrong password."],
    "not-configured": [503, "ADMIN_PASSWORD is not set on the server."],
  };
  const [status, msg] = messages[result];
  console.warn(`[admin] login ${result} from ${clientIp(req)}`);
  res.status(status).send(loginPage(msg));
});

app.post("/setup/logout", requireAdmin, requireCsrf, (_req: Request, res: Response) => {
  endSession(res);
  res.redirect(303, "/setup/login");
});

// ---------------------------------------------------------------------------
// Setup page — manage connected Gmail accounts
// ---------------------------------------------------------------------------

app.get("/setup", requireAdmin, (req: Request, res: Response) => {
  const { csrf } = res.locals.adminSession as AdminSession;
  const accounts = tokenStore.listAccounts();
  const message = req.query.message as string | undefined;
  const csrfField = `<input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />`;

  const accountRows = accounts.length > 0
    ? accounts
        .map(
          (a) => `
        <tr>
          <td>${escapeHtml(a.email)}</td>
          <td>${new Date(a.addedAt).toLocaleDateString()}</td>
          <td>
            <form method="POST" action="/setup/remove" style="display:inline" onsubmit="return confirm('Remove this account?')">
              ${csrfField}
              <input type="hidden" name="email" value="${escapeHtml(a.email)}" />
              <button type="submit" style="color:red;background:none;border:1px solid red;padding:4px 12px;cursor:pointer">Remove</button>
            </form>
          </td>
        </tr>`
        )
        .join("")
    : `<tr><td colspan="3" style="text-align:center;color:#888">No accounts connected yet</td></tr>`;

  const warnings = [
    passwordIsWeak
      ? `Your ADMIN_PASSWORD is shorter than ${MIN_PASSWORD_LENGTH} characters. Set a longer random one in Vercel → Settings → Environment Variables, then redeploy.`
      : "",
    !totpEnabled
      ? `Two-step login is off. <a href="/setup/2fa">Turn on authenticator-app codes</a> so a leaked password alone is not enough.`
      : "",
  ].filter(Boolean);

  res.send(shell("Gmail MCP — Setup", `
      <form method="POST" action="/setup/logout" style="float:right">${csrfField}<button class="link" type="submit">Log out</button></form>
      <h1>Gmail MCP Server — Setup</h1>
      ${warnings.map((w) => `<div class="warn">${w}</div>`).join("")}
      ${message ? `<div class="msg">${escapeHtml(message)}</div>` : ""}
      <table>
        <thead><tr><th>Account</th><th>Added</th><th></th></tr></thead>
        <tbody>${accountRows}</tbody>
      </table>
      <form method="POST" action="/oauth/start">${csrfField}<button class="btn" type="submit">+ Add Gmail Account</button></form>
      <hr style="margin-top:40px;border:none;border-top:1px solid #eee" />
      <details style="color:#888;font-size:13px">
        <summary>MCP endpoint (keep secret)</summary>
        <code>${escapeHtml(`${SERVER_URL}/mcp/${MCP_SECRET}`)}</code>
      </details>
      <p style="color:#888;font-size:13px">Connected accounts: ${accounts.length} · Two-step login: ${totpEnabled ? "on" : "off"}</p>
  `));
});

app.post("/setup/remove", requireAdmin, requireCsrf, async (req: Request, res: Response) => {
  const email = req.body.email;

  if (email && tokenStore.hasAccount(email)) {
    await tokenStore.removeAccount(email);
    res.redirect(303, `/setup?message=${encodeURIComponent(`Removed ${email}`)}`);
  } else {
    res.redirect(303, `/setup?message=${encodeURIComponent("Account not found")}`);
  }
});

// Two-step login setup: shows a fresh secret to add to an authenticator app and
// to Vercel as ADMIN_TOTP_SECRET. Nothing is saved on the server here.
app.get("/setup/2fa", requireAdmin, (_req: Request, res: Response) => {
  const { csrf } = res.locals.adminSession as AdminSession;
  if (totpEnabled) {
    res.send(shell("Two-step login", `<h1>Two-step login is on</h1>
      <p>To change the authenticator, remove <code>ADMIN_TOTP_SECRET</code> in Vercel, redeploy, and come back here.</p>
      <p><a href="/setup">← Back</a></p>`));
    return;
  }
  const secret = newTotpSecret();
  const uri = `otpauth://totp/${encodeURIComponent("Gmail MCP:admin")}?secret=${secret}&issuer=${encodeURIComponent("Gmail MCP")}`;
  res.send(shell("Turn on two-step login", `
    <h1>Turn on two-step login</h1>
    <ol>
      <li>Open Google Authenticator, Microsoft Authenticator or your password manager and add an account using this setup key:<br/>
        <code style="font-size:18px;letter-spacing:2px">${secret.replace(/(.{4})/g, "$1 ").trim()}</code><br/>
        <small style="color:#888">(or this link: <code>${escapeHtml(uri)}</code>)</small></li>
      <li>Type the 6-digit code it shows to check it works:
        <form method="POST" action="/setup/2fa/check">
          <input type="hidden" name="csrf" value="${escapeHtml(csrf)}" />
          <input type="hidden" name="secret" value="${secret}" />
          <input type="text" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required placeholder="123456" />
          <button class="btn" type="submit">Check code</button>
        </form></li>
    </ol>
    <p><a href="/setup">← Back</a></p>`));
});

app.post("/setup/2fa/check", requireAdmin, requireCsrf, (req: Request, res: Response) => {
  const secret = String(req.body.secret || "");
  const code = String(req.body.code || "").trim();
  if (matchTotp(code, secret) === null) {
    res.status(400).send(shell("Code didn't match", `<h1>That code didn't match</h1>
      <p>Check the phone's clock is set automatically, then <a href="/setup/2fa">start again</a>.</p>`));
    return;
  }
  res.send(shell("Code works", `<h1>The code works ✓</h1>
    <p>Last step — in Vercel, open <b>gmail-mcp-server → Settings → Environment Variables</b> and add:</p>
    <p>Name: <code>ADMIN_TOTP_SECRET</code><br/>Value: <code>${escapeHtml(secret)}</code></p>
    <p>Save it, then redeploy. From then on, logging in needs the password <b>and</b> the code from your app.</p>
    <p><a href="/setup">← Back</a></p>`));
});

// ---------------------------------------------------------------------------
// OAuth flow — server-managed Google auth
// ---------------------------------------------------------------------------

app.post("/oauth/start", requireAdmin, requireCsrf, (_req: Request, res: Response) => {
  const oauth2 = makeOAuth2Client();
  const url = oauth2.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
    state: newOAuthState(res), // random, checked against a cookie on return
  });

  res.redirect(303, url);
});

app.get("/oauth/callback", requireAdmin, async (req: Request, res: Response) => {
  const code = req.query.code as string;
  const error = req.query.error as string;
  const back = (msg: string) => res.redirect(303, `/setup?message=${encodeURIComponent(msg)}`);

  if (!checkOAuthState(req, res)) {
    back("Sign-in link expired or was not started from this page. Please try again.");
    return;
  }
  if (error) {
    back(`OAuth error: ${error}`);
    return;
  }
  if (!code) {
    back("No authorization code received");
    return;
  }

  try {
    const oauth2 = makeOAuth2Client();
    const { tokens } = await oauth2.getToken(code);

    if (!tokens.refresh_token) {
      back("No refresh token received. Try removing the app from your Google account permissions and re-adding.");
      return;
    }

    // Get the user's email address
    oauth2.setCredentials(tokens);
    const oauth2Api = google.oauth2({ version: "v2", auth: oauth2 });
    const userInfo = await oauth2Api.userinfo.get();
    const email = userInfo.data.email;

    if (!email) {
      back("Could not determine email address");
      return;
    }

    await tokenStore.addAccount(email, tokens.refresh_token);
    back(`Successfully connected ${email}`);
  } catch (err: any) {
    console.error("[oauth/callback] Error:", err);
    back(`Error: ${err.message}`);
  }
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    accounts: tokenStore.size,
  });
});

// ---------------------------------------------------------------------------
// MCP transport — Streamable HTTP (stateless: each request gets a fresh server)
// ---------------------------------------------------------------------------

app.post("/mcp/:secret", async (req: Request, res: Response) => {
  if (!secretMatches(req.params.secret as string)) {
    res.status(404).send("Not found");
    return;
  }
  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless — no session tracking
    });

    const mcpServer = createMcpServer();
    await mcpServer.connect(transport);

    await transport.handleRequest(req, res, req.body);

    // Clean up after response is sent
    res.on("close", () => {
      mcpServer.close().catch(() => {});
      transport.close().catch(() => {});
    });
  } catch (err: any) {
    console.error("[mcp] Error handling request:", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: err.message },
        id: null,
      });
    }
  }
});

app.get("/mcp/:secret", async (req: Request, res: Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "SSE streams not supported in stateless mode. Use POST." },
    id: null,
  });
});

app.delete("/mcp/:secret", async (req: Request, res: Response) => {
  res.status(405).json({
    jsonrpc: "2.0",
    error: { code: -32000, message: "Session management not used in stateless mode." },
    id: null,
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

export default app;

// Vercel imports the app; anywhere else, listen as before.
if (!process.env.VERCEL) app.listen(PORT, () => {
  console.log(`Gmail MCP server listening on port ${PORT}`);
  console.log(`  MCP endpoint:  ${SERVER_URL}/mcp/<MCP_SECRET>`);
  console.log(`  Setup page:    ${SERVER_URL}/setup`);
  console.log(`  Health check:  ${SERVER_URL}/health`);
  console.log(`  Accounts:      ${tokenStore.size}`);
});
