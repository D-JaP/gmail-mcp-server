import { Router, Request, Response } from "express";

// Public pages required by Google's OAuth consent screen: home page,
// privacy policy and terms of service. No authentication, no database access.

const UPDATED = "8 November 2026";
const CONTACT = "dzung.leanh218@gmail.com";

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${title} – HarryMCPMAIL</title>
<style>
  body{font-family:system-ui,sans-serif;max-width:720px;margin:48px auto;padding:0 20px;line-height:1.6;color:#1a1a1a}
  h1{font-size:1.8rem} h2{font-size:1.2rem;margin-top:1.8rem}
  nav a{margin-right:16px} footer{margin-top:3rem;color:#666;font-size:.9rem}
</style>
</head>
<body>
<nav><a href="/">Home</a><a href="/privacy">Privacy Policy</a><a href="/terms">Terms of Service</a></nav>
${body}
<footer>Last updated ${UPDATED}. Contact: <a href="mailto:${CONTACT}">${CONTACT}</a></footer>
</body>
</html>`;
}

const home = `
<h1>HarryMCPMAIL</h1>
<p>HarryMCPMAIL is a small, privately operated server that lets its owner's AI assistant
(through the Model Context Protocol) work with the owner's own Gmail accounts: search and read
email, create drafts, send email, apply labels and archive messages.</p>
<p>It is not a public service. Only Google accounts that the owner has connected can be used.
You are shown a Google sign-in screen only if the owner asked you to connect an account.</p>
<h2>How Google user data is used</h2>
<p>The app requests access to Gmail (read and modify) and to your email address. It uses that access only to carry out
actions the account owner asks their assistant to perform. See the <a href="/privacy">Privacy Policy</a>.</p>
`;

const privacy = `
<h1>Privacy Policy</h1>
<p>This policy describes how HarryMCPMAIL ("the app") handles information when a Google account is connected to it.</p>

<h2>Information the app accesses</h2>
<ul>
  <li>Your Google account email address, to identify which account is connected.</li>
  <li>Gmail data (messages, threads, labels, drafts and attachments' metadata), only when the account owner asks the assistant
  to read, search, draft, send, label or archive email.</li>
</ul>

<h2>Information the app stores</h2>
<p>The app stores only the OAuth refresh token for each connected account, together with the account's email address, in a
private database that only the app can access. Email content is <strong>not</strong> stored; it is fetched from Gmail when requested and
returned to the account owner's assistant for that request only.</p>

<h2>How information is used</h2>
<p>Gmail data is used only to perform the action the account owner requested. It is not used for advertising, is not sold, and is not
used to train generalized artificial intelligence or machine learning models.</p>

<h2>Sharing</h2>
<p>The app does not share Google user data with third parties. Data passes only between Google, the app's server, and the account owner's
AI assistant that the owner has chosen to use. Human access to the data is limited to the account owner.</p>
<p>The app's use of information received from Google APIs adheres to the
<a href="https://developers.google.com/terms/api-services-user-data-policy">Google API Services User Data Policy</a>,
including the Limited Use requirements.</p>

<h2>Retention and deletion</h2>
<p>Tokens are kept until the account is removed from the app. You can revoke the app's access at any time at
<a href="https://myaccount.google.com/permissions">myaccount.google.com/permissions</a>, or ask the owner to remove your account, at which point the stored token is deleted.</p>

<h2>Security</h2>
<p>Access to the administration page and to the assistant endpoint is protected by secrets, and all traffic uses HTTPS.</p>

<h2>Contact</h2>
<p>Questions or deletion requests: <a href="mailto:${CONTACT}">${CONTACT}</a>.</p>
`;

const terms = `
<h1>Terms of Service</h1>
<p>HarryMCPMAIL is a private tool operated by its owner for personal and business use. By connecting a Google account you agree to the following.</p>
<h2>Use</h2>
<p>The app may only be used with accounts you own or are authorised to access. Actions are carried out at the request of the account owner's AI assistant,
including reading, drafting, sending, labelling and archiving email.</p>
<h2>No warranty</h2>
<p>The app is provided "as is", without warranty of any kind. The owner is not liable for loss or damage arising from its use, including
actions taken by an AI assistant on your behalf.</p>
<h2>Access and revocation</h2>
<p>You can stop using the app and revoke its access at any time at
<a href="https://myaccount.google.com/permissions">myaccount.google.com/permissions</a>. The owner may disconnect any account at any time.</p>
<h2>Changes</h2>
<p>These terms may be updated; the date at the bottom of the page shows the latest version.</p>
<h2>Contact</h2>
<p><a href="mailto:${CONTACT}">${CONTACT}</a></p>
`;

export const legalRouter = Router();

legalRouter.get("/", (_req: Request, res: Response) => {
  res.type("html").send(page("Home", home));
});
legalRouter.get("/privacy", (_req: Request, res: Response) => {
  res.type("html").send(page("Privacy Policy", privacy));
});
legalRouter.get("/terms", (_req: Request, res: Response) => {
  res.type("html").send(page("Terms of Service", terms));
});
