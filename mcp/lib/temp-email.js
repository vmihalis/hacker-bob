"use strict";

const tempMailboxes = new Map();

const TEMP_EMAIL_PROVIDERS = ["mail.tm", "guerrillamail"];

const BROWSER_HEADERS = {
  "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Accept": "application/json, text/plain, */*",
  "Accept-Language": "en-US,en;q=0.9",
};

function generatePassword(len = 16) {
  const chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%";
  let pw = "";
  for (let i = 0; i < len; i++) pw += chars[Math.floor(Math.random() * chars.length)];
  return pw;
}

function generateUsername(len = 10) {
  const chars = "abcdefghijkmnpqrstuvwxyz23456789";
  let name = "hunt_";
  for (let i = 0; i < len; i++) name += chars[Math.floor(Math.random() * chars.length)];
  return name;
}

async function failDetail(resp, prefix) {
  let body = "";
  try { body = (await resp.text()).slice(0, 200); } catch { /* ignore */ }
  return `${prefix}: HTTP ${resp.status}${body ? ` — ${body}` : ""}`;
}

async function tempEmailCreate(preferredProvider) {
  const providers = preferredProvider
    ? [preferredProvider, ...TEMP_EMAIL_PROVIDERS.filter((p) => p !== preferredProvider)]
    : [...TEMP_EMAIL_PROVIDERS];
  const tried = [];

  for (const provider of providers) {
    try {
      if (provider === "mail.tm") {
        // Get available domain
        const domainResp = await fetch("https://api.mail.tm/domains", {
          headers: { ...BROWSER_HEADERS, Accept: "application/json" },
        });
        if (!domainResp.ok) throw new Error(await failDetail(domainResp, "mail.tm domains"));
        const domainData = await domainResp.json();
        const domains = domainData["hydra:member"] || domainData.member || [];
        if (!domains.length) throw new Error("mail.tm: no domains available");
        const emailDomain = domains[0].domain;
        const login = generateUsername();
        const password = generatePassword();
        const address = `${login}@${emailDomain}`;

        // Create account
        const createResp = await fetch("https://api.mail.tm/accounts", {
          method: "POST",
          headers: { ...BROWSER_HEADERS, "Content-Type": "application/json" },
          body: JSON.stringify({ address, password }),
        });
        if (!createResp.ok) throw new Error(await failDetail(createResp, "mail.tm create"));

        // Get auth token
        const tokenResp = await fetch("https://api.mail.tm/token", {
          method: "POST",
          headers: { ...BROWSER_HEADERS, "Content-Type": "application/json" },
          body: JSON.stringify({ address, password }),
        });
        if (!tokenResp.ok) throw new Error(await failDetail(tokenResp, "mail.tm token"));
        const tokenData = await tokenResp.json();

        const mailbox = { provider: "mail.tm", address, password, token: tokenData.token, domain: emailDomain, login };
        tempMailboxes.set(address, mailbox);
        return JSON.stringify({ success: true, email_address: address, password, provider: "mail.tm" });
      }

      if (provider === "guerrillamail") {
        const resp = await fetch("https://api.guerrillamail.com/ajax.php?f=get_email_address", {
          headers: BROWSER_HEADERS,
        });
        if (!resp.ok) throw new Error(await failDetail(resp, "guerrillamail get_email_address"));
        const data = await resp.json();
        const address = data.email_addr;
        if (!address) throw new Error("guerrillamail: no email_addr in response");
        const sidToken = data.sid_token;
        if (!sidToken) throw new Error("guerrillamail: no sid_token in response");
        const [login, emailDomain] = address.split("@");
        const password = generatePassword();

        const mailbox = { provider: "guerrillamail", address, password, token: sidToken, domain: emailDomain, login };
        tempMailboxes.set(address, mailbox);
        return JSON.stringify({ success: true, email_address: address, password, provider: "guerrillamail" });
      }
    } catch (err) {
      tried.push({ provider, error: err.message || String(err) });
    }
  }

  return JSON.stringify({ success: false, error: "All temp email providers failed", providers_tried: tried });
}

async function tempEmailPoll(emailAddress, fromFilter) {
  const mailbox = tempMailboxes.get(emailAddress);
  if (!mailbox) return JSON.stringify({ error: `Unknown email address: ${emailAddress}. Call create first.` });

  try {
    let messages = [];

    if (mailbox.provider === "mail.tm") {
      const resp = await fetch("https://api.mail.tm/messages", {
        headers: { ...BROWSER_HEADERS, Authorization: `Bearer ${mailbox.token}`, Accept: "application/json" },
      });
      if (!resp.ok) return JSON.stringify({ error: await failDetail(resp, "mail.tm poll") });
      const data = await resp.json();
      messages = (data["hydra:member"] || data.member || []).map((m) => ({
        id: m.id || m["@id"],
        from: m.from?.address || "",
        subject: m.subject || "",
        date: m.createdAt || "",
      }));
    }

    if (mailbox.provider === "guerrillamail") {
      const resp = await fetch(
        `https://api.guerrillamail.com/ajax.php?f=check_email&seq=0&sid_token=${encodeURIComponent(mailbox.token)}`,
        { headers: BROWSER_HEADERS }
      );
      if (!resp.ok) return JSON.stringify({ error: await failDetail(resp, "guerrillamail poll") });
      const data = await resp.json();
      messages = (data.list || []).map((m) => ({
        id: String(m.mail_id),
        from: m.mail_from || "",
        subject: m.mail_subject || "",
        date: m.mail_date || "",
      }));
    }

    if (fromFilter) {
      const filter = fromFilter.toLowerCase();
      messages = messages.filter((m) => m.from.toLowerCase().includes(filter));
    }

    return JSON.stringify({ success: true, messages });
  } catch (err) {
    return JSON.stringify({ error: err.message || String(err) });
  }
}

async function tempEmailExtract(emailAddress, messageId) {
  const mailbox = tempMailboxes.get(emailAddress);
  if (!mailbox) return JSON.stringify({ error: `Unknown email address: ${emailAddress}. Call create first.` });

  try {
    let bodyText = "";

    if (mailbox.provider === "mail.tm") {
      const resp = await fetch(`https://api.mail.tm/messages/${encodeURIComponent(messageId)}`, {
        headers: { ...BROWSER_HEADERS, Authorization: `Bearer ${mailbox.token}`, Accept: "application/json" },
      });
      if (!resp.ok) return JSON.stringify({ error: await failDetail(resp, "mail.tm read") });
      const data = await resp.json();
      bodyText = data.text || data.html || "";
    }

    if (mailbox.provider === "guerrillamail") {
      const resp = await fetch(
        `https://api.guerrillamail.com/ajax.php?f=fetch_email&email_id=${encodeURIComponent(messageId)}&sid_token=${encodeURIComponent(mailbox.token)}`,
        { headers: BROWSER_HEADERS }
      );
      if (!resp.ok) return JSON.stringify({ error: await failDetail(resp, "guerrillamail read") });
      const data = await resp.json();
      bodyText = data.mail_body || "";
    }

    // Strip HTML tags for code extraction
    const plainText = bodyText.replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ");

    // Extract verification codes (4-8 digit numbers)
    const codeMatches = plainText.match(/\b(\d{4,8})\b/g) || [];
    const verificationCodes = [...new Set(codeMatches)];

    // Extract verification links
    const linkPattern = /https?:\/\/[^\s"'<>]+(?:verify|confirm|activate|token|code|validate|email)[^\s"'<>]*/gi;
    const linkMatches = bodyText.match(linkPattern) || [];
    const verificationLinks = [...new Set(linkMatches)];

    return JSON.stringify({
      success: true,
      verification_codes: verificationCodes,
      verification_links: verificationLinks,
      raw_text_preview: plainText.slice(0, 500),
    });
  } catch (err) {
    return JSON.stringify({ error: err.message || String(err) });
  }
}

async function tempEmail(args) {
  const op = args.operation;
  if (op === "create") return tempEmailCreate(args.provider);
  if (op === "poll") return tempEmailPoll(args.email_address, args.from_filter);
  if (op === "extract") return tempEmailExtract(args.email_address, args.message_id);
  return JSON.stringify({ error: `Unknown operation: ${op}` });
}

module.exports = {
  tempEmail,
  tempEmailCreate,
  tempEmailExtract,
  tempEmailPoll,
};
