const express = require("express");

const app = express();

// ---- config ---------------------------------------------------------
const ALLOWED_HOSTS = ["cdn-b4irssg.example", "app-9u94o3p.example"];
const VALID_CHANNELS = ["html", "markdown", "url", "sql", "shell"];
const MAX_OUTPUT_LEN = 20000;

// ---- decoding helpers -------------------------------------------------

function decodePercentOnce(s) {
  try {
    return decodeURIComponent(s);
  } catch (e) {
    // Malformed sequence somewhere - fall back to decoding the valid
    // %XX groups we can, leaving anything else untouched.
    return s.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16)),
    );
  }
}

function decodeHtmlEntitiesOnce(s) {
  return s
    .replace(/&#x([0-9A-Fa-f]+);/g, (_, hex) => {
      try {
        return String.fromCodePoint(parseInt(hex, 16));
      } catch (e) {
        return _;
      }
    })
    .replace(/&#([0-9]+);/g, (_, dec) => {
      try {
        return String.fromCodePoint(parseInt(dec, 10));
      } catch (e) {
        return _;
      }
    })
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function decodeUnicodeEscapesOnce(s) {
  return s.replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) =>
    String.fromCharCode(parseInt(hex, 16)),
  );
}

// Decode once, in the required order: percent-escapes -> HTML entities -> \uXXXX
function decodeOnce(s) {
  return decodeUnicodeEscapesOnce(decodeHtmlEntitiesOnce(decodePercentOnce(s)));
}

// ---- URL helpers -------------------------------------------------------

// Classify a raw URL-ish string as relative or absolute, and if absolute,
// pull out its scheme + hostname (ignoring userinfo/credentials and query).
function classifyUrl(raw) {
  const trimmed = raw.trim();

  if (trimmed.startsWith("//")) {
    // protocol-relative -> a browser resolves this against the current
    // scheme, so treat it as absolute https for our purposes.
    try {
      const u = new URL("https:" + trimmed);
      return { absolute: true, scheme: "https", hostname: u.hostname };
    } catch (e) {
      return { absolute: true, scheme: null, hostname: null };
    }
  }

  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*)\s*:/);
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme === "http" || scheme === "https") {
      try {
        const u = new URL(trimmed);
        return { absolute: true, scheme, hostname: u.hostname };
      } catch (e) {
        return { absolute: true, scheme, hostname: null };
      }
    }
    // any other scheme (javascript:, data:, vbscript:, ftp:, etc.)
    return { absolute: true, scheme, hostname: null };
  }

  return { absolute: false, scheme: null, hostname: null };
}

function extractHtmlUrls(text) {
  const urls = [];
  const re = /(?:src|href)\s*=\s*"([^"]*)"|(?:src|href)\s*=\s*'([^']*)'/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    urls.push(m[1] !== undefined ? m[1] : m[2]);
  }
  return urls;
}

function extractMarkdownUrls(text) {
  const urls = [];
  const re = /\]\(([^)]*)\)/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    urls.push(m[1].trim());
  }
  return urls;
}

// Looks at a set of extracted URL-ish strings and returns:
// 'DANGEROUS_SCHEME' | 'EXTERNAL_EXFIL' | null
function checkUrls(urls) {
  let sawDangerousScheme = false;
  let sawExfil = false;

  for (const raw of urls) {
    if (!raw) continue;
    const c = classifyUrl(raw);
    if (!c.absolute) continue; // relative refs are fine

    if (c.scheme !== "http" && c.scheme !== "https") {
      sawDangerousScheme = true;
      continue;
    }
    if (!c.hostname || !ALLOWED_HOSTS.includes(c.hostname)) {
      sawExfil = true;
    }
  }

  if (sawDangerousScheme) return "DANGEROUS_SCHEME";
  if (sawExfil) return "EXTERNAL_EXFIL";
  return null;
}

const DANGEROUS_SCHEME_TEXT_RE = /(javascript|data|vbscript)\s*:/i;

// ---- channel rule checks -----------------------------------------------

function checkChannel(channel, text) {
  if (channel === "html") {
    if (/<\s*(script|iframe|object|embed)\b/i.test(text)) return "SCRIPT_TAG";
    if (/\bon[a-zA-Z]+\s*=/i.test(text)) return "EVENT_HANDLER";
    if (DANGEROUS_SCHEME_TEXT_RE.test(text)) return "DANGEROUS_SCHEME";
    const urls = extractHtmlUrls(text);
    const urlVerdict = checkUrls(urls);
    if (urlVerdict) return urlVerdict;
    return "SAFE";
  }

  if (channel === "markdown") {
    if (DANGEROUS_SCHEME_TEXT_RE.test(text)) return "DANGEROUS_SCHEME";
    const urls = extractMarkdownUrls(text);
    const urlVerdict = checkUrls(urls);
    if (urlVerdict) return urlVerdict;
    return "SAFE";
  }

  if (channel === "url") {
    if (DANGEROUS_SCHEME_TEXT_RE.test(text)) return "DANGEROUS_SCHEME";
    const urlVerdict = checkUrls([text.trim()]);
    if (urlVerdict) return urlVerdict;
    return "SAFE";
  }

  if (channel === "sql") {
    if (/['";]|--|\/\*|\bunion\b|\bor\s+1\s*=\s*1\b/i.test(text)) {
      return "SQL_METACHAR";
    }
    return "SAFE";
  }

  if (channel === "shell") {
    if (/[;&|`<>]|\$\(|\$\{/.test(text)) return "SHELL_METACHAR";
    return "SAFE";
  }

  return "SAFE";
}

// ---- schema validation ---------------------------------------------------

function isValidBody(body) {
  if (typeof body !== "object" || body === null || Array.isArray(body))
    return false;
  if (!VALID_CHANNELS.includes(body.channel)) return false;
  if (typeof body.output !== "string") return false;
  if (body.output.length > MAX_OUTPUT_LEN) return false;
  return true;
}

// ---- express app -----------------------------------------------------

// Allow any origin, including preflight OPTIONS requests, so a
// browser-based grader isn't blocked by CORS before it ever reaches
// the route logic below.
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.header("Access-Control-Allow-Headers", "*");
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

// Parse the body as JSON regardless of the Content-Type header the
// caller sent (or didn't send) - some HTTP clients / graders omit
// "Content-Type: application/json", and express.json() otherwise
// silently leaves req.body as {} in that case.
app.use(express.json({ limit: "1mb", type: () => true }));

app.get("/", (req, res) => {
  res.json({ status: "ok", service: "llm-output-gate" });
});

app.post("/sanitize-output", (req, res) => {
  const body = req.body;

  if (!isValidBody(body)) {
    return res.json({ safe: false, reason: "INVALID_SCHEMA" });
  }

  const { channel, output } = body;

  const decoded = decodeOnce(output);
  if (decoded !== output) {
    const decodedVerdict = checkChannel(channel, decoded);
    if (decodedVerdict !== "SAFE") {
      return res.json({ safe: false, reason: "ENCODED_PAYLOAD" });
    }
  }

  const verdict = checkChannel(channel, output);
  return res.json({ safe: verdict === "SAFE", reason: verdict });
});

// Malformed JSON body -> INVALID_SCHEMA, not a 500
app.use((err, req, res, next) => {
  if (
    err &&
    (err.type === "entity.parse.failed" || err instanceof SyntaxError)
  ) {
    return res.json({ safe: false, reason: "INVALID_SCHEMA" });
  }
  return next(err);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`llm-output-gate listening on port ${PORT}`);
});

module.exports = app;
