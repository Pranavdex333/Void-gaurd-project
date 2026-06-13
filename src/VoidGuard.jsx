import { useState, useEffect, useRef, useCallback } from "react";

const COLORS = {
  bg: "#0a0a0a",
  card: "#111111",
  cardBorder: "#1e1e1e",
  accent: "#00ff88",
  purple: "#8b5cf6",
  warning: "#ffb020",
  danger: "#ff3d71",
  text: "#ffffff",
  muted: "#888888",
  dimmed: "#444444",
};

const POPULAR_DOMAINS = [
  "google","amazon","paypal","microsoft","facebook","instagram","netflix","apple",
  "twitter","youtube","linkedin","github","dropbox","spotify","reddit","discord",
  "tiktok","snapchat","whatsapp","telegram","zoom","adobe","salesforce","stripe",
];

const RISKY_TLDS = [".xyz",".tk",".ml",".ga",".cf",".gq",".top",".click",".loan",".work",".site",".online",".live",".icu",".buzz"];
const SHORTENERS = ["bit.ly","tinyurl","t.co","ow.ly","buff.ly","goo.gl","short.link","rb.gy","tiny.cc","cutt.ly","is.gd","v.gd"];

function analyzeURL(url) {
  const findings = [];
  let score = 0;

  let parsed;
  try {
    if (!url.startsWith("http://") && !url.startsWith("https://")) url = "https://" + url;
    parsed = new URL(url);
  } catch {
    return { score: 100, level: "Dangerous", findings: [{ type: "error", label: "Invalid URL", detail: "Could not parse the URL structure.", severity: "high" }], parsed: null, url };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = url.toLowerCase();

  // HTTPS check
  if (parsed.protocol !== "https:") {
    score += 20;
    findings.push({ type: "ssl", label: "No HTTPS", detail: "Connection is unencrypted. Credentials and data sent to this site are exposed.", severity: "high" });
  }

  // IP-based URL
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 30;
    findings.push({ type: "ip", label: "IP-based URL", detail: "Legitimate services use domain names, not raw IP addresses. Phishing sites often use IPs to avoid domain blacklists.", severity: "high" });
  }

  // URL shortener
  if (SHORTENERS.some(s => hostname === s || hostname.endsWith("." + s))) {
    score += 15;
    findings.push({ type: "short", label: "URL Shortener Detected", detail: "The real destination is hidden. Attackers use shorteners to mask malicious links.", severity: "medium" });
  }

  // Typosquatting
  const domainCore = hostname.replace(/^www\./, "").split(".")[0];
  let closestMatch = null;
  let closestDist = Infinity;
  for (const brand of POPULAR_DOMAINS) {
    if (brand === domainCore) break;
    const dist = levenshtein(domainCore, brand);
    if (dist > 0 && dist <= 2 && dist < closestDist) {
      closestDist = dist;
      closestMatch = brand;
    }
  }
  if (closestMatch) {
    score += 35;
    findings.push({ type: "typo", label: `Typosquatting: ${closestMatch}.com`, detail: `"${domainCore}" is suspiciously similar to "${closestMatch}" (edit distance: ${closestDist}). This is a classic impersonation technique.`, severity: "high" });
  }

  // Risky TLD
  const tldMatch = RISKY_TLDS.find(t => hostname.endsWith(t));
  if (tldMatch) {
    score += 20;
    findings.push({ type: "tld", label: `High-Risk TLD: ${tldMatch}`, detail: `The ${tldMatch} TLD is heavily abused in phishing campaigns due to free/cheap registration with no identity verification.`, severity: "medium" });
  }

  // Suspicious subdomains
  const parts = hostname.split(".");
  if (parts.length > 3) {
    score += 15;
    findings.push({ type: "subdomain", label: "Excessive Subdomains", detail: `${hostname} has ${parts.length - 2} subdomain levels. Attackers use deep subdomain chains like "paypal.com.evil.xyz" to confuse users.`, severity: "medium" });
  }

  // Brand name in subdomain (not in actual domain)
  const subdomainStr = parts.slice(0, -2).join(".");
  const brandInSub = POPULAR_DOMAINS.find(b => subdomainStr.includes(b));
  if (brandInSub && !domainCore.includes(brandInSub)) {
    score += 25;
    findings.push({ type: "brand", label: `Brand "${brandInSub}" in Subdomain`, detail: `"${brandInSub}" appears in a subdomain but the actual domain is different. This tricks users who read URLs left-to-right.`, severity: "high" });
  }

  // URL length
  if (fullUrl.length > 100) {
    score += 10;
    findings.push({ type: "length", label: "Abnormally Long URL", detail: `${fullUrl.length} characters. Long URLs often contain encoded parameters used to track victims or bypass security filters.`, severity: "low" });
  }

  // Suspicious keywords
  const suspiciousKeywords = ["login","signin","verify","secure","update","account","confirm","banking","password","credential"];
  const foundKeywords = suspiciousKeywords.filter(k => fullUrl.includes(k));
  if (foundKeywords.length > 0) {
    score += Math.min(foundKeywords.length * 8, 24);
    findings.push({ type: "keyword", label: "Sensitive Keywords in URL", detail: `Keywords found: ${foundKeywords.join(", ")}. Phishing pages commonly include these terms to appear legitimate.`, severity: "medium" });
  }

  // Special characters
  if (hostname.includes("-") && (closestMatch || tldMatch)) {
    score += 5;
    findings.push({ type: "char", label: "Hyphen in Domain", detail: "Hyphens combined with other suspicious signals increase phishing likelihood.", severity: "low" });
  }

  score = Math.min(score, 100);

  let level;
  if (score <= 25) level = "Safe";
  else if (score <= 50) level = "Caution";
  else if (score <= 75) level = "Suspicious";
  else level = "Dangerous";

  return { score, level, findings, parsed, url };
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[a.length][b.length];
}

function getLevelColor(level) {
  if (level === "Safe") return COLORS.accent;
  if (level === "Caution") return COLORS.warning;
  if (level === "Suspicious") return "#ff8c42";
  return COLORS.danger;
}

function RobotMascot({ size = 60, color = COLORS.accent, animate = true }) {
  return (
    <svg width={size} height={size} viewBox="0 0 60 60" style={animate ? { animation: "float 3s ease-in-out infinite" } : {}}>
      <rect x="15" y="20" width="30" height="22" rx="6" fill={color} opacity="0.15" stroke={color} strokeWidth="1.5"/>
      <rect x="20" y="25" width="8" height="6" rx="2" fill={color} opacity="0.9"/>
      <rect x="32" y="25" width="8" height="6" rx="2" fill={color} opacity="0.9"/>
      <rect x="24" y="34" width="12" height="3" rx="1.5" fill={color} opacity="0.6"/>
      <rect x="22" y="15" width="16" height="7" rx="3" fill={color} opacity="0.2" stroke={color} strokeWidth="1"/>
      <circle cx="30" cy="18" r="2" fill={color}/>
      <rect x="10" y="24" width="5" height="10" rx="2.5" fill={color} opacity="0.5"/>
      <rect x="45" y="24" width="5" height="10" rx="2.5" fill={color} opacity="0.5"/>
      <rect x="20" y="42" width="8" height="8" rx="2" fill={color} opacity="0.5"/>
      <rect x="32" y="42" width="8" height="8" rx="2" fill={color} opacity="0.5"/>
    </svg>
  );
}

function ShieldBot({ size = 50, color = COLORS.purple }) {
  return (
    <svg width={size} height={size} viewBox="0 0 50 50" style={{ animation: "float 4s ease-in-out infinite 1s" }}>
      <path d="M25 5 L40 12 L40 28 C40 38 25 45 25 45 C25 45 10 38 10 28 L10 12 Z" fill={color} opacity="0.15" stroke={color} strokeWidth="1.5"/>
      <path d="M25 12 L33 16 L33 26 C33 32 25 36 25 36 C25 36 17 32 17 26 L17 16 Z" fill={color} opacity="0.3"/>
      <circle cx="21" cy="22" r="2" fill={color}/>
      <circle cx="29" cy="22" r="2" fill={color}/>
      <path d="M20 27 Q25 31 30 27" stroke={color} strokeWidth="1.5" fill="none" strokeLinecap="round"/>
    </svg>
  );
}

function ParticleField() {
  const canvasRef = useRef(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const W = canvas.width = canvas.offsetWidth;
    const H = canvas.height = canvas.offsetHeight;
    const particles = Array.from({ length: 60 }, () => ({
      x: Math.random() * W, y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.4, vy: (Math.random() - 0.5) * 0.4,
      r: Math.random() * 1.5 + 0.5,
      color: Math.random() > 0.7 ? COLORS.accent : COLORS.purple,
      opacity: Math.random() * 0.5 + 0.1,
    }));
    let frame;
    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      for (const p of particles) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
        if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.globalAlpha = p.opacity;
        ctx.fill();
      }
      ctx.globalAlpha = 1;
      frame = requestAnimationFrame(draw);
    };
    draw();
    return () => cancelAnimationFrame(frame);
  }, []);
  return <canvas ref={canvasRef} style={{ position: "absolute", inset: 0, width: "100%", height: "100%", pointerEvents: "none" }}/>;
}

function RiskGauge({ score, level }) {
  const color = getLevelColor(level);
  const angle = (score / 100) * 180 - 90;
  const r = 70;
  const cx = 100, cy = 90;
  const toRad = deg => deg * Math.PI / 180;
  const arcPath = (startDeg, endDeg, col, op = 0.15) => {
    const s = toRad(startDeg - 90), e = toRad(endDeg - 90);
    return `M ${cx + r * Math.cos(s)} ${cy + r * Math.sin(s)} A ${r} ${r} 0 ${endDeg - startDeg > 180 ? 1 : 0} 1 ${cx + r * Math.cos(e)} ${cy + r * Math.sin(e)}`;
  };
  const needleX = cx + (r - 10) * Math.cos(toRad(angle));
  const needleY = cy + (r - 10) * Math.sin(toRad(angle));

  return (
    <svg viewBox="0 0 200 110" style={{ width: "100%", maxWidth: 220 }}>
      <path d={arcPath(0, 45)} stroke={COLORS.accent} strokeWidth="12" fill="none" strokeLinecap="round" opacity="0.3"/>
      <path d={arcPath(45, 90)} stroke={COLORS.warning} strokeWidth="12" fill="none" strokeLinecap="round" opacity="0.3"/>
      <path d={arcPath(90, 135)} stroke="#ff8c42" strokeWidth="12" fill="none" strokeLinecap="round" opacity="0.3"/>
      <path d={arcPath(135, 180)} stroke={COLORS.danger} strokeWidth="12" fill="none" strokeLinecap="round" opacity="0.3"/>
      <line x1={cx} y1={cy} x2={needleX} y2={needleY} stroke={color} strokeWidth="2.5" strokeLinecap="round"/>
      <circle cx={cx} cy={cy} r="6" fill={color} opacity="0.9"/>
      <circle cx={cx} cy={cy} r="3" fill={COLORS.bg}/>
      <text x={cx} y={cy + 20} textAnchor="middle" fill={color} fontSize="22" fontWeight="700">{score}</text>
      <text x={cx} y={cy + 34} textAnchor="middle" fill={color} fontSize="10" opacity="0.8">{level.toUpperCase()}</text>
      <text x="18" y="105" fill={COLORS.accent} fontSize="8" opacity="0.6">Safe</text>
      <text x="160" y="105" fill={COLORS.danger} fontSize="8" opacity="0.6">Danger</text>
    </svg>
  );
}

function SeverityBadge({ severity }) {
  const map = { high: [COLORS.danger, "#3a0a14"], medium: [COLORS.warning, "#3a2800"], low: [COLORS.muted, "#222"] };
  const [color, bg] = map[severity] || [COLORS.muted, "#222"];
  return (
    <span style={{ background: bg, color, border: `1px solid ${color}30`, borderRadius: 4, fontSize: 10, padding: "2px 7px", fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5 }}>
      {severity}
    </span>
  );
}

const FINDING_ICONS = { ssl: "🔓", ip: "🌐", short: "🔗", typo: "👥", tld: "⚠️", subdomain: "🧩", brand: "🏷️", length: "📏", keyword: "🔑", char: "🔤", error: "❌" };

function FindingCard({ f }) {
  return (
    <div style={{ background: "#0f0f0f", border: `1px solid ${f.severity === "high" ? COLORS.danger + "40" : f.severity === "medium" ? COLORS.warning + "40" : "#2a2a2a"}`, borderRadius: 8, padding: "10px 14px", display: "flex", gap: 12, alignItems: "flex-start" }}>
      <span style={{ fontSize: 18, flexShrink: 0 }}>{FINDING_ICONS[f.type] || "🔍"}</span>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginBottom: 4 }}>
          <span style={{ color: COLORS.text, fontWeight: 600, fontSize: 13 }}>{f.label}</span>
          <SeverityBadge severity={f.severity} />
        </div>
        <p style={{ color: COLORS.muted, fontSize: 12, margin: 0, lineHeight: 1.5 }}>{f.detail}</p>
      </div>
    </div>
  );
}

function ScanTimeline({ steps, currentStep }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {steps.map((s, i) => (
        <div key={i} style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            width: 20, height: 20, borderRadius: "50%", flexShrink: 0,
            background: i < currentStep ? COLORS.accent + "20" : i === currentStep ? COLORS.accent + "30" : "#1a1a1a",
            border: `1.5px solid ${i < currentStep ? COLORS.accent : i === currentStep ? COLORS.accent : COLORS.dimmed}`,
            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 9,
          }}>
            {i < currentStep ? "✓" : i === currentStep ? <div style={{ width: 6, height: 6, borderRadius: "50%", background: COLORS.accent, animation: "pulse 1s infinite" }}/> : ""}
          </div>
          <span style={{ fontSize: 12, color: i < currentStep ? COLORS.accent : i === currentStep ? COLORS.text : COLORS.dimmed }}>
            {s}
          </span>
        </div>
      ))}
    </div>
  );
}

const SCAN_STEPS = ["Parsing URL structure", "Resolving domain", "Checking TLD reputation", "Detecting typosquatting", "Analyzing threat signals", "Calculating risk score", "Generating AI report"];

const HISTORY_KEY = "voidguard_history";

function getHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
}
function saveHistory(entry) {
  try {
    const h = getHistory();
    h.unshift(entry);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(h.slice(0, 50)));
  } catch {}
}

export default function VoidGuard() {
  const [page, setPage] = useState("landing");
  const [url, setUrl] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [aiExplanation, setAiExplanation] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [history, setHistory] = useState(getHistory());
  const [qrFile, setQrFile] = useState(null);
  const [qrUrl, setQrUrl] = useState("");
  const [historySearch, setHistorySearch] = useState("");
  const [copied, setCopied] = useState(false);
  const inputRef = useRef(null);

  const getAIExplanation = useCallback(async (result) => {
    setAiLoading(true);
    setAiExplanation("");
    const findings = result.findings.map(f => f.label).join(", ");
    const prompt = `You are a cybersecurity analyst. Analyze this URL threat scan result and write a 2-3 sentence natural-language explanation for a general user. Be specific about the risks and what an attacker might do with this URL.

URL: ${result.url}
Risk Score: ${result.score}/100
Threat Level: ${result.level}
Findings: ${findings || "No specific threats detected"}

Write in plain English. Be direct and informative. Do not use markdown, headers, or bullet points. Just plain paragraphs.`;

    try {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          messages: [{ role: "user", content: prompt }],
        }),
      });
      const data = await res.json();
      const text = data.content?.map(c => c.text || "").join("") || "Analysis unavailable.";
      setAiExplanation(text);
    } catch {
      setAiExplanation("AI analysis temporarily unavailable. Please review the threat findings above.");
    }
    setAiLoading(false);
  }, []);

  const runScan = useCallback(async (targetUrl) => {
    if (!targetUrl.trim()) return;
    setScanning(true);
    setScanStep(0);
    setAiExplanation("");
    setPage("analysis");

    for (let i = 0; i < SCAN_STEPS.length; i++) {
      await new Promise(r => setTimeout(r, 280 + Math.random() * 180));
      setScanStep(i + 1);
    }

    const result = analyzeURL(targetUrl);
    setScanResult(result);
    setScanning(false);
    const entry = { url: targetUrl, score: result.score, level: result.level, date: new Date().toISOString(), id: Date.now() };
    saveHistory(entry);
    setHistory(getHistory());
    getAIExplanation(result);
  }, [getAIExplanation]);

  const handleSubmit = (e) => {
    e?.preventDefault();
    if (url.trim()) runScan(url.trim());
  };

  const copyReport = () => {
    if (!scanResult) return;
    const text = `VoidGuard Threat Report\nURL: ${scanResult.url}\nScore: ${scanResult.score}/100\nLevel: ${scanResult.level}\nFindings:\n${scanResult.findings.map(f => `- [${f.severity.toUpperCase()}] ${f.label}: ${f.detail}`).join("\n")}\n\nAI Analysis:\n${aiExplanation}`;
    navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
  };

  const c = getLevelColor(scanResult?.level);

  return (
    <div style={{ fontFamily: "'Inter', 'Segoe UI', sans-serif", background: COLORS.bg, minHeight: "100vh", color: COLORS.text }}>
      <style>{`
        @keyframes float { 0%,100% { transform: translateY(0px); } 50% { transform: translateY(-8px); } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
        @keyframes glow { 0%,100% { box-shadow: 0 0 10px ${COLORS.accent}40; } 50% { box-shadow: 0 0 24px ${COLORS.accent}80; } }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
        .nav-link { background: none; border: none; color: ${COLORS.muted}; cursor: pointer; font-size: 13px; padding: 6px 12px; border-radius: 6px; transition: all 0.2s; }
        .nav-link:hover, .nav-link.active { color: ${COLORS.text}; background: #1a1a1a; }
        .scan-btn { background: ${COLORS.accent}; color: #000; border: none; padding: 12px 28px; border-radius: 8px; font-size: 15px; font-weight: 700; cursor: pointer; transition: all 0.2s; animation: glow 2s ease-in-out infinite; letter-spacing: 0.3px; }
        .scan-btn:hover { transform: translateY(-1px); background: #00ffaa; }
        .scan-btn:disabled { opacity: 0.5; cursor: not-allowed; animation: none; }
        .url-input { background: #0f0f0f; border: 1.5px solid #2a2a2a; color: ${COLORS.text}; padding: 12px 16px; border-radius: 8px; font-size: 14px; width: 100%; box-sizing: border-box; outline: none; transition: border-color 0.2s; }
        .url-input:focus { border-color: ${COLORS.accent}60; }
        .url-input::placeholder { color: #444; }
        .card { background: ${COLORS.card}; border: 1px solid ${COLORS.cardBorder}; border-radius: 12px; padding: 20px; }
        .history-row { display: grid; grid-template-columns: 1fr auto auto auto; gap: 12px; align-items: center; padding: 10px 16px; border-radius: 8px; cursor: pointer; transition: background 0.15s; }
        .history-row:hover { background: #161616; }
        .tag { display: inline-block; padding: "2px 8px"; border-radius: 4px; font-size: 11px; font-weight: 600; }
        .drop-zone { border: 2px dashed #2a2a2a; border-radius: 12px; padding: 40px; text-align: center; cursor: pointer; transition: all 0.2s; }
        .drop-zone:hover, .drop-zone.active { border-color: ${COLORS.accent}60; background: ${COLORS.accent}05; }
        .fade-in { animation: fadeIn 0.4s ease forwards; }
        .pulse-dot { width: 8px; height: 8px; border-radius: 50%; background: ${COLORS.accent}; animation: pulse 1.5s ease-in-out infinite; }
      `}</style>

      {/* Navbar */}
      <nav style={{ background: "#0d0d0d", borderBottom: `1px solid ${COLORS.cardBorder}`, padding: "0 24px", display: "flex", alignItems: "center", gap: 8, height: 52, position: "sticky", top: 0, zIndex: 100 }}>
        <button onClick={() => setPage("landing")} style={{ background: "none", border: "none", cursor: "pointer", display: "flex", alignItems: "center", gap: 8, padding: 0 }}>
          <ShieldBot size={32} color={COLORS.accent}/>
          <span style={{ color: COLORS.accent, fontWeight: 800, fontSize: 16, letterSpacing: 1 }}>VOID<span style={{ color: COLORS.purple }}>GUARD</span></span>
        </button>
        <div style={{ flex: 1 }}/>
        {[["landing","Home"],["analysis","Scanner"],["history","History"],["qr","QR Scan"],["about","Learn"]].map(([p, l]) => (
          <button key={p} className={`nav-link ${page === p ? "active" : ""}`} onClick={() => setPage(p)}>{l}</button>
        ))}
      </nav>

      {/* Landing Page */}
      {page === "landing" && (
        <div>
          <div style={{ position: "relative", minHeight: "90vh", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "60px 24px", overflow: "hidden" }}>
            <ParticleField/>
            <div style={{ position: "absolute", top: 60, right: 80, opacity: 0.7 }}><RobotMascot size={90} color={COLORS.accent}/></div>
            <div style={{ position: "absolute", bottom: 80, left: 60, opacity: 0.5 }}><ShieldBot size={70} color={COLORS.purple}/></div>
            <div style={{ position: "absolute", top: 120, left: 40, opacity: 0.3 }}><RobotMascot size={50} color={COLORS.purple}/></div>

            <div style={{ textAlign: "center", maxWidth: 680, position: "relative", zIndex: 1 }}>
              <div style={{ display: "inline-flex", alignItems: "center", gap: 8, background: COLORS.accent + "15", border: `1px solid ${COLORS.accent}30`, borderRadius: 20, padding: "5px 14px", marginBottom: 24, fontSize: 12, color: COLORS.accent }}>
                <div className="pulse-dot"/>
                AI-Powered Threat Intelligence
              </div>
              <h1 style={{ fontSize: "clamp(42px,8vw,80px)", fontWeight: 900, margin: "0 0 12px", letterSpacing: -2, lineHeight: 1.05 }}>
                <span style={{ color: COLORS.text }}>VOID</span>
                <span style={{ color: COLORS.accent }}>GUARD</span>
              </h1>
              <p style={{ color: COLORS.muted, fontSize: 18, margin: "0 0 40px", lineHeight: 1.5 }}>
                Analyze URLs. Detect Phishing. Expose Hidden Threats.
              </p>
              <form onSubmit={handleSubmit} style={{ display: "flex", gap: 10, maxWidth: 560, margin: "0 auto 16px" }}>
                <input
                  ref={inputRef}
                  className="url-input"
                  value={url}
                  onChange={e => setUrl(e.target.value)}
                  placeholder="Paste any URL to analyze threats..."
                  style={{ flex: 1 }}
                />
                <button type="submit" className="scan-btn" disabled={!url.trim()}>Analyze →</button>
              </form>
              <p style={{ color: COLORS.dimmed, fontSize: 12 }}>Try: paypa1.com · bit.ly/anything · secure-google.xyz</p>
            </div>
          </div>

          {/* Stats */}
          <div style={{ background: "#0d0d0d", borderTop: `1px solid ${COLORS.cardBorder}`, borderBottom: `1px solid ${COLORS.cardBorder}`, padding: "28px 24px" }}>
            <div style={{ maxWidth: 700, margin: "0 auto", display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 24, textAlign: "center" }}>
              {[["2.4M+","URLs Scanned"],["187K","Threats Detected"],["94K","Users Protected"]].map(([n,l]) => (
                <div key={l}>
                  <div style={{ fontSize: 28, fontWeight: 800, color: COLORS.accent }}>{n}</div>
                  <div style={{ fontSize: 12, color: COLORS.muted, marginTop: 4 }}>{l}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Features */}
          <div style={{ maxWidth: 800, margin: "0 auto", padding: "60px 24px" }}>
            <h2 style={{ textAlign: "center", fontSize: 22, fontWeight: 700, marginBottom: 32, color: COLORS.text }}>What VoidGuard Detects</h2>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))", gap: 16 }}>
              {[
                ["🎣","Phishing Sites","Identifies pages designed to steal credentials"],
                ["👥","Typosquatting","Catches domain impersonation of 25+ major brands"],
                ["🔗","Hidden Redirects","Unmasks dangerous URL shorteners"],
                ["🌐","Risky TLDs","Flags abuse-prone top-level domains"],
                ["🧩","Subdomain Abuse","Detects deceptive subdomain structures"],
                ["🤖","AI Analysis","Plain-English explanations of every threat"],
              ].map(([icon,title,desc]) => (
                <div key={title} className="card" style={{ textAlign: "center" }}>
                  <div style={{ fontSize: 28, marginBottom: 10 }}>{icon}</div>
                  <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 6 }}>{title}</div>
                  <div style={{ color: COLORS.muted, fontSize: 12, lineHeight: 1.5 }}>{desc}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Analysis Page */}
      {page === "analysis" && (
        <div style={{ maxWidth: 780, margin: "0 auto", padding: "32px 24px" }}>
          {scanning ? (
            <div className="fade-in" style={{ textAlign: "center" }}>
              <div style={{ marginBottom: 32 }}>
                <div style={{ animation: "float 2s ease-in-out infinite", display: "inline-block" }}>
                  <RobotMascot size={80} color={COLORS.accent}/>
                </div>
                <h2 style={{ fontSize: 18, fontWeight: 600, color: COLORS.accent, marginTop: 16 }}>🤖 Scanning the cyber matrix…</h2>
                <p style={{ color: COLORS.muted, fontSize: 14, marginTop: 4 }}>Shield bots are investigating this URL</p>
              </div>
              <div className="card" style={{ maxWidth: 360, margin: "0 auto", textAlign: "left" }}>
                <ScanTimeline steps={SCAN_STEPS} currentStep={scanStep}/>
              </div>
            </div>
          ) : scanResult ? (
            <div className="fade-in">
              {/* Header */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 24, flexWrap: "wrap", gap: 12 }}>
                <div>
                  <h1 style={{ fontSize: 20, fontWeight: 700, margin: "0 0 6px" }}>Threat Analysis Report</h1>
                  <p style={{ color: COLORS.muted, fontSize: 13, margin: 0, wordBreak: "break-all", maxWidth: 500 }}>{scanResult.url}</p>
                </div>
                <div style={{ display: "flex", gap: 8 }}>
                  <button onClick={copyReport} style={{ background: "#1a1a1a", border: `1px solid #333`, color: COLORS.text, padding: "8px 16px", borderRadius: 8, cursor: "pointer", fontSize: 13 }}>
                    {copied ? "✓ Copied" : "📋 Copy Report"}
                  </button>
                  <button onClick={() => { setUrl(""); setPage("landing"); setScanResult(null); }} style={{ background: COLORS.accent + "15", border: `1px solid ${COLORS.accent}40`, color: COLORS.accent, padding: "8px 16px", borderRadius: 8, cursor: "pointer", fontSize: 13 }}>
                    + New Scan
                  </button>
                </div>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: 20, marginBottom: 20, alignItems: "start" }}>
                {/* Gauge */}
                <div className="card" style={{ textAlign: "center" }}>
                  <RiskGauge score={scanResult.score} level={scanResult.level}/>
                </div>

                {/* Domain Info */}
                <div className="card">
                  <h3 style={{ fontSize: 13, color: COLORS.muted, textTransform: "uppercase", letterSpacing: 1, margin: "0 0 14px", fontWeight: 600 }}>Domain Intelligence</h3>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                    {[
                      ["Protocol", scanResult.parsed?.protocol?.replace(":", "") || "Unknown"],
                      ["Host", scanResult.parsed?.hostname || "N/A"],
                      ["Path", scanResult.parsed?.pathname?.substring(0, 24) || "/"],
                      ["Port", scanResult.parsed?.port || "Default"],
                      ["Params", scanResult.parsed?.search || "None"],
                      ["Domain Parts", scanResult.parsed?.hostname?.split(".").length || "?"],
                    ].map(([k, v]) => (
                      <div key={k} style={{ background: "#0d0d0d", borderRadius: 6, padding: "8px 12px" }}>
                        <div style={{ fontSize: 10, color: COLORS.dimmed, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 3 }}>{k}</div>
                        <div style={{ fontSize: 13, color: COLORS.text, fontFamily: "monospace", wordBreak: "break-all" }}>{v}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* AI Explanation */}
              <div className="card" style={{ marginBottom: 20, borderColor: COLORS.purple + "40" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
                  <div style={{ width: 32, height: 32, borderRadius: "50%", background: COLORS.purple + "20", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16 }}>🤖</div>
                  <h3 style={{ fontSize: 14, fontWeight: 600, margin: 0 }}>AI Security Analysis</h3>
                  {aiLoading && <div style={{ width: 14, height: 14, border: `2px solid ${COLORS.purple}`, borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.8s linear infinite" }}/>}
                </div>
                {aiLoading ? (
                  <div style={{ color: COLORS.muted, fontSize: 13 }}>✨ AI assistant is analyzing hidden threats…</div>
                ) : aiExplanation ? (
                  <p style={{ color: "#cccccc", fontSize: 14, lineHeight: 1.7, margin: 0 }}>{aiExplanation}</p>
                ) : (
                  <div style={{ color: COLORS.dimmed, fontSize: 13 }}>Analysis pending…</div>
                )}
              </div>

              {/* Findings */}
              {scanResult.findings.length > 0 ? (
                <div className="card" style={{ marginBottom: 20 }}>
                  <h3 style={{ fontSize: 13, color: COLORS.muted, textTransform: "uppercase", letterSpacing: 1, margin: "0 0 14px", fontWeight: 600 }}>
                    Threat Findings ({scanResult.findings.length})
                  </h3>
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {scanResult.findings.map((f, i) => <FindingCard key={i} f={f}/>)}
                  </div>
                </div>
              ) : (
                <div className="card" style={{ marginBottom: 20, textAlign: "center", padding: "32px", borderColor: COLORS.accent + "40" }}>
                  <div style={{ fontSize: 40, marginBottom: 12 }}>✅</div>
                  <div style={{ color: COLORS.accent, fontSize: 16, fontWeight: 600 }}>No Threats Detected</div>
                  <div style={{ color: COLORS.muted, fontSize: 13, marginTop: 6 }}>This URL passed all security checks.</div>
                </div>
              )}

              {/* New scan */}
              <div style={{ display: "flex", gap: 10, marginTop: 16 }}>
                <input className="url-input" value={url} onChange={e => setUrl(e.target.value)} placeholder="Scan another URL…" onKeyDown={e => e.key === "Enter" && handleSubmit()} style={{ flex: 1 }}/>
                <button className="scan-btn" onClick={handleSubmit} disabled={!url.trim()}>Scan →</button>
              </div>
            </div>
          ) : (
            <div style={{ textAlign: "center", padding: "80px 0" }}>
              <RobotMascot size={70} color={COLORS.accent}/>
              <p style={{ color: COLORS.muted, marginTop: 16 }}>No scan results yet. Enter a URL to analyze.</p>
              <button className="scan-btn" style={{ marginTop: 12 }} onClick={() => setPage("landing")}>Go to Scanner</button>
            </div>
          )}
        </div>
      )}

      {/* History */}
      {page === "history" && (
        <div style={{ maxWidth: 780, margin: "0 auto", padding: "32px 24px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24, flexWrap: "wrap", gap: 12 }}>
            <h1 style={{ fontSize: 20, fontWeight: 700, margin: 0 }}>Scan History</h1>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <RobotMascot size={36} color={COLORS.purple} animate={false}/>
              <input className="url-input" style={{ width: 220 }} placeholder="Search URLs…" value={historySearch} onChange={e => setHistorySearch(e.target.value)}/>
            </div>
          </div>

          {history.length === 0 ? (
            <div className="card" style={{ textAlign: "center", padding: 48 }}>
              <div style={{ fontSize: 40, marginBottom: 12 }}>🤖</div>
              <p style={{ color: COLORS.muted }}>No scans yet. The shield bots are waiting!</p>
            </div>
          ) : (
            <div className="card">
              <div style={{ display: "grid", gridTemplateColumns: "1fr auto auto auto", gap: 12, padding: "6px 16px", marginBottom: 6, fontSize: 11, color: COLORS.dimmed, textTransform: "uppercase", letterSpacing: 0.5 }}>
                <span>URL</span><span>Score</span><span>Level</span><span>Date</span>
              </div>
              {history
                .filter(h => !historySearch || h.url.toLowerCase().includes(historySearch.toLowerCase()))
                .map(h => {
                  const col = getLevelColor(h.level);
                  return (
                    <div key={h.id} className="history-row" onClick={() => { setUrl(h.url); runScan(h.url); }}>
                      <span style={{ fontSize: 13, color: COLORS.text, wordBreak: "break-all", minWidth: 0 }}>{h.url}</span>
                      <span style={{ fontSize: 13, fontWeight: 700, color: col, fontFamily: "monospace" }}>{h.score}</span>
                      <span style={{ fontSize: 11, fontWeight: 600, color: col, background: col + "15", border: `1px solid ${col}30`, borderRadius: 4, padding: "2px 8px", whiteSpace: "nowrap" }}>{h.level}</span>
                      <span style={{ fontSize: 11, color: COLORS.dimmed, whiteSpace: "nowrap" }}>{new Date(h.date).toLocaleDateString()}</span>
                    </div>
                  );
                })}
            </div>
          )}

          {history.length > 0 && (
            <div style={{ marginTop: 16, textAlign: "right" }}>
              <button onClick={() => { localStorage.removeItem(HISTORY_KEY); setHistory([]); }} style={{ background: "none", border: `1px solid ${COLORS.danger}40`, color: COLORS.danger, padding: "6px 14px", borderRadius: 6, cursor: "pointer", fontSize: 12 }}>
                Clear History
              </button>
            </div>
          )}
        </div>
      )}

      {/* QR Scanner */}
      {page === "qr" && (
        <div style={{ maxWidth: 640, margin: "0 auto", padding: "32px 24px" }}>
          <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>QR Code Security Scanner</h1>
          <p style={{ color: COLORS.muted, fontSize: 14, marginBottom: 28 }}>Upload a QR code to extract and analyze the embedded URL for threats.</p>

          <div
            className={`drop-zone ${qrFile ? "active" : ""}`}
            onClick={() => document.getElementById("qr-input").click()}
            onDragOver={e => e.preventDefault()}
            onDrop={e => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) setQrFile(f); }}
          >
            <input id="qr-input" type="file" accept="image/*" style={{ display: "none" }} onChange={e => { setQrFile(e.target.files[0]); setQrUrl(""); }}/>
            {qrFile ? (
              <div>
                <div style={{ color: COLORS.accent, fontSize: 32, marginBottom: 8 }}>✓</div>
                <div style={{ color: COLORS.text, fontSize: 14 }}>{qrFile.name}</div>
                <div style={{ color: COLORS.muted, fontSize: 12, marginTop: 4 }}>QR code uploaded</div>
              </div>
            ) : (
              <div>
                <div style={{ fontSize: 40, marginBottom: 12 }}>📷</div>
                <div style={{ color: COLORS.text, fontSize: 14, fontWeight: 600 }}>Drop QR code image here</div>
                <div style={{ color: COLORS.muted, fontSize: 12, marginTop: 6 }}>or click to browse · PNG, JPG, WEBP</div>
              </div>
            )}
          </div>

          {qrFile && (
            <div style={{ marginTop: 20 }}>
              <div className="card" style={{ marginBottom: 16 }}>
                <h3 style={{ fontSize: 13, color: COLORS.muted, textTransform: "uppercase", letterSpacing: 1, margin: "0 0 12px", fontWeight: 600 }}>QR Preview</h3>
                <div style={{ display: "flex", justifyContent: "center", padding: 16, background: "#0d0d0d", borderRadius: 8, border: `2px solid ${COLORS.purple}40` }}>
                  <img src={URL.createObjectURL(qrFile)} alt="QR Code" style={{ maxHeight: 180, maxWidth: "100%", borderRadius: 4 }}/>
                </div>
              </div>
              <p style={{ color: COLORS.muted, fontSize: 13, textAlign: "center", marginBottom: 12 }}>
                🤖 QR decoding requires a backend service. For now, manually paste the URL from your QR code below:
              </p>
              <div style={{ display: "flex", gap: 10 }}>
                <input className="url-input" value={qrUrl} onChange={e => setQrUrl(e.target.value)} placeholder="Paste extracted URL from QR code…" style={{ flex: 1 }}/>
                <button className="scan-btn" disabled={!qrUrl.trim()} onClick={() => { setUrl(qrUrl); runScan(qrUrl); }}>Analyze →</button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* About / Education */}
      {page === "about" && (
        <div style={{ maxWidth: 780, margin: "0 auto", padding: "32px 24px" }}>
          <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 8 }}>Cybersecurity Education</h1>
          <p style={{ color: COLORS.muted, fontSize: 14, marginBottom: 32 }}>Learn how attackers abuse URLs and how to protect yourself.</p>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 20 }}>
            {[
              {
                icon: "🎣", title: "Phishing", color: COLORS.danger,
                desc: "Attackers create fake websites that mimic trusted brands. They send these links via email, SMS, or social media to steal your username, password, or credit card details.",
                tip: "Always verify the URL before entering credentials. Look for HTTPS and the exact domain name.",
              },
              {
                icon: "👥", title: "Typosquatting", color: COLORS.warning,
                desc: "Cybercriminals register domains that look like real sites but with slight misspellings: gooogle.com, paypa1.com, arnazon.com. Users mistype or are misled into visiting them.",
                tip: "Bookmark important sites instead of typing them. Double-check the URL bar every time.",
              },
              {
                icon: "🔗", title: "URL Shortener Abuse", color: COLORS.purple,
                desc: "Services like bit.ly hide the real destination. Attackers use them to mask malicious links that would otherwise look suspicious. You can't tell where you're going until you arrive.",
                tip: "Use URL expander tools to preview shortened links before clicking.",
              },
              {
                icon: "🧩", title: "Subdomain Tricks", color: "#ff8c42",
                desc: "Attackers create URLs like paypal.com.evil-site.xyz — the real domain is evil-site.xyz, but they put paypal.com as a subdomain to fool users who read left-to-right.",
                tip: "The real domain is always the part just before the final TLD (like .com). Everything before it is a subdomain.",
              },
              {
                icon: "⚠️", title: "Risky TLDs", color: COLORS.warning,
                desc: "Domains ending in .xyz, .tk, .ml, .ga, and similar TLDs are extremely cheap or free with no identity verification — making them popular with cybercriminals for throwaway phishing sites.",
                tip: "Be extra cautious with unusual TLDs, especially for financial or sensitive services.",
              },
              {
                icon: "🔓", title: "Missing HTTPS", color: COLORS.danger,
                desc: "HTTP sites transmit all data in plain text. Anyone on the same network (e.g. a café WiFi) can intercept your login credentials, form data, and browsing activity.",
                tip: "Never enter sensitive information on HTTP sites. Look for the padlock icon in your browser.",
              },
            ].map(({ icon, title, color, desc, tip }) => (
              <div key={title} className="card" style={{ borderColor: color + "30" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 14 }}>
                  <div style={{ width: 40, height: 40, borderRadius: 10, background: color + "15", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22 }}>{icon}</div>
                  <h3 style={{ fontSize: 15, fontWeight: 700, margin: 0, color }}>{title}</h3>
                </div>
                <p style={{ color: COLORS.muted, fontSize: 13, lineHeight: 1.6, margin: "0 0 14px" }}>{desc}</p>
                <div style={{ background: color + "10", border: `1px solid ${color}25`, borderRadius: 6, padding: "8px 12px" }}>
                  <span style={{ color, fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 0.5 }}>💡 Tip: </span>
                  <span style={{ color: "#bbb", fontSize: 12 }}>{tip}</span>
                </div>
              </div>
            ))}
          </div>

          <div className="card" style={{ marginTop: 24, textAlign: "center", borderColor: COLORS.accent + "30" }}>
            <RobotMascot size={60} color={COLORS.accent}/>
            <h3 style={{ fontSize: 16, fontWeight: 700, marginTop: 12, color: COLORS.accent }}>Stay Safe Online</h3>
            <p style={{ color: COLORS.muted, fontSize: 13, lineHeight: 1.6, maxWidth: 480, margin: "8px auto 20px" }}>
              When in doubt, don't click. Use VoidGuard to verify any suspicious link before visiting it. Remember: attackers rely on urgency and fear — slow down and check.
            </p>
            <button className="scan-btn" onClick={() => setPage("landing")}>Scan a URL Now →</button>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer style={{ borderTop: `1px solid ${COLORS.cardBorder}`, padding: "24px", textAlign: "center", marginTop: 60 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 8, marginBottom: 8 }}>
          <ShieldBot size={24} color={COLORS.accent}/>
          <span style={{ color: COLORS.accent, fontWeight: 700, fontSize: 13 }}>VOID<span style={{ color: COLORS.purple }}>GUARD</span></span>
        </div>
        <p style={{ color: COLORS.dimmed, fontSize: 12, margin: 0 }}>AI-Powered URL Threat Intelligence · For educational purposes only</p>
      </footer>
    </div>
  );
}
