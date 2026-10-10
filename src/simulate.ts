// Generates SYNTHETIC log lines (benign traffic + labelled attack scenarios) so the detection
// engine can be demonstrated and regression-tested. It only writes text; nothing is sent anywhere.
// All IPs are RFC 5737 documentation addresses.

const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const p2 = (n: number) => String(n).padStart(2, "0");

function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const sshStamp = (ts: number) => {
  const d = new Date(ts);
  return `${MON[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, " ")} ${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}`;
};
const webStamp = (ts: number) => {
  const d = new Date(ts);
  return `${p2(d.getUTCDate())}/${MON[d.getUTCMonth()]}/${d.getUTCFullYear()}:${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())} +0000`;
};

export interface SimResult { ssh: string[]; nginx: string[] }
export const SIM_YEAR = 2026;
export const SIM_BASE = Date.UTC(SIM_YEAR, 9, 10, 0, 0, 0);

export function simulate(seed = 1337): SimResult {
  const rand = rng(seed);
  const pick = <T,>(a: T[]): T => a[Math.floor(rand() * a.length)];
  const ssh: { ts: number; line: string }[] = [];
  const web: { ts: number; line: string }[] = [];
  const at = (h: number, m = 0, s = 0) => SIM_BASE + ((h * 60 + m) * 60 + s) * 1000;

  const sshFail = (ts: number, ip: string, user: string, invalid = false) =>
    ssh.push({ ts, line: `${sshStamp(ts)} web01 sshd[${1000 + Math.floor(rand() * 8000)}]: Failed password for ${invalid ? "invalid user " : ""}${user} from ${ip} port ${20000 + Math.floor(rand() * 40000)} ssh2` });
  const sshOk = (ts: number, ip: string, user: string, method = "password") =>
    ssh.push({ ts, line: `${sshStamp(ts)} web01 sshd[${1000 + Math.floor(rand() * 8000)}]: Accepted ${method} for ${user} from ${ip} port ${20000 + Math.floor(rand() * 40000)} ssh2` });
  const hit = (ts: number, ip: string, method: string, path: string, status: number, ua: string) =>
    web.push({ ts, line: `${ip} - - [${webStamp(ts)}] "${method} ${path} HTTP/1.1" ${status} ${200 + Math.floor(rand() * 5000)} "-" "${ua}"` });

  // ---- Benign background traffic ----
  const uas = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
  ];
  const pages = ["/", "/index.html", "/about", "/products", "/products?id=12", "/api/items", "/static/app.js", "/static/site.css", "/contact", "/search?q=shoes"];
  const clients = Array.from({ length: 30 }, (_, i) => `192.0.2.${10 + i}`);
  for (let i = 0; i < 900; i++) {
    const ts = SIM_BASE + Math.floor(rand() * 86_400_000);
    const r = rand();
    if (rand() < 0.03) hit(ts, pick(clients), "POST", "/login", r < 0.5 ? 401 : 200, pick(uas));
    else hit(ts, pick(clients), "GET", pick(pages), r < 0.9 ? 200 : r < 0.97 ? 304 : 404, pick(uas));
  }
  for (let i = 0; i < 36; i++) sshOk(SIM_BASE + Math.floor(rand() * 86_400_000), pick(["198.51.100.5", "198.51.100.6"]), pick(["alice", "bob"]), "publickey");
  for (let i = 0; i < 4; i++) { // human typos: one failure then success
    const ts = SIM_BASE + Math.floor(rand() * 80_000_000);
    sshFail(ts, "198.51.100.5", "alice");
    sshOk(ts + 12_000, "198.51.100.5", "alice");
  }

  // ---- Labelled attack scenarios ----
  // A. SSH brute force from known-bad IP
  const users = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "pi"];
  for (let i = 0; i < 80; i++) sshFail(at(2, 15) + i * 1500, "203.0.113.66", pick(users), true);
  // B. Password spraying: 12 different accounts, one attempt each, slow
  ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory", "deploy"]
    .forEach((u, i) => sshFail(at(3, 40) + i * 8000, "203.0.113.77", u));
  // C. Guessed account then root login (compromise)
  for (let i = 0; i < 7; i++) sshFail(at(4, 5) + i * 3000, "203.0.113.99", "deploy");
  sshOk(at(4, 5, 30), "203.0.113.99", "deploy");
  sshOk(at(4, 16), "203.0.113.99", "root");
  // D. Recon scan with Nikto
  const words = [".env", ".git/config", "admin", "phpmyadmin", "backup.zip", "wp-config.php.bak", "login.php", "server-status", ".aws/credentials", "id_rsa", "config", "old", "test", "uploads", "api/v1", "dashboard", "console", "setup", "install", "debug"];
  for (let i = 0; i < 120; i++) hit(at(9, 30) + i * 500, "198.51.100.200", "GET", `/${words[i % 20]}${i < 20 ? "" : "." + ["bak", "old", "php"][i % 3]}`, 404, "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:Port Check)");
  // E. SQL injection via sqlmap from the same known-bad IP
  const sqli = [
    "/products?id=1%27%20OR%20%271%27%3D%271",
    "/search?q=1%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/products?id=1;SELECT%20SLEEP(5)--",
    "/products?id=1%20AND%201=1%20UNION%20ALL%20SELECT%20NULL,table_name%20FROM%20information_schema.tables",
    "/products?id=1%27%3B%20DROP%20TABLE%20users%3B--",
  ];
  for (let i = 0; i < 10; i++) hit(at(9, 41) + i * 2000, "203.0.113.66", "GET", sqli[i % sqli.length], 200, "sqlmap/1.7.2#stable (https://sqlmap.org)");
  // F. Reflected XSS probes
  const xss = ["/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/comment?c=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "/search?q=javascript:alert(document.cookie)"];
  for (let i = 0; i < 5; i++) hit(at(11, 10) + i * 4000, "198.51.100.150", "GET", xss[i % 3], 200, pick(uas));
  // G. Path traversal incl. double-encoding
  const trav = ["/download?file=../../../../etc/passwd", "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "/download?file=%252e%252e%252f%252e%252e%252fetc%252fshadow"];
  for (let i = 0; i < 6; i++) hit(at(13, 25) + i * 3000, "203.0.113.120", "GET", trav[i % 3], 400, pick(uas));
  // H. Credential stuffing on /login
  for (let i = 0; i < 40; i++) hit(at(15) + i * 1000, "198.51.100.77", "POST", "/login", 401, "python-requests/2.32.3");

  const sort = (a: { ts: number }[]) => a.sort((x, y) => x.ts - y.ts);
  return { ssh: sort(ssh).map((x) => (x as any).line), nginx: sort(web).map((x) => (x as any).line) };
}
