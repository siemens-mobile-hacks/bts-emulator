// GPRS gateway for emulators in a browser: a WebSocket per phone, each
// binary message one Ethernet frame of the phone's GPRS (what qemu's
// built-in cell hands to its netdev), and behind every connection its own
// slirp (slirp-pipe), so the phone gets QEMU's -netdev user network.
//
// It runs in the net namespace, where nat.nft sends the helpers' DNS, WAP,
// operator proxy and MMSC traffic to dnsmasq, Kannel, squid and the MMSC,
// and drops what is not for the Internet. The gateway filters the phone's
// frames itself too (refusal()), so a missing nat.nft opens nothing.
//
// A browser emulator cannot send faster than its GPRS (one CS-1 timeslot,
// about 1 KB/s; the limits leave room for EDGE), so a client well above that
// is not one: its address is banned.
// Settings are the GPRS_GW_* variables of .env.default.
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import { createRequire } from "node:module";
import net from "node:net";
import path from "node:path";

const { WebSocketServer } = createRequire(import.meta.url)("ws");

const env = (name, fallback) => process.env[`GPRS_GW_${name}`] || fallback;
const LISTEN = env("LISTEN", "0.0.0.0:5751");
const HELPER = env("HELPER", "/usr/local/bin/slirp-pipe");
const HELPER_UID = Number(env("HELPER_UID", 64010));
const ORIGINS = env("ORIGINS", "").split(",").map((s) => s.trim()).filter(Boolean);
const TRUSTED_PROXIES = Number(env("TRUSTED_PROXIES", 0));
const PER_IP = Number(env("PER_IP", 2));
const DAILY_BYTES = Number(env("DAILY_BYTES", 50e6));
const DOWN_RATE = Number(env("DOWN_RATE", 10240));
const DOWN_BURST = Number(env("DOWN_BURST", 81920));
const BAN_RATE = Number(env("BAN_RATE", 20480));
const BAN_FRAMES = Number(env("BAN_FRAMES", 300));
const BAN_DAYS = Number(env("BAN_DAYS", 182));
const IDLE_S = Number(env("IDLE", 900));
const STATE = env("STATE", "/var/lib/gprs-gw/state.json");
const MAX_SESSIONS = Number(env("MAX_SESSIONS", 100));
const ATTEMPTS = Number(env("ATTEMPTS", 20));
const TCP_PORTS = env("TCP_PORTS", "80,443,8080,1080,110,143,993,995,5190,5222,5223");
const NEW_FLOWS = Number(env("NEW_FLOWS", 120));
const HOSTS = Number(env("HOSTS", 200));
const OPERATORS = env("OPERATORS", "/run/operators");
const WINDOW_S = 10;
const FRAME_MAX = 1514;

const ipv4 = (s) => s.split(".").reduce((a, b) => a * 256 + Number(b), 0);
const cidr = (s) => {
  const [a, bits] = s.split("/");
  const mask = bits === "0" ? 0 : (~0 << (32 - bits)) >>> 0;
  return [(ipv4(a) & mask) >>> 0, mask];
};
const within = (ip, [net, mask]) => ((ip & mask) >>> 0) === net;
const VNET = cidr("10.0.2.0/24");
const PRIVATE = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
  "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
  "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"].map(cidr);
// mail submission is never let out, whatever TCP_PORTS says
const SMTP = new Set([25, 465, 587, 2525]);
const UDP_PORTS = new Set([53, 9200, 9201, 9202, 9203]);
const tcpPorts = TCP_PORTS.trim() === "*" ? null : new Set(TCP_PORTS.split(",").map(Number));
// nat.nft sends these to squid and the MMSC: the operator's addresses from
// operators.csv, and those dnsmasq gives operator host names
const operatorIps = new Set(["192.0.2.1", "192.0.2.2"].map(ipv4));
for (const name of ["operator-proxy-ips.txt", "operator-mmsc-ips.txt"]) {
  try {
    for (const line of fs.readFileSync(path.join(OPERATORS, name), "utf8").split("\n"))
      if (net.isIPv4(line.trim())) operatorIps.add(ipv4(line.trim()));
  } catch {}
}

const CLOSE = {
  connections: [4001, "too many connections from this address"],
  full: [4002, "the gateway is full"],
  attempts: [4029, "too many connection attempts from this address"],
  banned: [4003, "banned"],
  quota: [4004, "daily traffic used up"],
  idle: [4008, "idle"],
  origin: [4009, "origin not allowed"],
  helper: [1011, "network helper exited"],
};

const log = (s) => console.log(`${new Date().toISOString()} ${s}`);

// bans: address -> until (ms); usage: address -> bytes, for `day`
let state = { bans: {}, day: "", usage: {} };
try { state = { ...state, ...JSON.parse(fs.readFileSync(STATE, "utf8")) }; } catch {}
let dirty = false;
const save = () => {
  if (!dirty) return;
  dirty = false;
  fs.mkdirSync(path.dirname(STATE), { recursive: true });
  fs.writeFileSync(STATE + ".tmp", JSON.stringify(state));
  fs.renameSync(STATE + ".tmp", STATE);
};
setInterval(save, 30000).unref();
const today = () => new Date().toISOString().slice(0, 10);
const usage = (addr) => {
  if (state.day !== today()) {
    state.day = today();
    state.usage = {};
  }
  return state.usage[addr] ?? 0;
};
const banned = (addr) => (state.bans[addr] ?? 0) > Date.now();

// the client's address: the socket peer, or as many hops back in
// X-Forwarded-For as there are trusted proxies in front; IPv6 per /64
function clientAddress(req) {
  const peer = req.socket.remoteAddress.replace(/^::ffff:/, "");
  const chain = [...(req.headers["x-forwarded-for"] ?? "").split(",").map((s) => s.trim()).filter(Boolean), peer];
  const ip = (chain[chain.length - 1 - TRUSTED_PROXIES] ?? chain[0]).replace(/^::ffff:/, "");
  if (net.isIPv6(ip)) {
    const full = ip.includes("::")
      ? ip.replace("::", ":" + "0:".repeat(9 - ip.split(":").length)).replace(/^:|:$/g, "")
      : ip;
    return full.split(":").slice(0, 4).join(":") + "::/64";
  }
  return ip;
}

// Why a frame from the phone may not go to slirp, or null. The phone gets
// ARP and IPv4 without fragments; slirp's own addresses; DNS and WAP over
// UDP; ICMP echo; TCP to TCP_PORTS but never mail submission. Operator
// proxies and MMSCs take any TCP port, nothing else private is reachable.
// A frame that may open a flow returns { flow, host } for the per-session
// limits.
function refusal(frame) {
  if (frame.length < 14) return { why: "runt frame" };
  const type = frame.readUInt16BE(12);
  if (type === 0x0806) return null;
  if (type !== 0x0800) return { why: "not IPv4" };
  const ip = frame.subarray(14);
  const hl = (ip[0] & 15) * 4;
  if (ip.length < hl + 8 || ip[0] >> 4 !== 4 || hl < 20) return { why: "bad IPv4 header" };
  if (ip.readUInt16BE(6) & 0x3fff) return { why: "fragment" };
  const dst = ip.readUInt32BE(16);
  const proto = ip[9];
  if (within(dst, VNET)) return null;
  const operator = operatorIps.has(dst);
  if (!operator && PRIVATE.some((n) => within(dst, n)) && !(proto === 17 && dst === 0xffffffff))
    return { why: "private address" };
  if (proto === 1) return ip[hl] === 8 ? { flow: `${dst} icmp`, host: dst } : { why: "ICMP other than echo" };
  if (proto !== 6 && proto !== 17) return { why: `IP protocol ${proto}` };
  const sport = ip.readUInt16BE(hl);
  const port = ip.readUInt16BE(hl + 2);
  const flow = { flow: `${proto} ${dst}:${port} ${sport}`, host: dst };
  if (proto === 17) return UDP_PORTS.has(port) || dst === 0xffffffff && port === 67 ? flow : { why: "UDP port" };
  if (ip.length < hl + 20) return { why: "bad TCP header" };
  if (SMTP.has(port)) return { why: "SMTP" };
  if (!operator && port !== 53 && tcpPorts && !tcpPorts.has(port)) return { why: "TCP port" };
  // only a SYN opens a connection; slirp answers other segments of unknown ones with a reset
  return (ip[hl + 13] & 0x12) === 0x02 ? flow : null;
}

const sessions = new Map(); // address -> Set of sessions
const attempts = new Map(); // address -> connections this minute
setInterval(() => attempts.clear(), 60000).unref();

class Session {
  constructor(ws, addr) {
    this.ws = ws;
    this.addr = addr;
    this.up = 0;
    this.down = 0;
    this.dropped = 0;
    this.peak = 0;
    // uplink bytes and frames per second over the last WINDOW_S seconds
    this.secBytes = new Array(WINDOW_S).fill(0);
    this.secFrames = new Array(WINDOW_S).fill(0);
    this.sec = Math.floor(Date.now() / 1000);
    this.tokens = DOWN_BURST;
    this.refill = Date.now();
    this.last = Date.now();
    this.refused = {}; // reason -> frames
    this.flows = new Set();
    this.flowsSince = Date.now();
    this.hosts = new Set();
    this.hostsSince = Date.now();
    this.helper = spawn(HELPER, [], {
      stdio: ["pipe", "pipe", "inherit"],
      env: { SLIRP_HOST_LOOPBACK: process.env.SLIRP_HOST_LOOPBACK ?? "" },
      ...(process.getuid?.() === 0 ? { uid: HELPER_UID, gid: HELPER_UID } : {}),
    });
    this.helper.on("exit", () => this.close(...CLOSE.helper));
    this.helper.stdin.on("error", () => {});
    let buf = Buffer.alloc(0);
    this.helper.stdout.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
        const len = buf.readUInt16BE(0);
        this.toPhone(buf.subarray(2, 2 + len));
        buf = buf.subarray(2 + len);
      }
    });
    ws.on("message", (data, binary) => binary && this.fromPhone(data));
    ws.on("close", () => this.close());
    ws.on("error", () => this.close());
  }

  // uplink: count, ban a client faster than an emulator, pass to slirp
  fromPhone(frame) {
    if (this.closed) return;
    const now = Date.now();
    const sec = Math.floor(now / 1000);
    for (; this.sec < sec; this.sec++) {
      this.secBytes[(this.sec + 1) % WINDOW_S] = 0;
      this.secFrames[(this.sec + 1) % WINDOW_S] = 0;
    }
    this.secBytes[sec % WINDOW_S] += frame.length;
    this.secFrames[sec % WINDOW_S] += 1;
    const rate = this.secBytes.reduce((a, b) => a + b) / WINDOW_S;
    const frames = this.secFrames.reduce((a, b) => a + b) / WINDOW_S;
    this.peak = Math.max(this.peak, rate);
    if (rate > BAN_RATE || frames > BAN_FRAMES) {
      ban(this.addr, `${rate.toFixed(0)} B/s, ${frames.toFixed(1)} frames/s uplink`);
      return;
    }
    if (!this.count(frame.length) || frame.length > FRAME_MAX || !this.admit(frame)) return;
    this.up += frame.length;
    this.last = now;
    const head = Buffer.alloc(2);
    head.writeUInt16BE(frame.length);
    this.helper.stdin.write(Buffer.concat([head, frame]));
  }

  // refusal(), then at most NEW_FLOWS new flows a minute and HOSTS hosts an hour
  admit(frame) {
    const r = refusal(frame);
    if (!r) return true;
    if (!r.why) {
      const now = Date.now();
      if (now - this.flowsSince > 60e3) [this.flows, this.flowsSince] = [new Set(), now];
      if (now - this.hostsSince > 3600e3) [this.hosts, this.hostsSince] = [new Set(), now];
      if (!this.flows.has(r.flow) && this.flows.size >= NEW_FLOWS) r.why = "new flows a minute";
      else if (!this.hosts.has(r.host) && this.hosts.size >= HOSTS) r.why = "hosts an hour";
      else {
        this.flows.add(r.flow);
        this.hosts.add(r.host);
        return true;
      }
    }
    if (!this.refused[r.why]) log(`${this.addr} refused: ${r.why}`);
    this.refused[r.why] = (this.refused[r.why] ?? 0) + 1;
    return false;
  }

  // downlink at most DOWN_RATE; a frame over that is dropped and TCP slows down
  toPhone(frame) {
    if (this.closed) return;
    const now = Date.now();
    this.tokens = Math.min(DOWN_BURST, this.tokens + ((now - this.refill) * DOWN_RATE) / 1000);
    this.refill = now;
    if (this.tokens < frame.length || this.ws.bufferedAmount > DOWN_BURST) {
      this.dropped++;
      return;
    }
    if (!this.count(frame.length)) return;
    this.tokens -= frame.length;
    this.down += frame.length;
    this.ws.send(frame);
  }

  count(bytes) {
    const used = usage(this.addr) + bytes;
    state.usage[this.addr] = used;
    dirty = true;
    if (used <= DAILY_BYTES) return true;
    this.close(...CLOSE.quota);
    return false;
  }

  close(code, reason) {
    if (this.closed) return;
    this.closed = true;
    sessions.get(this.addr)?.delete(this);
    if (!sessions.get(this.addr)?.size) sessions.delete(this.addr);
    this.helper.stdin.end();
    this.helper.kill();
    if (code) this.ws.close(code, reason);
    else this.ws.terminate();
    log(`${this.addr} closed${reason ? ` (${reason})` : ""}: up ${this.up} B, down ${this.down} B, ` +
      `${this.dropped} downlink frames dropped, peak uplink ${this.peak.toFixed(0)} B/s` +
      Object.entries(this.refused).map(([why, n]) => `, ${n} refused (${why})`).join(""));
  }
}

function ban(addr, why) {
  state.bans[addr] = Date.now() + BAN_DAYS * 86400e3;
  dirty = true;
  save();
  log(`${addr} banned for ${BAN_DAYS} days: ${why}`);
  for (const s of [...(sessions.get(addr) ?? [])]) s.close(...CLOSE.banned);
}

setInterval(() => {
  const idle = Date.now() - IDLE_S * 1000;
  for (const set of sessions.values())
    for (const s of [...set]) if (s.last < idle) s.close(...CLOSE.idle);
}, 10000).unref();

const server = http.createServer((req, res) => {
  res.writeHead(426, { "Content-Type": "text/plain" });
  res.end("GPRS gateway: WebSocket only\n");
});
server.headersTimeout = server.requestTimeout = 10000;
const wss = new WebSocketServer({ server, maxPayload: FRAME_MAX, perMessageDeflate: false });
wss.on("connection", (ws, req) => {
  const addr = clientAddress(req);
  const reject = ([code, reason]) => {
    log(`${addr} refused: ${reason}`);
    ws.close(code, reason);
  };
  attempts.set(addr, (attempts.get(addr) ?? 0) + 1);
  if (ORIGINS.length && !ORIGINS.includes(req.headers.origin)) return reject(CLOSE.origin);
  if (banned(addr)) return reject(CLOSE.banned);
  if (attempts.get(addr) > ATTEMPTS) return reject(CLOSE.attempts);
  if ([...sessions.values()].reduce((n, set) => n + set.size, 0) >= MAX_SESSIONS) return reject(CLOSE.full);
  if (usage(addr) >= DAILY_BYTES) return reject(CLOSE.quota);
  if ((sessions.get(addr)?.size ?? 0) >= PER_IP) return reject(CLOSE.connections);
  const s = new Session(ws, addr);
  if (!sessions.has(addr)) sessions.set(addr, new Set());
  sessions.get(addr).add(s);
  log(`${addr} connected (${sessions.get(addr).size} from it)`);
});

const [host, port] = [LISTEN.slice(0, LISTEN.lastIndexOf(":")), Number(LISTEN.slice(LISTEN.lastIndexOf(":") + 1))];
server.listen(port, host, () => log(`gprs-gw listening on ${LISTEN}`));
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => { save(); process.exit(0); });
