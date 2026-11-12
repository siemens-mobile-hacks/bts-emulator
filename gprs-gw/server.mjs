// GPRS gateway for emulators in a browser: a WebSocket per phone, each
// binary message one Ethernet frame of the phone's GPRS (what qemu's
// built-in cell hands to its netdev), and behind every connection its own
// slirp (slirp-pipe), so the phone gets QEMU's -netdev user network.
//
// It runs in the net namespace, where nat.nft sends the helpers' DNS, WAP,
// operator proxy and MMSC traffic to dnsmasq, Kannel, squid and the MMSC,
// and drops what is not for the Internet.
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
const WINDOW_S = 10;
const FRAME_MAX = 1514;

const CLOSE = {
  connections: [4001, "too many connections from this address"],
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

const sessions = new Map(); // address -> Set of sessions

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
    if (!this.count(frame.length) || frame.length > FRAME_MAX) return;
    this.up += frame.length;
    this.last = now;
    const head = Buffer.alloc(2);
    head.writeUInt16BE(frame.length);
    this.helper.stdin.write(Buffer.concat([head, frame]));
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
      `${this.dropped} downlink frames dropped, peak uplink ${this.peak.toFixed(0)} B/s`);
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
const wss = new WebSocketServer({ server, maxPayload: FRAME_MAX });
wss.on("connection", (ws, req) => {
  const addr = clientAddress(req);
  const reject = ([code, reason]) => {
    log(`${addr} refused: ${reason}`);
    ws.close(code, reason);
  };
  if (ORIGINS.length && !ORIGINS.includes(req.headers.origin)) return reject(CLOSE.origin);
  if (banned(addr)) return reject(CLOSE.banned);
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
