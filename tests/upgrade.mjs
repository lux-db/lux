import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createConnection, createServer } from "node:net";
import {
  mkdirSync,
  mkdtempSync,
  openSync,
  closeSync,
  readFileSync,
  cpSync,
  existsSync,
  writeFileSync,
} from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
// Usage: node tests/upgrade.mjs /path/to/published-v0.37.0 /path/to/candidate
// Runs only isolated loopback fixtures. No downloads or installed stack changes.
assert.equal(
  process.argv.length,
  4,
  "supply the v0.37.0 and candidate binary paths",
);
const oldBinary = resolve(process.argv[2]);
const newBinary = resolve(process.argv[3]);
const sha256 = (path) =>
  createHash("sha256").update(readFileSync(path)).digest("hex");
const sourceSha256 = sha256(oldBinary);
const candidateSha256 = sha256(newBinary);
assert(
  [
    "77480001709d62766f2963522b30ade659d3fa02c46f68991cd7744589e6d2d8",
    "4a28981381df531be126f66deace90550cd04a7af749452621865142d97b7a07",
    "b7fa76ce998c66454cee1e55e966c6c378c7e009dcab4fdd56dc4465e2241155",
  ].includes(sourceSha256),
  "source must be an unmodified published v0.37.0 binary",
);
const scratch = resolve(dirname(fileURLToPath(import.meta.url)), "../.scratch");
mkdirSync(scratch, { recursive: true });
const root = mkdtempSync(join(scratch, "upgrade-"));
const password = "local-upgrade-fixture-password";
const auth = true;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function port() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const value = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return value;
}
function command(port, args) {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: "127.0.0.1", port });
    let body = Buffer.alloc(0);
    socket.setTimeout(5000, () => socket.destroy(new Error("command timeout")));
    socket.on("error", reject);
    socket.on("close", () =>
      reject(new Error("connection closed before a complete response")),
    );
    const encode = (values) =>
      `*${values.length}\r\n` +
      values
        .map((value) => `$${Buffer.byteLength(String(value))}\r\n${value}\r\n`)
        .join("");
    socket.on("connect", () =>
      socket.write(encode(["AUTH", password]) + encode(args)),
    );
    function parse(offset = 0) {
      const end = body.indexOf("\r\n", offset);
      if (end < 0) return;
      const type = String.fromCharCode(body[offset]);
      const value = body.toString("utf8", offset + 1, end);
      let next = end + 2;
      if (type === "+" || type === "-" || type === ":")
        return [
          type === ":"
            ? Number(value)
            : type === "-"
              ? { error: value }
              : value,
          next,
        ];
      if (type === "$") {
        const length = Number(value);
        if (length === -1) return [null, next];
        if (body.length < next + length + 2) return;
        return [body.toString("utf8", next, next + length), next + length + 2];
      }
      if (type === "*") {
        if (Number(value) === -1) return [null, next];
        const result = [];
        for (let i = 0; i < Number(value); i++) {
          const item = parse(next);
          if (!item) return;
          result.push(item[0]);
          next = item[1];
        }
        return [result, next];
      }
      throw new Error(`unknown RESP type ${type}`);
    }
    socket.on("data", (chunk) => {
      body = Buffer.concat([body, chunk]);
      try {
        const authenticated = parse();
        if (!authenticated) return;
        assert.equal(authenticated[0], "OK");
        const result = parse(authenticated[1]);
        if (result) {
          socket.destroy();
          resolve(result[0]);
        }
      } catch (error) {
        socket.destroy();
        reject(error);
      }
    });
  });
}
async function start(binary, data, mode, label) {
  const respPort = await port();
  const httpPort = await port();
  const logPath = join(data, `${label}.log`);
  const log = openSync(logPath, "w", 0o600);
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => !key.startsWith("LUX_")),
  );
  Object.assign(env, {
    LUX_PORT: String(respPort),
    LUX_HTTP_PORT: String(httpPort),
    LUX_PASSWORD: password,
    LUX_BIND_HOST: "127.0.0.1",
    LUX_DATA_DIR: data,
    LUX_STORAGE_MODE: mode,
    LUX_SHARDS: "2",
    LUX_RUNTIME_THREADS: "2",
    LUX_SAVE_INTERVAL: "3600",
    RAYON_NUM_THREADS: "2",
  });
  if (mode === "tiered") {
    env.LUX_MAXMEMORY = label === "rollback" ? "0" : "128kb";
    env.LUX_MAXMEMORY_POLICY = "allkeys-lru";
  }
  if (auth)
    Object.assign(env, {
      LUX_AUTH_ENABLED: "1",
      LUX_AUTH_ISSUER: "http://localhost/upgrade-fixture/auth/v1",
      LUX_AUTH_PUBLISHABLE_KEY: "lux_pub_upgrade_fixture",
      LUX_ENC_AUTO_INIT: "1",
    });
  const child = spawn(binary, [], {
    cwd: data,
    env,
    stdio: ["ignore", log, log],
  });
  closeSync(log);
  let spawnError;
  const exited = new Promise((resolve) => {
    child.on("exit", (code, signal) => resolve({ code, signal }));
    child.on("error", (error) => {
      spawnError = error;
      resolve({ error });
    });
  });
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (spawnError) throw spawnError;
    if (child.exitCode !== null || child.signalCode !== null)
      throw new Error(
        `${label} startup failed: ${readFileSync(logPath, "utf8")}`,
      );
    try {
      if ((await command(respPort, ["PING"])) === "PONG")
        return {
          child,
          exited,
          httpPort,
          command: (args) => command(respPort, args),
        };
    } catch {}
    await sleep(50);
  }
  child.kill("SIGKILL");
  await exited;
  throw new Error(`${label} readiness timeout`);
}
async function stop(server, signal = "SIGKILL") {
  server.child.kill(signal);
  await server.exited;
}

function copySnapshot(source, target) {
  for (const file of ["lux.dat", "lux.enc", "lux.enc.seal"])
    if (existsSync(join(source, file)))
      cpSync(join(source, file), join(target, file));
}

async function rejectedImport(source, mode, kind) {
  const target = mkdtempSync(join(root, `${mode}-${kind}-`));
  if (kind === "incomplete") {
    copySnapshot(source, target);
    const bytes = readFileSync(join(target, "lux.dat"));
    writeFileSync(
      join(target, "lux.dat"),
      bytes.subarray(0, Math.floor(bytes.length / 2)),
      { mode: 0o600 },
    );
  } else {
    cpSync(join(source, "lux.dat"), join(target, "lux.dat"));
    cpSync(join(source, "lux.enc"), join(target, "lux.enc"));
  }
  const before = sha256(join(target, "lux.dat"));
  let server;
  let failure;
  try {
    server = await start(newBinary, target, mode, "rejected-import");
  } catch (error) {
    failure = error;
  }
  if (server) await stop(server);
  assert(
    failure && /startup failed:/.test(failure.message),
    `${kind} import must refuse startup, not merely time out`,
  );
  assert.equal(
    sha256(join(target, "lux.dat")),
    before,
    "failed import must not rewrite the snapshot",
  );
  copySnapshot(source, target);
  server = await start(newBinary, target, mode, "repaired-import");
  try {
    assert.equal(await server.command(["GET", "text"]), "preserved");
    assert.equal(await server.command(["GET", "encrypted"]), "fixture-value");
  } finally {
    await stop(server);
  }
}
async function request(server, path, body, token) {
  const response = await fetch(`http://127.0.0.1:${server.httpPort}${path}`, {
    method: body ? "POST" : "GET",
    headers: {
      apikey: "lux_pub_upgrade_fixture",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(5000),
  });
  const value = await response.json();
  assert(
    response.ok,
    `${path}: HTTP ${response.status} ${JSON.stringify(value)}`,
  );
  return value;
}

async function verifyAccess(server, session, other, label) {
  const rows = await request(
    server,
    "/v1/tables/owned",
    null,
    session.access_token,
  );
  assert(
    JSON.stringify(rows).includes('"mine"'),
    "owner must see its saved row",
  );
  assert(
    !JSON.stringify(rows).includes('"theirs"'),
    "read grant must exclude another owner",
  );
  const denied = await fetch(
    `http://127.0.0.1:${server.httpPort}/v1/tables/rows`,
    {
      headers: {
        apikey: "lux_pub_upgrade_fixture",
        Authorization: `Bearer ${session.access_token}`,
      },
      signal: AbortSignal.timeout(5000),
    },
  );
  assert.equal(
    denied.status,
    403,
    "table without a grant must remain inaccessible",
  );
  await denied.arrayBuffer();

  // Reconnect after an upgrade; live connections and missed events are not persisted.
  const url = new URL(`ws://127.0.0.1:${server.httpPort}/live`);
  url.searchParams.set("apikey", "lux_pub_upgrade_fixture");
  url.searchParams.set("access_token", session.access_token);
  const socket = new WebSocket(url);
  const events = [];
  let failure;
  socket.addEventListener("error", () => {
    failure = new Error("live socket failed");
  });
  socket.addEventListener("message", ({ data }) => {
    try {
      const message = JSON.parse(String(data));
      if (message.type === "live.error")
        failure = new Error(JSON.stringify(message.error));
      if (message.type === "live.event") events.push(message.event);
    } catch (error) {
      failure = error;
    }
  });
  async function until(predicate) {
    const deadline = Date.now() + 5000;
    while (!predicate()) {
      if (failure) throw failure;
      assert(Date.now() < deadline, "live response deadline exceeded");
      await sleep(10);
    }
  }
  try {
    await until(() => socket.readyState === WebSocket.OPEN);
    socket.send(
      JSON.stringify({
        type: "live.subscribe",
        id: "owned",
        spec: { kind: "table", table: "owned" },
      }),
    );
    await until(() => events.some((event) => event.kind === "snapshot"));
    assert(JSON.stringify(events).includes('"mine"'));
    assert(!JSON.stringify(events).includes('"theirs"'));
    for (const [id, owner] of [
      [`hidden-${label}`, other.user.id],
      [`visible-${label}`, session.user.id],
    ]) {
      const result = await server.command([
        "TINSERT",
        "owned",
        "id",
        id,
        "owner",
        owner,
      ]);
      assert(!result?.error, JSON.stringify(result));
    }
    await until(() =>
      events.some(
        (event) =>
          event.kind === "insert" &&
          JSON.stringify(event).includes(`visible-${label}`),
      ),
    );
    await sleep(100);
    assert(
      !JSON.stringify(events).includes(`hidden-${label}`),
      "live grant must exclude another owner",
    );
  } finally {
    socket.close();
  }
}
const writes = [
  ["SET", "text", "preserved"],
  ["HSET", "hash", "a", "one", "b", "two"],
  ["RPUSH", "list", "first", "second"],
  ["SADD", "set", "a", "b"],
  ["ZADD", "sorted", "1", "a", "2", "b"],
  ["XADD", "queue", "1-0", "job", "one"],
  ["TSADD", "series", "1000", "42.5"],
  ["VSET", "vector", "2", "1", "0", "META", '{"label":"one"}'],
  ["TCREATE", "rows", "id INT PRIMARY KEY, value STR, profile JSON"],
  ["TINSERT", "rows", "id", "1", "value", "saved", "profile", '{"rank":7}'],
  ["TINDEX", "rows", "profile.rank", "INT"],
  [
    "LUX",
    "MIGRATE",
    "APPLY",
    "001_fixture.lux",
    "TCREATE migrated id INT PRIMARY KEY, value STR;\nTINSERT migrated id 1 value ledgered;",
  ],
  ["XGROUP", "CREATE", "queue", "workers", "0"],
  [
    "XREADGROUP",
    "GROUP",
    "workers",
    "worker",
    "COUNT",
    "1",
    "STREAMS",
    "queue",
    ">",
  ],
  ["SET", "ttl", "alive", "EX", "3600"],
];
const reads = [
  ["GET", "text"],
  ["HGETALL", "hash"],
  ["LRANGE", "list", "0", "-1"],
  ["SMEMBERS", "set"],
  ["ZRANGE", "sorted", "0", "-1", "WITHSCORES"],
  ["XRANGE", "queue", "-", "+"],
  ["TSRANGE", "series", "-", "+"],
  ["VGET", "vector"],
  ["TSELECT", "*", "FROM", "rows"],
  ["GET", "ttl"],
];
reads.push(
  ["TSELECT", "*", "FROM", "rows", "WHERE", "profile.rank", "=", "7"],
  ["TSELECT", "*", "FROM", "rows", "WHERE", "value", "=", "saved"],
  ["TSELECT", "*", "FROM", "migrated"],
  ["LUX", "MIGRATE", "LIST"],
  ["XPENDING", "queue", "workers"],
);
const baseReadCount = reads.length;
const coldValues = Array.from(
  { length: 32 },
  (_, i) => `${i}:` + "x".repeat(8192),
);
for (let i = 0; i < coldValues.length; i++) reads.push(["GET", `cold:${i}`]);
const results = [];
for (const mode of ["memory", "tiered"]) {
  const snapshot = true;
  const data = mkdtempSync(join(root, `${mode}-source-`));
  let target = data;
  let server;
  try {
    server = await start(oldBinary, data, mode, "old");
    let session;
    if (auth)
      session = await request(server, "/auth/v1/signup", {
        email: "upgrade@example.test",
        password: "fixture-password-12345",
      });
    const parallelSessions = auth
      ? await Promise.all(
          Array.from({ length: 12 }, (_, i) =>
            request(server, "/auth/v1/signup", {
              email: `parallel-${i}@example.test`,
              password: "fixture-password-12345",
            }),
          ),
        )
      : [];
    for (const args of writes) {
      const response = await server.command(args);
      assert(!response?.error, JSON.stringify({ command: args[0], response }));
    }
    for (const args of [
      ["TCREATE", "owned", "id STR PRIMARY KEY, owner STR"],
      ["TINSERT", "owned", "id", "mine", "owner", session.user.id],
      [
        "TINSERT",
        "owned",
        "id",
        "theirs",
        "owner",
        parallelSessions[0].user.id,
      ],
      ["GRANT", "read", "ON", "owned", "WHERE", "owner", "=", "auth.uid()"],
    ]) {
      const result = await server.command(args);
      assert(!result?.error, JSON.stringify(result));
    }
    const expected = [];
    // Capture the logical baseline before memory pressure. The old engine's
    // table scans can omit cold rows; they are not an oracle for expected data.
    for (const args of reads.slice(0, baseReadCount))
      expected.push(await server.command(args));
    for (let i = 0; i < coldValues.length; i++) {
      assert.equal(
        await server.command(["SET", `cold:${i}`, coldValues[i]]),
        "OK",
      );
      expected.push(coldValues[i]);
    }
    if (mode === "tiered") {
      const info = await server.command(["INFO"]);
      assert(
        Number(info.match(/disk_keys:(\d+)/)?.[1]) > 0,
        "fixture must include real cold data",
      );
    }
    if (auth)
      assert.equal(
        await server.command([
          "SET",
          "encrypted",
          "fixture-value",
          "ENCRYPTED",
        ]),
        "OK",
      );
    if (snapshot)
      assert.match(
        await server.command(["SAVE"]),
        /^OK(?: \(\d+ keys saved\))?$/,
      );
    if (mode === "tiered")
      assert.equal(
        await server.command(["SET", "tail", "after_snapshot"]),
        "OK",
      );
    assert.equal(
      await server.command([
        "SET",
        "expires-offline",
        "temporary",
        "PX",
        "2000",
      ]),
      "OK",
    );
    const expiresBy = Date.now() + 2100;
    assert.match(
      await server.command(["SAVE"]),
      /^OK(?: \(\d+ keys saved\))?$/,
    );
    await sleep(1200); // Published WAL fsync interval.
    await stop(server);
    server = null;
    await sleep(Math.max(0, expiresBy - Date.now()));
    cpSync(data, `${data}-before`, { recursive: true });
    const snapshotSha256 = sha256(join(data, "lux.dat"));
    await rejectedImport(data, mode, "incomplete");
    await rejectedImport(data, mode, "missing-seal");
    {
      target = mkdtempSync(join(root, `${mode}-import-`));
      copySnapshot(data, target);
    }
    server = await start(newBinary, target, mode, "new");
    assert.equal(await server.command(["GET", "expires-offline"]), null);
    assert.equal(await server.command(["PTTL", "expires-offline"]), -2);
    await verifyAccess(server, session, parallelSessions[0], "import");
    const actual = [];
    for (const args of reads) actual.push(await server.command(args));
    assert.deepEqual(actual, expected);
    if (mode === "tiered")
      assert.equal(await server.command(["GET", "tail"]), "after_snapshot");
    if (auth) {
      assert.equal(await server.command(["GET", "encrypted"]), "fixture-value");
      await request(server, "/auth/v1/user", null, session.access_token);
      for (const saved of parallelSessions)
        await request(server, "/auth/v1/user", null, saved.access_token);
      const refreshed = await request(server, "/auth/v1/token", {
        grant_type: "refresh_token",
        refresh_token: session.refresh_token,
      });
      assert(refreshed.access_token && refreshed.refresh_token);
      await request(server, "/auth/v1/token", {
        grant_type: "password",
        email: "upgrade@example.test",
        password: "fixture-password-12345",
      });
    }
    assert.equal(await server.command(["SET", "new_write", "preserved"]), "OK");
    await stop(server);
    server = null;
    server = await start(newBinary, target, mode, "new-restart");
    assert.equal(await server.command(["GET", "new_write"]), "preserved");
    assert.equal(await server.command(["GET", "expires-offline"]), null);
    await verifyAccess(server, session, parallelSessions[0], "restart");
    {
      await stop(server);
      server = null;
      server = await start(oldBinary, `${data}-before`, mode, "rollback");
      assert.equal(await server.command(["GET", "expires-offline"]), null);
      for (let i = 0; i < reads.length; i++)
        assert.deepEqual(await server.command(reads[i]), expected[i]);
      assert.equal(await server.command(["GET", "new_write"]), null);
      if (auth) {
        assert.equal(
          await server.command(["GET", "encrypted"]),
          "fixture-value",
        );
        await request(server, "/auth/v1/user", null, session.access_token);
        for (const saved of parallelSessions)
          await request(server, "/auth/v1/user", null, saved.access_token);
      }
    }
    assert.equal(
      sha256(join(data, "lux.dat")),
      snapshotSha256,
      "source snapshot must remain untouched",
    );
    results.push({ mode, snapshot, result: "pass", snapshotSha256 });
  } catch (error) {
    results.push({
      mode,
      snapshot,
      result: "fail",
      error: error.message,
      data,
    });
  } finally {
    if (server) await stop(server);
  }
}
console.log(
  JSON.stringify(
    { sourceSha256, candidateSha256, fixtures: root, results },
    null,
    2,
  ),
);
if (results.some((result) => result.result === "fail")) process.exitCode = 1;
