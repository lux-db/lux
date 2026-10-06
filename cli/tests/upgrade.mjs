import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createServer, createConnection } from "node:net";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  cpSync,
  chmodSync,
  existsSync,
} from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes, randomInt } from "node:crypto";
const exec = promisify(execFile);
assert.equal(
  process.argv.length,
  5,
  "usage: node cli/tests/upgrade.mjs CLI_BINARY OLD_IMAGE CANDIDATE_IMAGE",
);
const cliBinary = resolve(process.argv[2]);
const oldImage = process.argv[3],
  candidateImage = process.argv[4];
assert(/^[a-zA-Z0-9]/.test(oldImage) && /^[a-zA-Z0-9]/.test(candidateImage));
const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
mkdirSync(join(root, ".scratch"), { recursive: true });
const nonce = randomBytes(8).toString("hex");
const realDocker = (await exec("which", ["docker"])).stdout.trim();
const candidateTag = `local-validation-upgrade-${nonce}`;
const dir = mkdtempSync(join(root, ".scratch/cli-upgrade-"));
const bin = join(dir, "bin");
mkdirSync(bin);
cpSync(join(root, "cli/tests/upgrade-docker.mjs"), join(bin, "docker"));
chmodSync(join(bin, "docker"), 0o755);
const mode = process.env.AUTO_TEST_MODE || "normal";
assert(["normal", "backup-rollback", "unsupported-downgrade", "verification-write", "snapshot-failure", "stopped-snapshot-failure", "probe-failure", "import-failure", "stopped", "prepare-interruption", "cutover-interruption"].includes(mode), "unknown test mode");
const sourceStorage = process.env.LUX_SOURCE_STORAGE_MODE || "tiered";
assert(["memory", "tiered"].includes(sourceStorage), "unknown source storage mode");
const refusesUpdate = ["unsupported-downgrade", "snapshot-failure", "stopped-snapshot-failure", "probe-failure", "import-failure"].includes(mode);
const startsStopped = ["stopped", "stopped-snapshot-failure"].includes(mode);
const docker = (...args) => exec(realDocker, args, { timeout: 30000 });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const selectedPorts = new Set();
async function port() {
  // Stay outside the host's ephemeral client-port range: test HTTP requests
  // must not claim a future Docker listener port while the image starts.
  for (let attempt = 0; attempt < 100; attempt++) {
    const p = randomInt(20000, 30000);
    if (selectedPorts.has(p)) continue;
    const s = createServer();
    try {
      await new Promise((resolve, reject) => {
        s.once("error", reject);
        s.listen(p, "127.0.0.1", resolve);
      });
      await new Promise((resolve) => s.close(resolve));
      selectedPorts.add(p);
      return p;
    } catch (error) {
      if (error.code !== "EADDRINUSE") throw error;
    }
  }
  throw Error("no available fixture port");
}
const password = "local-upgrade-test-password";
function responseEnd(body, start = 0) {
  const end = body.indexOf("\r\n", start);
  if (end < 0) return null;
  const type = body[start];
  if ([43, 45, 58].includes(type)) return end + 2;
  const count = Number(body.subarray(start + 1, end).toString());
  assert(Number.isSafeInteger(count) && count >= -1, "invalid RESP length");
  if (count === -1) return end + 2;
  if (type === 36) {
    const finish = end + 2 + count + 2;
    if (body.length < finish) return null;
    assert.equal(body.subarray(finish - 2, finish).toString(), "\r\n");
    return finish;
  }
  assert.equal(type, 42, "unsupported RESP reply");
  let cursor = end + 2;
  for (let i = 0; i < count; i++) {
    cursor = responseEnd(body, cursor);
    if (cursor === null) return null;
  }
  return cursor;
}
function cmd(port, args) {
  return new Promise((resolve, reject) => {
    const s = createConnection({ host: "127.0.0.1", port });
    let body = Buffer.alloc(0);
    s.setTimeout(2000, () => s.destroy(new Error("deadline")));
    s.on("error", reject);
    s.on("close", () => reject(new Error("closed")));
    const encode = (a) =>
      `*${a.length}\r\n` +
      a.map((v) => `$${Buffer.byteLength(String(v))}\r\n${v}\r\n`).join("");
    s.on("connect", () => s.write(encode(["AUTH", password]) + encode(args)));
    s.on("data", (c) => {
      try {
        body = Buffer.concat([body, c]);
        assert(body.length <= 1024 * 1024, "fixture response too large");
        const authenticated = responseEnd(body);
        if (authenticated === null) return;
        assert.equal(body.subarray(0, authenticated).toString(), "+OK\r\n");
        const end = responseEnd(body, authenticated);
        if (end === null) return;
        s.destroy();
        resolve(body.subarray(authenticated, end).toString());
      } catch (error) {
        s.destroy();
        reject(error);
      }
    });
  });
}
async function assertDocumentSchema(port, phase) {
  const schema = await cmd(port, ["TSCHEMA", "documents"]);
  for (const field of [
    "id INT PRIMARY KEY NOT NULL",
    "metadata JSON",
    "embedding VECTOR(3)",
  ]) assert(schema.includes(field), `${phase} schema is missing ${field}`);
}
const p = await port(),
  h = await port();
const container = `lux-upgrade-test-${nonce}`;
const volume = `${container}-data`;
const old = oldImage;
const sourceId = (
  await docker("image", "inspect", "--format", "{{.Id}}", oldImage)
).stdout.trim();
const candidateId = (
  await docker("image", "inspect", "--format", "{{.Id}}", candidateImage)
).stdout.trim();
assert.notEqual(
  sourceId,
  candidateId,
  "source and candidate must be different images",
);
await docker("tag", candidateImage, `ghcr.io/lux-db/lux:${candidateTag}`);
const project = join(dir, "project");
mkdirSync(join(project, "lux"), { recursive: true });
mkdirSync(join(project, "lux/migrations"));
writeFileSync(
  join(project, "lux/config.toml"),
  `engine_version = "${candidateTag}"\n`,
);
writeFileSync(
  join(project, "lux/migrations/001_lifecycle.lux"),
  "TCREATE migration_rows id INT PRIMARY KEY, value STR;\n" +
    "TINSERT migration_rows id 1 value preserved;\n",
);
const state = {
  password,
  publishable_key: "lux_pub_upgrade_test",
  secret_key: password,
  http_port: h,
  resp_port: p,
  container,
  volume,
  image: old,
  bind_host: "127.0.0.1",
  studio_port: await port(),
  studio_container: `${container}-studio`,
  seed_status: "complete",
};
writeFileSync(join(project, "lux/.lux-local.json"), JSON.stringify(state), {
  mode: 0o600,
});
const env = Object.fromEntries(
  Object.entries(process.env).filter(([k]) => !k.startsWith("LUX_")),
);
env.PATH = bin + ":" + env.PATH;
env.UPGRADE_TEST_DOCKER_BINARY = realDocker;
if (mode.endsWith("interruption")) {
  env.VALIDATION_MARKER = join(dir, "pause.json");
  if (mode === "prepare-interruption") env.VALIDATION_PAUSE = "rename";
  else env.AUTO_CUTOVER_NAME = container;
}
const owned = [];
let completed = false;
try {
  await docker(
    "run",
    "-d",
    "--name",
    container,
    "--restart",
    "unless-stopped",
    "-p",
    `127.0.0.1:${p}:6379`,
    "-p",
    `127.0.0.1:${h}:5890`,
    "-v",
    `${volume}:/data`,
    "--cpus",
    "1",
    "-e",
    "LUX_DATA_DIR=/data",
    "-e",
    `LUX_STORAGE_MODE=${sourceStorage}`,
    "-e",
    "LUX_PORT=6379",
    "-e",
    "LUX_HTTP_PORT=5890",
    "-e",
    "LUX_BIND_HOST=0.0.0.0",
    "-e",
    `LUX_PASSWORD=${password}`,
    "-e",
    "LUX_AUTH_ENABLED=1",
    "-e",
    "LUX_AUTH_PUBLISHABLE_KEY=lux_pub_upgrade_test",
    "-e",
    `LUX_AUTH_ISSUER=http://localhost:${h}/auth/v1`,
    "-e",
    "LUX_ENC_AUTO_INIT=1",
    "-e",
    "LUX_RUNTIME_THREADS=2",
    "-e",
    "LUX_SHARDS=2",
    old,
  );
  for (let i = 0; i < 40; i++) {
    try {
      assert.match(await cmd(p, ["PING"]), /PONG/);
      break;
    } catch {
      await sleep(100);
    }
  }
  const signup = await fetch(`http://127.0.0.1:${h}/auth/v1/signup`, {
    method: "POST",
    headers: {
      apikey: state.publishable_key,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email: "automatic@example.test",
      password: "fixture-password-12345",
    }),
  });
  assert(signup.ok);
  const session = await signup.json();
  await exec(cliBinary, ["migrate", "run"], {
    cwd: project,
    env,
    timeout: 30000,
  });
  for (const operation of [
    ["SET", "string", "preserved"],
    ["SET", "expires", "preserved"],
    ["PEXPIREAT", "expires", "4102444800000"],
    ["SET", "protected", "sealed-value", "ENCRYPTED"],
    ["HSET", "hash", "field", "preserved"],
    ["RPUSH", "list", "first", "second"],
    ["SADD", "set", "member"],
    ["ZADD", "sorted", "1", "member"],
    ["XADD", "jobs", "1-0", "body", "preserved"],
    ["XGROUP", "CREATE", "jobs", "workers", "0"],
    ["XREADGROUP", "GROUP", "workers", "fixture", "COUNT", "1", "STREAMS", "jobs", ">"],
    ["PFADD", "cardinality", "one", "two", "three"],
    ["TSADD", "metric", "1000", "42.5", "LABELS", "kind", "fixture"],
    ["VSET", "vector", "3", "1", "0", "0", "META", '{"kind":"fixture"}'],
    ["TCREATE", "rows", "id INT PRIMARY KEY, value STR"],
    ["TINSERT", "rows", "id", "1", "value", "preserved"],
    ["TCREATE", "documents", "id INT PRIMARY KEY, metadata JSON, embedding VECTOR(3)"],
    ["TINDEX", "documents", "metadata.kind", "STR"],
    ["TINSERT", "documents", "id", "1", "metadata", '{"kind":"fixture"}', "embedding", "[1,0,0]"],
  ]) assert(!((await cmd(p, operation)).startsWith("-")), `${operation[0]} failed`);
  const reads = [
    ["GET", "string"],
    ["GET", "expires"],
    ["GET", "protected"],
    ["HGET", "hash", "field"],
    ["LRANGE", "list", "0", "-1"],
    ["SISMEMBER", "set", "member"],
    ["ZRANGE", "sorted", "0", "-1", "WITHSCORES"],
    ["XLEN", "jobs"],
    ["XPENDING", "jobs", "workers"],
    ["PFCOUNT", "cardinality"],
    ["TSRANGE", "metric", "0", "2000"],
    ["VGET", "vector"],
    ["TSELECT", "*", "FROM", "rows"],
    ["TSELECT", "*", "FROM", "migration_rows"],
    ["TSELECT", "*", "FROM", "documents", "WHERE", "metadata.kind", "=", "fixture"],
  ];
  const before = [];
  for (const query of reads) {
    const response = await cmd(p, query);
    assert(!response.startsWith("-"), `${query[0]} failed`);
    before.push(response);
  }
  await assertDocumentSchema(p, "source");
  if (startsStopped) {
    assert.match(await cmd(p, ["SET", "before-stop", "value"]), /\+OK/);
    assert.match(await cmd(p, ["SAVE"]), /\+OK/);
    await docker("kill", "--signal", "KILL", container);
  }
  const acknowledged = [];
  let sending = true;
  const writer = (async () => {
    for (let i = 0; sending && i < 2000; i++) {
      try {
        assert.match(await cmd(p, ["SET", `written:${i}`, "value"]), /\+OK/);
        acknowledged.push(i);
      } catch {
        break;
      }
      await sleep(5);
    }
  })();
  await sleep(100);
  let cli;
  try {
    const pending = exec(cliBinary, ["update", "engine"], {
      cwd: project,
      env,
      timeout: 120000,
    });
    if (mode.endsWith("interruption")) {
      const settled = pending.catch((error) => error);
      const deadline = Date.now() + 30000;
      while (!existsSync(env.VALIDATION_MARKER)) {
        assert(Date.now() < deadline, "pause boundary not reached");
        await sleep(50);
      }
      if (mode === "cutover-interruption") {
        for (let i = 0; i < 50; i++) {
          try {
            assert.match(
              await cmd(p, ["SET", "after-cutover", "keep-this"]),
              /\+OK/,
            );
            break;
          } catch {
            assert(i < 49);
            await sleep(100);
          }
        }
      }
      const child = JSON.parse(readFileSync(env.VALIDATION_MARKER, "utf8"));
      process.kill(pending.child.pid, "SIGKILL");
      try {
        await exec(cliBinary, ["start", "--no-studio"], { cwd: project, env, timeout: 10000 });
        assert.fail("recovery must wait for the pending Docker operation");
      } catch (error) {
        assert.equal(error.code, 1);
        assert.match(error.stderr, /another local engine operation is still running/);
      } finally {
        process.kill(child.pid, "SIGKILL");
      }
      await settled;
      delete env.VALIDATION_PAUSE;
      delete env.AUTO_CUTOVER_NAME;
      delete env.VALIDATION_MARKER;
      cli = await exec(cliBinary, ["start", "--no-studio"], {
        cwd: project,
        env,
        timeout: 120000,
      });
    } else cli = await pending;
    assert(!refusesUpdate, "expected update refusal");
  } catch (error) {
    if (!refusesUpdate) throw error;
    assert.equal(error.code, 1);
    cli = error;
    if (mode === "unsupported-downgrade")
      assert.match(error.stderr, /does not support automatic snapshot upgrades/);
    else assert.match(error.stderr, /original engine restored/);
  }
  sending = false;
  await writer;
  writeFileSync(join(dir, "cli.log"), cli.stdout + "\n" + cli.stderr);
  const updated = JSON.parse(
    readFileSync(join(project, "lux/.lux-local.json"), "utf8"),
  );
  if (refusesUpdate || mode === "prepare-interruption")
    assert.equal(updated.volume, volume);
  else assert.notEqual(updated.volume, volume);
  if (mode === "unsupported-downgrade") assert.equal(updated.image, old);
  else assert(updated.image.startsWith("sha256:"));
  if (startsStopped) {
    const status = await docker(
      "inspect",
      "-f",
      "{{.State.Status}}",
      container,
    );
    assert.equal(status.stdout.trim(), refusesUpdate ? "exited" : "created");
    await docker("start", container);
    await sleep(500);
    assert.match(await cmd(p, ["EXISTS", "before-stop"]), /:1\r\n/);
  }
  for (const i of acknowledged)
    assert.match(await cmd(p, ["EXISTS", `written:${i}`]), /:1\r\n/);
  for (let i = 0; i < reads.length; i++)
    assert.equal(await cmd(p, reads[i]), before[i], `${reads[i][0]} changed`);
  await assertDocumentSchema(p, "candidate");
  const ttl = await cmd(p, ["PTTL", "expires"]);
  assert.match(ttl, /^:\d+\r\n$/, "absolute TTL was not preserved");
  if (mode === "verification-write")
    assert.equal(await cmd(p, ["EXISTS", "verification-only"]), ":0\r\n");
  if (mode === "cutover-interruption")
    assert.match(await cmd(p, ["EXISTS", "after-cutover"]), /:1\r\n/);
  const user = await fetch(`http://127.0.0.1:${h}/auth/v1/user`, {
    headers: {
      apikey: state.publishable_key,
      Authorization: `Bearer ${session.access_token}`,
    },
  });
  assert.equal(user.status, 200);
  const login = await fetch(`http://127.0.0.1:${h}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: {
      apikey: state.publishable_key,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email: "automatic@example.test",
      password: "fixture-password-12345",
    }),
  });
  assert.equal(login.status, 200, "password login failed after upgrade");
  await exec(cliBinary, ["migrate", "status", "--check"], {
    cwd: project,
    env,
    timeout: 30000,
  });
  const records = await docker("ps", "-a", "--format", "{{.Names}}");
  owned.push(
    ...records.stdout
      .trim()
      .split("\n")
      .filter((n) => n.startsWith(container)),
  );
  if (!refusesUpdate && mode !== "prepare-interruption")
    assert(owned.some((n) => n.includes("-backup-")));
  for (const backup of owned.filter(n => n.includes("-backup-"))) {
    const policy = await docker("inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", backup);
    assert.equal(policy.stdout.trim(), "no", "a retained backup must not auto-start");
  }
  if (mode === "backup-rollback") {
    const backup = owned.find((name) => name.includes("-backup-"));
    assert(backup, "upgrade did not retain a backup container");
    await docker("stop", "--timeout", "300", updated.container);
    await docker("network", "connect", "bridge", backup);
    await docker("start", backup);
    for (let i = 0; i < 40; i++) {
      try {
        assert.match(await cmd(p, ["PING"]), /PONG/);
        break;
      } catch {
        assert(i < 39, "backup did not become ready");
        await sleep(100);
      }
    }
    for (let i = 0; i < reads.length; i++)
      assert.equal(await cmd(p, reads[i]), before[i], `${reads[i][0]} changed in backup`);
    await assertDocumentSchema(p, "backup");
    assert.match(await cmd(p, ["SAVE"]), /OK/, "backup SAVE failed");
    await docker("kill", "--signal", "KILL", backup);
    await docker("network", "disconnect", "--force", "bridge", backup);
    await docker("start", updated.container);
    for (let i = 0; i < 40; i++) {
      try {
        assert.match(await cmd(p, ["PING"]), /PONG/);
        break;
      } catch {
        assert(i < 39, "candidate did not resume after backup verification");
        await sleep(100);
      }
    }
  }
  console.log(
    JSON.stringify({
      result: "pass",
      mode,
      sourceStorage,
      sourceId,
      candidateId,
      acknowledged: acknowledged.length,
      dir,
      updatedVolume: updated.volume,
    }),
  );
  completed = true;
} catch (error) {
  console.error(error.message, error.stdout || "", error.stderr || "");
  process.exitCode = 1;
} finally {
  const records = await docker("ps", "-a", "--format", "{{.Names}}");
  for (const c of records.stdout
    .trim()
    .split("\n")
    .filter((n) => n.startsWith(container)))
    await docker("rm", "-f", c).catch(() => {});
  await docker("image", "rm", `ghcr.io/lux-db/lux:${candidateTag}`).catch(
    () => {},
  );
  if (completed && process.env.LUX_KEEP_LIFECYCLE_FIXTURES !== "1") {
    const volumes = await docker("volume", "ls", "--format", "{{.Name}}");
    for (const name of volumes.stdout
      .trim()
      .split("\n")
      .filter((name) => name.startsWith(`${container}-data`)))
      await docker("volume", "rm", name).catch(() => {});
  }
}
