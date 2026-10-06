import assert from "node:assert/strict";
import Redis from "ioredis";

const password = process.env.LUX_COMPAT_PASSWORD ?? "lux-client-compat";
const luxPort = Number(process.env.LUX_COMPAT_PORT ?? "26379");
const valkeyPort = Number(process.env.LUX_COMPAT_REFERENCE_PORT ?? "26380");

function client(port: number) {
  return new Redis({
    host: "127.0.0.1",
    port,
    password,
    protocol: 2,
    enableReadyCheck: false,
    lazyConnect: true,
    maxRetriesPerRequest: 1,
  });
}

const lux = client(luxPort);
const valkey = client(valkeyPort);

type Command = readonly (string | Buffer)[];
type Result = unknown;

function normalize(value: Result): Result {
  if (Buffer.isBuffer(value)) return { bytes: value.toString("hex") };
  if (Array.isArray(value)) return value.map(normalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, normalize(item)]),
    );
  }
  return value;
}

function sorted(value: Result): Result {
  if (!Array.isArray(value)) return normalize(value);
  return value.map(normalize).sort((left, right) =>
    JSON.stringify(left).localeCompare(JSON.stringify(right)),
  );
}

async function call(redis: Redis, command: Command): Promise<Result> {
  const [name, ...args] = command;
  return redis.call(name, ...args);
}

async function compare(
  family: string,
  commands: readonly Command[],
  transform: (value: Result) => Result = normalize,
) {
  await Promise.all([lux.flushdb(), valkey.flushdb()]);
  for (const command of commands) {
    const [luxResult, valkeyResult] = await Promise.all([
      call(lux, command),
      call(valkey, command),
    ]);
    assert.deepStrictEqual(
      transform(luxResult),
      transform(valkeyResult),
      `${family}: ${String(command[0])} diverged`,
    );
  }
  console.log(`differential: ${family}`);
}

async function compareSets() {
  await Promise.all([lux.flushdb(), valkey.flushdb()]);
  const ordered: Command[] = [
    ["SADD", "set:a", "one", "two", "three"],
    ["SADD", "set:b", "three", "four"],
    ["SCARD", "set:a"],
    ["SISMEMBER", "set:a", "two"],
    ["SMISMEMBER", "set:a", "one", "missing"],
    ["SMOVE", "set:a", "set:b", "two"],
    ["SINTERCARD", "2", "set:a", "set:b"],
    ["SDIFFSTORE", "set:diff", "set:a", "set:b"],
    ["SINTERSTORE", "set:inter", "set:a", "set:b"],
    ["SUNIONSTORE", "set:union", "set:a", "set:b"],
  ];
  for (const command of ordered) {
    assert.deepStrictEqual(normalize(await call(lux, command)), normalize(await call(valkey, command)), `sets: ${command[0]} diverged`);
  }
  for (const command of [
    ["SMEMBERS", "set:a"],
    ["SDIFF", "set:a", "set:b"],
    ["SINTER", "set:a", "set:b"],
    ["SUNION", "set:a", "set:b"],
  ] satisfies Command[]) {
    assert.deepStrictEqual(sorted(await call(lux, command)), sorted(await call(valkey, command)), `sets: ${command[0]} diverged`);
  }
  console.log("differential: sets");
}

async function compareExpiry() {
  await Promise.all([lux.flushdb(), valkey.flushdb()]);
  for (const redis of [lux, valkey]) {
    await redis.set("expires", "value");
    assert.equal(await redis.pexpire("expires", 30_000), 1);
  }
  const [luxTtl, valkeyTtl] = await Promise.all([lux.pttl("expires"), valkey.pttl("expires")]);
  assert.ok(luxTtl > 0 && valkeyTtl > 0 && Math.abs(luxTtl - valkeyTtl) < 1_000, `expiry TTLs diverged: Lux=${luxTtl}, Valkey=${valkeyTtl}`);
  assert.equal(await lux.persist("expires"), await valkey.persist("expires"));
  assert.equal(await lux.ttl("expires"), await valkey.ttl("expires"));
  console.log("differential: keys and expiry");
}

async function compareGeo() {
  await Promise.all([lux.flushdb(), valkey.flushdb()]);
  for (const redis of [lux, valkey]) {
    await redis.geoadd("places", -73.9857, 40.7484, "empire", -74.0445, 40.6892, "liberty");
  }
  const [luxDistance, valkeyDistance] = await Promise.all([
    lux.geodist("places", "empire", "liberty", "km"),
    valkey.geodist("places", "empire", "liberty", "km"),
  ]);
  assert.ok(Math.abs(Number(luxDistance) - Number(valkeyDistance)) < 0.01, `geo distance diverged: Lux=${luxDistance}, Valkey=${valkeyDistance}`);
  assert.deepStrictEqual(await lux.geohash("places", "empire", "liberty"), await valkey.geohash("places", "empire", "liberty"));
  console.log("differential: geo");
}

async function compareStreams() {
  await Promise.all([lux.flushdb(), valkey.flushdb()]);
  const commands: Command[] = [
    ["XADD", "events", "1-0", "type", "created"],
    ["XADD", "events", "2-0", "type", "updated"],
    ["XLEN", "events"],
    ["XRANGE", "events", "-", "+"],
    ["XREVRANGE", "events", "+", "-", "COUNT", "1"],
    ["XGROUP", "CREATE", "events", "workers", "0"],
    ["XREADGROUP", "GROUP", "workers", "worker-1", "COUNT", "1", "STREAMS", "events", ">"],
    ["XPENDING", "events", "workers"],
    ["XACK", "events", "workers", "1-0"],
    ["XDEL", "events", "2-0"],
  ];
  for (const command of commands) {
    assert.deepStrictEqual(normalize(await call(lux, command)), normalize(await call(valkey, command)), `streams: ${command[0]} diverged`);
  }
  console.log("differential: streams and consumer groups");
}

async function comparePubSub() {
  const luxSub = client(luxPort);
  const valkeySub = client(valkeyPort);
  const messages = (redis: Redis) => new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("pub/sub message timed out")), 3_000);
    redis.once("message", (channel, message) => {
      clearTimeout(timer);
      resolve(`${channel}:${message}`);
    });
  });
  await Promise.all([luxSub.connect(), valkeySub.connect()]);
  await Promise.all([luxSub.subscribe("compat:events"), valkeySub.subscribe("compat:events")]);
  const luxMessage = messages(luxSub);
  const valkeyMessage = messages(valkeySub);
  const published = await Promise.all([
    lux.publish("compat:events", "ready"),
    valkey.publish("compat:events", "ready"),
  ]);
  assert.deepStrictEqual(published, [1, 1]);
  assert.equal(await luxMessage, await valkeyMessage);
  await Promise.all([luxSub.unsubscribe(), valkeySub.unsubscribe()]);
  await Promise.all([luxSub.quit(), valkeySub.quit()]);
  console.log("differential: pub/sub");
}

async function compareTransactions() {
  await Promise.all([lux.flushdb(), valkey.flushdb()]);
  const luxResult = await lux.multi().set("tx:key", "1").incr("tx:key").get("tx:key").exec();
  const valkeyResult = await valkey.multi().set("tx:key", "1").incr("tx:key").get("tx:key").exec();
  assert.deepStrictEqual(normalize(luxResult), normalize(valkeyResult));
  console.log("differential: transactions");
}

async function proveIoredis() {
  await lux.flushdb();
  const pipeline = await lux.pipeline().set("pipe:a", "1").incr("pipe:a").get("pipe:a").exec();
  assert.deepStrictEqual(pipeline, [[null, "OK"], [null, 2], [null, "2"]]);

  const key = Buffer.from([0x6b, 0x00, 0xff]);
  const value = Buffer.from([0x00, 0x80, 0xff, 0x41]);
  await lux.set(key, value);
  assert.deepStrictEqual(await lux.getBuffer(key), value);

  const ended = new Promise<void>(resolve => lux.once("end", resolve));
  lux.disconnect();
  await ended;
  await lux.connect();
  assert.deepStrictEqual(await lux.getBuffer(key), value);

  await lux.rpush("blocking", "ready");
  assert.deepStrictEqual(await lux.blpop("blocking", 1), ["blocking", "ready"]);
  console.log("client: ioredis 6.0.0");
}

async function proveExplicitErrors() {
  await assert.rejects(() => call(lux, ["HELLO", "3"]), /NOPROTO|RESP3/i);
  await assert.rejects(() => call(lux, ["CLUSTER", "SLOTS"]), /unsupported|unknown/i);
  await assert.rejects(() => call(lux, ["MODULE", "LIST"]), /unsupported|unknown/i);
  console.log("contract: RESP3, cluster, and modules fail explicitly");
}

try {
  await Promise.all([lux.connect(), valkey.connect()]);
  await compare("strings and bit operations", [
    ["SET", "string", "hello"],
    ["APPEND", "string", " world"],
    ["GET", "string"],
    ["STRLEN", "string"],
    ["SETRANGE", "range", "3", "lux"],
    ["GETRANGE", "range", "0", "-1"],
    ["SET", "counter", "10"],
    ["INCR", "counter"],
    ["INCRBYFLOAT", "counter", "0.5"],
    ["SETBIT", "bits", "7", "1"],
    ["GETBIT", "bits", "7"],
    ["BITCOUNT", "bits"],
    ["BITPOS", "bits", "1"],
  ]);
  await compareExpiry();
  await compare("lists and blocking operations", [
    ["RPUSH", "list", "a", "b", "c"],
    ["LRANGE", "list", "0", "-1"],
    ["LINDEX", "list", "1"],
    ["LINSERT", "list", "BEFORE", "b", "x"],
    ["LSET", "list", "0", "z"],
    ["LMOVE", "list", "other", "RIGHT", "LEFT"],
    ["BLPOP", "other", "1"],
    ["LLEN", "list"],
  ]);
  await compare("hashes", [
    ["HSET", "hash", "name", "lux", "count", "1"],
    ["HGET", "hash", "name"],
    ["HMGET", "hash", "name", "missing"],
    ["HINCRBY", "hash", "count", "2"],
    ["HEXISTS", "hash", "name"],
    ["HSTRLEN", "hash", "name"],
    ["HLEN", "hash"],
    ["HDEL", "hash", "name"],
  ]);
  await compareSets();
  await compare("sorted sets", [
    ["ZADD", "scores", "1", "a", "2", "b", "3", "c"],
    ["ZRANGE", "scores", "0", "-1", "WITHSCORES"],
    ["ZINCRBY", "scores", "2", "a"],
    ["ZRANK", "scores", "b"],
    ["ZCOUNT", "scores", "-inf", "+inf"],
    ["ZPOPMIN", "scores", "1"],
    ["ZCARD", "scores"],
    ["ZADD", "blocking:scores", "1", "ready"],
    ["BZPOPMIN", "blocking:scores", "1"],
  ]);
  await compareGeo();
  await compareStreams();
  await compare("HyperLogLog", [
    ["PFADD", "hll:a", "a", "b", "c"],
    ["PFADD", "hll:b", "c", "d"],
    ["PFCOUNT", "hll:a"],
    ["PFMERGE", "hll:all", "hll:a", "hll:b"],
    ["PFCOUNT", "hll:all"],
  ]);
  await compare("Lua scripting", [
    ["EVAL", "return redis.call('SET', KEYS[1], ARGV[1])", "1", "lua:key", "value"],
    ["EVAL", "return redis.call('GET', KEYS[1])", "1", "lua:key"],
    ["SCRIPT", "EXISTS", "ffffffffffffffffffffffffffffffffffffffff"],
  ]);
  await compare("server basics", [
    ["PING"],
    ["ECHO", "hello"],
    ["SELECT", "0"],
    ["CLIENT", "SETNAME", "lux-compat"],
    ["CLIENT", "GETNAME"],
    ["DBSIZE"],
  ]);
  await comparePubSub();
  await compareTransactions();
  await proveIoredis();
  await proveExplicitErrors();
} finally {
  await Promise.allSettled([lux.quit(), valkey.quit()]);
}
