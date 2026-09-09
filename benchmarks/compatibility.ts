import { BENCHMARK_PASSWORD, type BenchmarkSettings, type Workload } from "./config";
import { measureCatalog, redisCli, type Measurement } from "./measure";
import { loadCommands, RespConnection } from "./resp";
import { progress } from "./runtime";
import { sampleFromLatencies, summarize, type Sample } from "./stats";
import type { Subject } from "./subjects";

function benchmarkKey(prefix: string, index: number): string {
  return `${prefix}:${String(index).padStart(12, "0")}`;
}

function stringCommands(prefix: string, payload: string, count: number): Iterable<string[]> {
  return (function* () {
    for (let index = 0; index < count; index++)
      yield ["SET", benchmarkKey(prefix, index), payload];
  })();
}

function geoCommands(count: number): Iterable<string[]> {
  return (function* () {
    for (let index = 0; index < count; index++) {
      const longitude = -180 + index * (360 / count);
      const latitude = Math.min(85, -80 + index * (165 / count));
      yield [
        "GEOADD", "benchmark:geo", longitude.toFixed(6), latitude.toFixed(6),
        `place:${index}`,
      ];
    }
  })();
}

function collectionCommands(count: number): Iterable<string[]> {
  return (function* () {
    for (let index = 0; index < count; index++) {
      const suffix = String(index).padStart(12, "0");
      yield ["HSET", `benchmark:hash:${suffix}`, "field", `value-${index}`];
      yield ["LPUSH", `benchmark:list:${suffix}`, ...Array.from({ length: 10 }, (_, item) => `item-${item}`)];
      yield ["SADD", `benchmark:set:${suffix}`, ...Array.from({ length: 10 }, (_, item) => `member-${item}`)];
      yield ["ZADD", `benchmark:zset:${suffix}`, ...Array.from({ length: 10 }, (_, item) => [String(item), `member-${item}`]).flat()];
    }
  })();
}

function commandWorkload(
  group: string,
  id: string,
  operation: string,
  command: string[],
  dimensions: Record<string, string | number>,
  overrides: Partial<Workload> = {},
): Workload {
  return {
    id,
    group,
    class: "compatibility",
    description: operation,
    command,
    dimensions: { operation, ...dimensions },
    ...overrides,
  };
}

export function compatibilityWorkloads(
  quick: boolean,
  settings: BenchmarkSettings,
): Workload[] {
  const workloads: Workload[] = [];
  const basePayload = "x".repeat(128);
  const basePrefix = "benchmark:string:128";
  const pipelines = [...new Set(
    quick ? [1, settings.pipeline] : [1, settings.pipeline, 64, 128, 256, 512],
  )].sort((left, right) => left - right);
  for (const pipeline of pipelines) {
    for (const operation of ["SET", "GET"] as const) {
      workloads.push(commandWorkload(
        "Pipeline scaling",
        `pipeline_${operation.toLowerCase()}_${pipeline}`,
        operation,
        operation === "SET"
          ? ["SET", `${basePrefix}:__rand_int__`, basePayload]
          : ["GET", `${basePrefix}:__rand_int__`],
        { pipeline, payload_bytes: 128 },
        { pipeline },
      ));
    }
  }

  const clients = quick ? [1, 8] : [1, 10, 50, 200];
  for (const clientCount of clients) {
    for (const operation of ["SET", "GET"] as const) {
      workloads.push(commandWorkload(
        "Connection scaling",
        `clients_${operation.toLowerCase()}_${clientCount}`,
        operation,
        operation === "SET"
          ? ["SET", `${basePrefix}:__rand_int__`, basePayload]
          : ["GET", `${basePrefix}:__rand_int__`],
        { clients: clientCount, payload_bytes: 128 },
        {
          pipeline: 1,
          clients: clientCount,
          threads: Math.min(clientCount, settings.threads),
        },
      ));
    }
  }

  const payloads = quick ? [128] : [64, 1_024, 16_384];
  for (const payloadBytes of payloads) {
    const prefix = `benchmark:string:${payloadBytes}`;
    const keyspace = payloadBytes >= 16_384
      ? Math.min(settings.keyspace, 10_000)
      : settings.keyspace;
    for (const operation of ["SET", "GET"] as const) {
      workloads.push(commandWorkload(
        "Payload scaling",
        `payload_${operation.toLowerCase()}_${payloadBytes}`,
        operation,
        operation === "SET"
          ? ["SET", `${prefix}:__rand_int__`, "x".repeat(payloadBytes)]
          : ["GET", `${prefix}:__rand_int__`],
        { payload_bytes: payloadBytes },
        { pipeline: 1, keyspace },
      ));
    }
  }

  for (const width of quick ? [8] : [8, 32]) {
    workloads.push(commandWorkload(
      "Multi-key reads",
      `mget_${width}`,
      "MGET",
      ["MGET", ...Array.from({ length: width }, () => `${basePrefix}:__rand_int__`)],
      { keys: width, payload_bytes: 128 },
      { pipeline: 1 },
    ));
  }

  const collectionKeys = Math.min(settings.keyspace, quick ? 1_000 : 10_000);
  const collectionCases: Array<[string, string, string[]]> = [
    ["hash_write", "HSET", ["HSET", "benchmark:hash:__rand_int__", "field", "updated"]],
    ["hash_read", "HGET", ["HGET", "benchmark:hash:__rand_int__", "field"]],
    ["list_write", "LPUSH", ["LPUSH", "benchmark:list:__rand_int__", "new-item"]],
    ["list_range", "LRANGE", ["LRANGE", "benchmark:list:__rand_int__", "0", "9"]],
    ["set_write", "SADD", ["SADD", "benchmark:set:__rand_int__", "new-member"]],
    ["set_membership", "SISMEMBER", ["SISMEMBER", "benchmark:set:__rand_int__", "member-5"]],
    ["sorted_set_write", "ZADD", ["ZADD", "benchmark:zset:__rand_int__", "11", "new-member"]],
    ["sorted_set_range", "ZRANGE", ["ZRANGE", "benchmark:zset:__rand_int__", "0", "9"]],
  ];
  for (const [id, operation, command] of collectionCases) {
    workloads.push(commandWorkload(
      "Data structures",
      id,
      operation,
      command,
      { keys: collectionKeys, pipeline: 1 },
      { keyspace: collectionKeys, pipeline: 1 },
    ));
  }

  const geoPipelines = [...new Set(
    quick ? [1, settings.pipeline] : [1, settings.pipeline, 64, 128, 256, 512],
  )].sort((left, right) => left - right);
  const geo = [
    ["GEOPOS", ["GEOPOS", "benchmark:geo", "place:500"]],
    ["GEODIST", ["GEODIST", "benchmark:geo", "place:100", "place:500", "km"]],
    ["GEOSEARCH 500km", [
      "GEOSEARCH", "benchmark:geo", "FROMLONLAT", "0", "0", "BYRADIUS", "500", "km",
      "ASC", "COUNT", "10",
    ]],
    ["GEOSEARCH 5000km", [
      "GEOSEARCH", "benchmark:geo", "FROMLONLAT", "0", "0", "BYRADIUS", "5000", "km",
      "ASC", "COUNT", "100",
    ]],
  ] as const;
  for (const pipeline of geoPipelines) {
    for (const [operation, command] of geo) {
      const slug = operation.toLowerCase().replaceAll(" ", "_");
      workloads.push(commandWorkload(
        "Geospatial scaling",
        `geo_${slug}_${pipeline}`,
        operation,
        [...command],
        { pipeline, members: 1_000 },
        { pipeline, requests: quick ? 10_000 : settings.requests },
      ));
    }
  }
  return workloads;
}

async function mixedSample(
  subject: Subject,
  requests: number,
  concurrency: number,
  keyspace: number,
  readPercent: number,
): Promise<Sample> {
  const connections = await Promise.all(
    Array.from({ length: concurrency }, () => RespConnection.connect(subject.resp_port, BENCHMARK_PASSWORD)),
  );
  let next = 0;
  const latencies: number[] = [];
  const started = performance.now();
  try {
    await Promise.all(connections.map(async (connection) => {
      while (true) {
        const index = next++;
        if (index >= requests) return;
        const key = benchmarkKey("benchmark:string:128", (index * 7_919) % keyspace);
        const read = index % 100 < readPercent;
        const requestStarted = performance.now();
        const value = await connection.request(read
          ? ["GET", key]
          : ["SET", key, `write-${index}`.padEnd(128, "x")]);
        latencies.push(performance.now() - requestStarted);
        if (read && typeof value !== "string")
          throw new Error(`${subject.kind} mixed read returned ${JSON.stringify(value)}`);
        if (!read && value !== "OK")
          throw new Error(`${subject.kind} mixed write returned ${JSON.stringify(value)}`);
      }
    }));
  } finally {
    for (const connection of connections) connection.close();
  }
  return sampleFromLatencies(latencies, performance.now() - started);
}

async function measureMixes(
  subjects: Subject[],
  settings: BenchmarkSettings,
): Promise<Measurement[]> {
  const measurements: Measurement[] = [];
  for (const readPercent of [90, 50]) {
    const samples = new Map<Subject, Sample[]>(subjects.map((subject) => [subject, []]));
    for (const subject of subjects)
      await mixedSample(subject, settings.warmupRequests, settings.clients, settings.keyspace, readPercent);
    for (let repetition = 0; repetition < settings.repetitions; repetition++) {
      const order = repetition % 2 === 0 ? subjects : [...subjects].reverse();
      for (const subject of order) {
        const sample = await mixedSample(
          subject,
          settings.requests,
          settings.clients,
          settings.keyspace,
          readPercent,
        );
        samples.get(subject)!.push(sample);
        progress(`  ${subject.kind} ${readPercent}/${100 - readPercent} run ${repetition + 1}: ${sample.rps.toFixed(0)} ops/s, p99 ${sample.p99_latency_ms.toFixed(3)} ms`);
      }
    }
    for (const subject of subjects) {
      const values = samples.get(subject)!;
      measurements.push({
        workload: `mixed_${readPercent}_${100 - readPercent}`,
        group: "Read/write mixes",
        class: "compatibility",
        subject: subject.kind,
        description: `${readPercent}% reads and ${100 - readPercent}% writes`,
        dimensions: {
          operation: `${readPercent}/${100 - readPercent} GET/SET`,
          requests: settings.requests,
          warmup_requests: settings.warmupRequests,
          clients: settings.clients,
          repetitions: settings.repetitions,
          pipeline: 1,
          payload_bytes: 128,
          keyspace: settings.keyspace,
        },
        samples: values,
        summary: summarize(values),
      });
    }
  }
  return measurements;
}

export async function measureCompatibility(
  subjects: Subject[],
  network: string,
  clientImage: string,
  quick: boolean,
  settings: BenchmarkSettings,
): Promise<Measurement[]> {
  progress("Preparing exact compatibility datasets...");
  const payloads = quick ? [128] : [64, 128, 1_024, 16_384];
  for (const subject of subjects) {
    await redisCli(subject, network, clientImage, "FLUSHALL");
    for (const payloadBytes of payloads) {
      const count = payloadBytes >= 16_384
        ? Math.min(settings.keyspace, 10_000)
        : settings.keyspace;
      await loadCommands(
        subject.resp_port,
        BENCHMARK_PASSWORD,
        stringCommands(`benchmark:string:${payloadBytes}`, "x".repeat(payloadBytes), count),
      );
    }
    await loadCommands(subject.resp_port, BENCHMARK_PASSWORD, geoCommands(1_000));
    await loadCommands(
      subject.resp_port,
      BENCHMARK_PASSWORD,
      collectionCommands(Math.min(settings.keyspace, quick ? 1_000 : 10_000)),
    );
  }
  const measurements = await measureCatalog(
    subjects,
    compatibilityWorkloads(quick, settings),
    network,
    clientImage,
    settings,
  );
  measurements.push(...await measureMixes(subjects, settings));
  for (const subject of subjects) {
    const connection = await RespConnection.connect(subject.resp_port, BENCHMARK_PASSWORD);
    try {
      const value = await connection.request(["GET", benchmarkKey("benchmark:string:128", 0)]);
      if (value !== "x".repeat(128)) throw new Error(`${subject.kind} string dataset changed unexpectedly`);
      const position = await connection.request(["GEOPOS", "benchmark:geo", "place:500"]);
      if (!Array.isArray(position) || position.length !== 1)
        throw new Error(`${subject.kind} geospatial dataset is incomplete`);
    } finally {
      connection.close();
    }
  }
  return measurements;
}
