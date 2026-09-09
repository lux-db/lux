import { BENCHMARK_PASSWORD, type BenchmarkScale, type BenchmarkSettings, type Workload } from "./config";
import { measureCatalog, redisCli, type Measurement } from "./measure";
import { loadCommands, RespConnection } from "./resp";
import { progress } from "./runtime";
import { sampleFromLatencies, summarize, type Sample } from "./stats";
import type { Subject } from "./subjects";

export type VectorEvidence = {
  vectors: number;
  dimensions: number;
  queries: number;
  k: number;
  recall_at_k: number;
  filtered_recall_at_k: number;
};

function seededVector(index: number, dimensions: number): number[] {
  let state = (index + 1) * 0x9e3779b1;
  const vector: number[] = [];
  let norm = 0;
  for (let dimension = 0; dimension < dimensions; dimension++) {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    const value = ((state >>> 0) / 0xffff_ffff) * 2 - 1;
    vector.push(value);
    norm += value * value;
  }
  const length = Math.sqrt(norm);
  return vector.map((value) => value / length);
}

function vectorCommands(vectors: number[][]): Iterable<string[]> {
  return (function* () {
    for (let index = 0; index < vectors.length; index++) {
      yield [
        "VSET", `benchmark:vector:${index}`, String(vectors[index].length),
        ...vectors[index].map((value) => value.toFixed(7)),
        "META", JSON.stringify({ cohort: index % 2 === 0 ? "even" : "odd" }),
      ];
    }
  })();
}

function cosine(left: number[], right: number[]): number {
  let score = 0;
  for (let index = 0; index < left.length; index++) score += left[index] * right[index];
  return score;
}

function resultKeys(value: unknown): string[] {
  if (!Array.isArray(value)) throw new Error(`vector search returned ${JSON.stringify(value)}`);
  return value.map((entry) => {
    if (!Array.isArray(entry) || typeof entry[0] !== "string")
      throw new Error(`vector search returned malformed entry ${JSON.stringify(entry)}`);
    return entry[0];
  });
}

async function concurrentRespSample(
  port: number,
  requests: number,
  concurrency: number,
  command: (index: number) => string[],
  verify: (value: unknown, index: number) => void,
): Promise<Sample> {
  const connections = await Promise.all(
    Array.from({ length: concurrency }, () => RespConnection.connect(port, BENCHMARK_PASSWORD)),
  );
  let next = 0;
  const latencies: number[] = [];
  const started = performance.now();
  try {
    await Promise.all(connections.map(async (connection) => {
      while (true) {
        const index = next++;
        if (index >= requests) return;
        const requestStarted = performance.now();
        const value = await connection.request(command(index));
        latencies.push(performance.now() - requestStarted);
        verify(value, index);
      }
    }));
  } finally {
    for (const connection of connections) connection.close();
  }
  return sampleFromLatencies(latencies, performance.now() - started);
}

export async function measureVectors(
  subject: Subject,
  network: string,
  clientImage: string,
  settings: BenchmarkSettings,
  scale: BenchmarkScale,
): Promise<{ measurements: Measurement[]; evidence: VectorEvidence }> {
  progress(`Preparing ${scale.vectorCount} ${scale.vectorDimensions}-dimensional vectors...`);
  await redisCli(subject, network, clientImage, "FLUSHALL");
  const vectors = Array.from(
    { length: scale.vectorCount },
    (_, index) => seededVector(index, scale.vectorDimensions),
  );
  await loadCommands(subject.resp_port, BENCHMARK_PASSWORD, vectorCommands(vectors), 128);

  const queryIndexes = Array.from(
    { length: scale.vectorQueries },
    (_, index) => Math.floor((index * scale.vectorCount) / scale.vectorQueries),
  );
  const k = Math.min(10, scale.vectorCount);
  let matches = 0;
  let filteredMatches = 0;
  let possible = 0;
  const verifier = await RespConnection.connect(subject.resp_port, BENCHMARK_PASSWORD);
  try {
    for (const queryIndex of queryIndexes) {
      const query = vectors[queryIndex];
      const actual = resultKeys(await verifier.request([
        "VSEARCH", String(scale.vectorDimensions), ...query.map((value) => value.toFixed(7)),
        "K", String(k),
      ]));
      const expected = vectors
        .map((vector, index) => ({ key: `benchmark:vector:${index}`, score: cosine(query, vector) }))
        .sort((left, right) => right.score - left.score)
        .slice(0, k)
        .map((entry) => entry.key);
      const expectedSet = new Set(expected);
      matches += actual.filter((key) => expectedSet.has(key)).length;
      possible += k;
      if (!actual.includes(`benchmark:vector:${queryIndex}`))
        throw new Error(`vector search did not return its exact source vector ${queryIndex}`);
      const cohort = queryIndex % 2 === 0 ? "even" : "odd";
      const filtered = resultKeys(await verifier.request([
        "VSEARCH", String(scale.vectorDimensions), ...query.map((value) => value.toFixed(7)),
        "K", String(k), "FILTER", "cohort", cohort,
      ]));
      const filteredExpected = vectors
        .map((vector, index) => ({ key: `benchmark:vector:${index}`, index, score: cosine(query, vector) }))
        .filter((entry) => (entry.index % 2 === 0 ? "even" : "odd") === cohort)
        .sort((left, right) => right.score - left.score)
        .slice(0, k)
        .map((entry) => entry.key);
      const filteredExpectedSet = new Set(filteredExpected);
      filteredMatches += filtered.filter((key) => filteredExpectedSet.has(key)).length;
      if (filtered.some((key) => Number(key.split(":").at(-1)) % 2 !== queryIndex % 2))
        throw new Error(`filtered vector search returned the wrong cohort for ${queryIndex}`);
    }
  } finally {
    verifier.close();
  }
  const evidence: VectorEvidence = {
    vectors: scale.vectorCount,
    dimensions: scale.vectorDimensions,
    queries: scale.vectorQueries,
    k,
    recall_at_k: matches / possible,
    filtered_recall_at_k: filteredMatches / possible,
  };

  const requests = scale.nativeRequests;
  const concurrency = Math.min(settings.clients, 32);
  const samples: Sample[] = [];
  const filteredSamples: Sample[] = [];
  await concurrentRespSample(
    subject.resp_port,
    Math.min(requests, 100),
    concurrency,
    (index) => {
      const query = vectors[queryIndexes[index % queryIndexes.length]];
      return ["VSEARCH", String(query.length), ...query.map((value) => value.toFixed(7)), "K", String(k)];
    },
    (value) => {
      if (resultKeys(value).length !== k) throw new Error("vector search returned the wrong result count");
    },
  );
  for (let repetition = 0; repetition < settings.repetitions; repetition++) {
    const sample = await concurrentRespSample(
      subject.resp_port,
      requests,
      concurrency,
      (index) => {
        const query = vectors[queryIndexes[(index + repetition) % queryIndexes.length]];
        return ["VSEARCH", String(query.length), ...query.map((value) => value.toFixed(7)), "K", String(k)];
      },
      (value) => {
        if (resultKeys(value).length !== k) throw new Error("vector search returned the wrong result count");
      },
    );
    samples.push(sample);
    progress(`  vector search run ${repetition + 1}: ${sample.rps.toFixed(0)} ops/s, p99 ${sample.p99_latency_ms.toFixed(3)} ms`);
    const filtered = await concurrentRespSample(
      subject.resp_port,
      requests,
      concurrency,
      (index) => {
        const queryIndex = queryIndexes[(index + repetition) % queryIndexes.length];
        const query = vectors[queryIndex];
        return [
          "VSEARCH", String(query.length), ...query.map((value) => value.toFixed(7)),
          "K", String(k), "FILTER", "cohort", queryIndex % 2 === 0 ? "even" : "odd",
        ];
      },
      (value, index) => {
        const queryIndex = queryIndexes[(index + repetition) % queryIndexes.length];
        const expectedParity = queryIndex % 2;
        const keys = resultKeys(value);
        if (keys.length !== k || keys.some((key) => Number(key.split(":").at(-1)) % 2 !== expectedParity))
          throw new Error("filtered vector search returned an invalid result set");
      },
    );
    filteredSamples.push(filtered);
    progress(`  filtered vector search run ${repetition + 1}: ${filtered.rps.toFixed(0)} ops/s, p99 ${filtered.p99_latency_ms.toFixed(3)} ms`);
  }

  const writeVector = seededVector(scale.vectorCount + 1, scale.vectorDimensions)
    .map((value) => value.toFixed(7));
  const writeWorkload: Workload = {
    id: "vector_upsert",
    group: "Vector search",
    class: "native",
    description: "Vector upsert into a populated HNSW index",
    command: [
      "VSET", "benchmark:vector:write:__rand_int__", String(scale.vectorDimensions), ...writeVector,
    ],
    keyspace: scale.vectorCount,
    requests,
    warmupRequests: Math.min(requests, 100),
    dimensions: {
      operation: "upsert",
      vectors: scale.vectorCount,
      dimensions: scale.vectorDimensions,
    },
  };
  const measurements = await measureCatalog(
    [subject], [writeWorkload], network, clientImage, settings,
  );
  measurements.push({
    workload: "vector_search",
    group: "Vector search",
    class: "native",
    subject: "lux",
    description: "Top-k search across varied queries with result validation",
    dimensions: {
      operation: "search",
      requests,
      warmup_requests: Math.min(requests, 100),
      repetitions: settings.repetitions,
      vectors: scale.vectorCount,
      dimensions: scale.vectorDimensions,
      k,
      clients: concurrency,
    },
    samples,
    summary: summarize(samples),
  });
  measurements.push({
    workload: "vector_filtered_search",
    group: "Vector search",
    class: "native",
    subject: "lux",
    description: "Metadata-filtered top-k search with result validation",
    dimensions: {
      operation: "filtered_search",
      requests,
      warmup_requests: 0,
      repetitions: settings.repetitions,
      vectors: scale.vectorCount,
      dimensions: scale.vectorDimensions,
      k,
      selectivity_percent: 50,
      clients: concurrency,
    },
    samples: filteredSamples,
    summary: summarize(filteredSamples),
  });
  return { measurements, evidence };
}

function timeSeriesCommands(scale: BenchmarkScale): Iterable<string[]> {
  return (function* () {
    for (let series = 0; series < scale.timeSeriesCount; series++) {
      const key = `benchmark:ts:${String(series).padStart(12, "0")}`;
      for (let sample = 0; sample < scale.samplesPerSeries; sample++) {
        const command = ["TSADD", key, String(sample), String(series + sample / 10)];
        if (sample === 0)
          command.push("LABELS", "cohort", series % 2 === 0 ? "even" : "odd");
        yield command;
      }
    }
  })();
}

export async function measureTimeSeries(
  subject: Subject,
  network: string,
  clientImage: string,
  settings: BenchmarkSettings,
  scale: BenchmarkScale,
): Promise<Measurement[]> {
  const total = scale.timeSeriesCount * scale.samplesPerSeries;
  progress(`Preparing ${total} samples across ${scale.timeSeriesCount} time series...`);
  await redisCli(subject, network, clientImage, "FLUSHALL");
  await loadCommands(subject.resp_port, BENCHMARK_PASSWORD, timeSeriesCommands(scale));
  const key = "benchmark:ts:__rand_int__";
  const recentStart = Math.max(0, scale.samplesPerSeries - 100);
  const requests = scale.nativeRequests;
  const base = {
    group: "Time series",
    class: "native" as const,
    keyspace: scale.timeSeriesCount,
    requests,
    warmupRequests: Math.min(requests, 100),
  };
  const workloads: Workload[] = [
    {
      ...base,
      id: "timeseries_append",
      description: "Append into a populated time-series set",
      command: ["TSADD", "benchmark:ts:write:__rand_int__", "*", "42.5"],
      dimensions: { operation: "append", series: scale.timeSeriesCount, samples: total },
    },
    {
      ...base,
      id: "timeseries_recent_range",
      description: "Read the latest 100 samples from one series",
      command: ["TSRANGE", key, String(recentStart), String(scale.samplesPerSeries - 1)],
      dimensions: { operation: "recent_range", series: scale.timeSeriesCount, result_samples: 100 },
    },
    {
      ...base,
      id: "timeseries_full_range",
      description: "Read a complete populated series",
      command: ["TSRANGE", key, "0", String(scale.samplesPerSeries - 1)],
      requests: Math.min(requests, 1_000),
      dimensions: {
        operation: "full_range",
        series: scale.timeSeriesCount,
        result_samples: scale.samplesPerSeries,
      },
    },
    {
      ...base,
      id: "timeseries_aggregate",
      description: "Aggregate a complete series into ten buckets",
      command: [
        "TSRANGE", key, "0", String(scale.samplesPerSeries - 1), "AGGREGATION", "avg",
        String(Math.max(1, Math.floor(scale.samplesPerSeries / 10))),
      ],
      dimensions: { operation: "aggregate", series: scale.timeSeriesCount, result_samples: 10 },
    },
  ];
  const measurements = await measureCatalog([subject], workloads, network, clientImage, settings);
  const verify = await RespConnection.connect(subject.resp_port, BENCHMARK_PASSWORD);
  try {
    const range = await verify.request([
      "TSRANGE", `benchmark:ts:${String(0).padStart(12, "0")}`, "0",
      String(scale.samplesPerSeries - 1),
    ]);
    if (!Array.isArray(range) || range.length !== scale.samplesPerSeries)
      throw new Error(`time-series verification returned ${Array.isArray(range) ? range.length : "non-array"} samples`);
  } finally {
    verify.close();
  }
  return measurements;
}
