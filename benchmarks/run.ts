import { randomBytes } from "node:crypto";
import { arch, cpus, platform, release, totalmem } from "node:os";
import { resolve } from "node:path";
import {
  BENCHMARK_PASSWORD,
  HARNESS_VERSION,
  LUX_BUILD,
  SCALES,
  validateConfiguration,
} from "./config";
import { compatibilityWorkloads, measureCompatibility } from "./compatibility";
import { measureLifecycle, type LifecycleEvidence } from "./lifecycle";
import type { Measurement } from "./measure";
import { measureTables } from "./native";
import { measureTimeSeries, measureVectors, type VectorEvidence } from "./native_features";
import { help, parseOptions } from "./options";
import { measureRealtime } from "./realtime";
import { markdown } from "./report";
import { command, docker, imageInventory, progress } from "./runtime";
import { summarize, type Sample } from "./stats";
import { measureTiered, type TieredEvidence } from "./tiered";
import { containerStats, startSubject, type Subject } from "./subjects";

async function main(): Promise<void> {
  const root = resolve(import.meta.dir, "..");
  let options;
  try {
    options = parseOptions(Bun.argv.slice(2));
  } catch (error) {
    if (error instanceof Error && error.message === "help") {
      console.log(help());
      return;
    }
    console.error(error instanceof Error ? error.message : String(error));
    console.error(`\n${help()}`);
    process.exit(2);
  }
  validateConfiguration(compatibilityWorkloads(options.quick, options.settings));
  if (options.validate) {
    console.log(`Benchmark harness v${HARNESS_VERSION}: configuration valid`);
    return;
  }
  if (options.image && /(^|:)latest$/.test(options.image))
    throw new Error("--image must identify a fixed candidate, not :latest");
  if (!options.redisImage.includes("@sha256:"))
    console.error("Note: the Redis override is not digest-pinned; the resolved image ID will still be recorded.");

  const settings = options.settings;
  const scale = SCALES[options.quick ? "quick" : "standard"];
  const nonce = randomBytes(6).toString("hex");
  const network = `lux-benchmark-${nonce}`;
  const label = `dev.luxdb.benchmark=${nonce}`;
  const subjects: Subject[] = [];
  const volumes = new Set<string>();
  const measurements: Measurement[] = [];
  const resourceSamples: Array<{
    stage: string;
    description: string;
    subjects: Record<string, Record<string, unknown>>;
  }> = [];
  const tieredEvidence: TieredEvidence[] = [];
  const lifecycleEvidence: LifecycleEvidence[] = [];
  let vectorEvidence: VectorEvidence | undefined;
  let temporaryImage: string | undefined;
  const startedAt = new Date().toISOString();
  const [commit, dirty] = await Promise.all([
    command(["git", "-C", root, "rev-parse", "HEAD"], { quiet: true }),
    command(["git", "-C", root, "status", "--porcelain"], { quiet: true }),
  ]);
  let luxImage = options.image;

  const remember = (subject: Subject) => {
    subjects.push(subject);
    if (subject.configuration.LUX_DURABILITY && subject.configuration.LUX_DURABILITY !== "ephemeral")
      volumes.add(`${subject.name}-data`);
    if (subject.kind === "redis" && subject.configuration.persistence !== "none")
      volumes.add(`${subject.name}-data`);
    return subject;
  };
  const retire = async (...retired: Subject[]) => {
    for (const subject of retired)
      await command(["docker", "rm", "-f", subject.name], { allowFailure: true, quiet: true });
  };

  try {
    if (!luxImage) {
      temporaryImage = `lux-benchmark:local-${nonce}`;
      luxImage = temporaryImage;
      progress("Building the current Lux checkout...");
      await command([
        "docker", "build", "--file", resolve(root, LUX_BUILD.dockerfile),
        "--build-arg", `LUX_BUILD_SHA=${commit.stdout.trim()}`,
        "--build-arg", "LUX_VERSION=local-benchmark",
        "--label", `org.opencontainers.image.revision=${commit.stdout.trim()}`,
        "--label", "org.opencontainers.image.version=local-benchmark",
        "--tag", luxImage, root,
      ], { quiet: true, timeoutMs: 1_800_000 });
    } else {
      await command(["docker", "image", "inspect", luxImage], { quiet: true });
    }
    await command(["docker", "pull", options.redisImage], { quiet: true });
    await docker("network", "create", "--label", label, network);

    if (options.features.has("compatibility")) {
      const lux = remember(await startSubject(
        "lux", luxImage, options.redisImage, network, `${nonce}-compatibility`,
        options.quick, settings,
      ));
      const redis = remember(await startSubject(
        "redis", options.redisImage, options.redisImage, network, `${nonce}-compatibility`,
        options.quick, settings,
      ));
      measurements.push(...await measureCompatibility(
        [lux, redis], network, options.redisImage, options.quick, settings,
      ));
      resourceSamples.push({
        stage: "compatibility",
        description: "Resident memory after the disclosed compatibility datasets and measurements",
        subjects: { lux: await containerStats(lux), redis: await containerStats(redis) },
      });
      await retire(lux, redis);
    }

    if (options.features.has("tables")) {
      const lux = remember(await startSubject(
        "lux", luxImage, options.redisImage, network, `${nonce}-tables`,
        options.quick, settings,
      ));
      measurements.push(...await measureTables(lux, network, options.redisImage, settings, scale));
      resourceSamples.push({
        stage: "tables",
        description: `Resident memory after ${scale.tableRows} users, ${scale.tableRows} posts, and measured writes`,
        subjects: { lux: await containerStats(lux) },
      });
      await retire(lux);
    }

    if (options.features.has("vectors")) {
      const lux = remember(await startSubject(
        "lux", luxImage, options.redisImage, network, `${nonce}-vectors`,
        options.quick, settings,
      ));
      const result = await measureVectors(lux, network, options.redisImage, settings, scale);
      measurements.push(...result.measurements);
      vectorEvidence = result.evidence;
      resourceSamples.push({
        stage: "vectors",
        description: `Resident memory after ${scale.vectorCount} ${scale.vectorDimensions}-dimensional vectors and measured writes`,
        subjects: { lux: await containerStats(lux) },
      });
      await retire(lux);
    }

    if (options.features.has("timeseries")) {
      const lux = remember(await startSubject(
        "lux", luxImage, options.redisImage, network, `${nonce}-timeseries`,
        options.quick, settings,
      ));
      measurements.push(...await measureTimeSeries(
        lux, network, options.redisImage, settings, scale,
      ));
      resourceSamples.push({
        stage: "timeseries",
        description: `Resident memory after ${scale.timeSeriesCount * scale.samplesPerSeries} seeded samples and measured appends`,
        subjects: { lux: await containerStats(lux) },
      });
      await retire(lux);
    }

    if (options.features.has("realtime")) {
      const lux = remember(await startSubject(
        "lux", luxImage, options.redisImage, network, `${nonce}-realtime`,
        options.quick, settings,
      ));
      for (const fanout of options.quick ? [1, 10] : [1, 10, 100]) {
        const samples: Sample[] = [];
        for (let repetition = 0; repetition < settings.repetitions; repetition++)
          samples.push(await measureRealtime(
            lux.resp_port,
            BENCHMARK_PASSWORD,
            Math.min(settings.warmupRequests, 100),
            scale.realtimeEvents,
            fanout,
          ));
        measurements.push({
          workload: `realtime_fanout_${fanout}`,
          group: "Realtime fanout",
          class: "native",
          subject: "lux",
          description: "Acknowledged mutation through receipt by every subscriber",
          dimensions: {
            operation: "mutation_to_event",
            repetitions: settings.repetitions,
            subscribers: fanout,
            events: scale.realtimeEvents,
            verified_deliveries: fanout * scale.realtimeEvents,
          },
          samples,
          summary: summarize(samples),
        });
      }
      resourceSamples.push({
        stage: "realtime",
        description: "Resident memory after fanout measurements; every expected delivery was verified",
        subjects: { lux: await containerStats(lux) },
      });
      await retire(lux);
    }

    if (options.features.has("tiered")) {
      const tiered = remember(await startSubject(
        "lux", luxImage, options.redisImage, network, `${nonce}-tiered`,
        options.quick, settings, "tiered",
      ));
      const result = await measureTiered(
        tiered, network, options.redisImage, options.quick, settings,
      );
      measurements.push(...result.measurements);
      tieredEvidence.push(...result.evidence);
      resourceSamples.push({
        stage: "tiered",
        description: "Resident memory after verified hot, cold, and mixed reads",
        subjects: { lux: await containerStats(tiered) },
      });
      await retire(tiered);
    }

    if (options.features.has("recovery"))
      lifecycleEvidence.push(...await measureLifecycle(
        luxImage,
        options.redisImage,
        network,
        nonce,
        options.quick,
        settings,
        scale,
      ));

    const dockerVersion = await command(
      ["docker", "version", "--format", "{{.Server.Version}}"],
      { quiet: true },
    );
    const result = {
      schema_version: 2,
      harness_version: HARNESS_VERSION,
      mode: options.quick ? "quick" : "standard",
      features: [...options.features],
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      source: { commit: commit.stdout.trim(), dirty: Boolean(dirty.stdout.trim()) },
      build: temporaryImage
        ? {
            method: "local_dockerfile",
            recipe: LUX_BUILD,
            arguments: {
              LUX_BUILD_SHA: commit.stdout.trim(),
              LUX_VERSION: "local-benchmark",
            },
          }
        : { method: "existing_image" },
      system: {
        platform: platform(),
        release: release(),
        arch: arch(),
        bun: Bun.version,
        docker: dockerVersion.stdout.trim(),
        cpu: { model: cpus()[0]?.model ?? "unknown", logical: cpus().length },
        memory_bytes: totalmem(),
      },
      settings,
      scale,
      images: {
        lux: await imageInventory(luxImage),
        redis: await imageInventory(options.redisImage),
        client: await imageInventory(options.redisImage),
      },
      subjects: subjects.map(({ kind, alias, image, startup_ms, configuration }) => ({
        kind,
        alias,
        image,
        startup_ms,
        configuration,
      })),
      resource_samples: resourceSamples,
      measurements,
      vector_quality: vectorEvidence,
      tiered: tieredEvidence,
      lifecycle: lifecycleEvidence,
    };
    process.stdout.write(options.json ? `${JSON.stringify(result, null, 2)}\n` : markdown(result));
  } finally {
    for (const subject of subjects.reverse())
      await command(["docker", "rm", "-f", subject.name], { allowFailure: true, quiet: true });
    for (const volume of volumes)
      await command(["docker", "volume", "rm", volume], { allowFailure: true, quiet: true });
    await command(["docker", "network", "rm", network], { allowFailure: true, quiet: true });
    if (temporaryImage)
      await command(["docker", "image", "rm", temporaryImage], { allowFailure: true, quiet: true });
  }
}

await main();
