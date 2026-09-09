import { BENCHMARK_PASSWORD, tieredMemoryLimit, type BenchmarkSettings } from "./config";
import { command, docker, publishedPort, waitReady } from "./runtime";

export type Subject = {
  kind: "lux" | "redis";
  name: string;
  alias: string;
  image: string;
  startup_ms: number;
  resp_port: number;
  http_port?: number;
  configuration: Record<string, string>;
};

export async function startSubject(
  kind: Subject["kind"],
  image: string,
  clientImage: string,
  network: string,
  nonce: string,
  quick: boolean,
  settings: BenchmarkSettings,
  mode: "ephemeral" | "durable" | "tiered" = "ephemeral",
): Promise<Subject> {
  const name = `lux-benchmark-${nonce}-${kind}-${mode}`;
  const alias = `${kind}-${mode}`;
  const args = [
    "run", "-d", "--name", name, "--network", network,
    "--network-alias", alias, "--label", `dev.luxdb.benchmark=${nonce}`,
    "--cpus", String(settings.cpus), "--memory", settings.memory,
  ];
  const configuration: Record<string, string> = {};

  if (kind === "lux") {
    const environment: Record<string, string> = {
      LUX_PASSWORD: BENCHMARK_PASSWORD,
      LUX_BIND_HOST: "0.0.0.0",
      LUX_PORT: "6379",
      LUX_HTTP_PORT: "5890",
      LUX_AUTH_ENABLED: "0",
      LUX_SAVE_INTERVAL: "0",
      LUX_SHARDS: String(settings.cpus),
      LUX_RUNTIME_THREADS: String(settings.cpus),
      RAYON_NUM_THREADS: String(settings.cpus),
      LUX_STORAGE_MODE: mode === "tiered" ? "tiered" : "memory",
      LUX_DURABILITY: mode === "ephemeral" ? "ephemeral" : "every_second",
    };
    if (mode === "tiered") {
      environment.LUX_MAXMEMORY = tieredMemoryLimit(quick);
      environment.LUX_MAXMEMORY_POLICY = "allkeys-lru";
    }
    Object.assign(configuration, environment, { LUX_PASSWORD: "enabled" });
    for (const [key, value] of Object.entries(environment))
      args.push("-e", `${key}=${value}`);
    if (mode !== "ephemeral") args.push("-v", `${name}-data:/data`);
    args.push("-p", "127.0.0.1::6379", "-p", "127.0.0.1::5890", image);
  } else {
    Object.assign(configuration, {
      persistence: mode === "ephemeral" ? "none" : "aof/everysec",
      requirepass: "enabled",
    });
    if (mode !== "ephemeral") args.push("-v", `${name}-data:/data`);
    args.push(
      "-p", "127.0.0.1::6379", image, "redis-server", "--save", "",
      "--appendonly", mode === "ephemeral" ? "no" : "yes",
      ...(mode === "ephemeral" ? [] : ["--appendfsync", "everysec"]),
      "--requirepass", BENCHMARK_PASSWORD,
    );
  }

  const started = performance.now();
  await docker(...args);
  try {
    await waitReady(network, alias, clientImage);
    return {
      kind,
      name,
      alias,
      image,
      startup_ms: performance.now() - started,
      resp_port: await publishedPort(name),
      http_port: kind === "lux" ? await publishedPort(name, 5890) : undefined,
      configuration,
    };
  } catch (error) {
    await command(["docker", "rm", "-f", name], { allowFailure: true, quiet: true });
    if (mode !== "ephemeral")
      await command(["docker", "volume", "rm", `${name}-data`], {
        allowFailure: true,
        quiet: true,
      });
    throw error;
  }
}

export async function containerStats(subject: Subject): Promise<Record<string, unknown>> {
  return JSON.parse(await docker("stats", "--no-stream", "--format", "{{json .}}", subject.name));
}
