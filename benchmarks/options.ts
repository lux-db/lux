import { REDIS_IMAGE, SETTINGS, type BenchmarkSettings } from "./config";

export const FEATURES = [
  "compatibility",
  "tables",
  "vectors",
  "timeseries",
  "realtime",
  "tiered",
  "recovery",
] as const;

export type Feature = (typeof FEATURES)[number];

export type Options = {
  validate: boolean;
  quick: boolean;
  json: boolean;
  features: Set<Feature>;
  image?: string;
  redisImage: string;
  settings: BenchmarkSettings;
};

const HELP = `Usage:
  bun benchmarks/run.ts
  bun benchmarks/run.ts --feature tables
  bun benchmarks/run.ts --quick
  bun benchmarks/run.ts --image IMAGE
  bun benchmarks/run.ts --json > results.json

Options:
  -f, --feature NAME      Run one or more comma-separated features
  -q, --quick             Use a short local run instead of the full defaults
  -i, --image IMAGE       Use an existing Lux image instead of building this checkout
      --redis-image IMAGE Override the pinned Redis comparison image
      --requests N        Override measured requests per repetition
      --warmup N          Override warmup requests
      --repetitions N     Override repetitions
      --clients N         Override concurrent clients
      --threads N         Override client threads
      --keyspace N        Override randomized keyspace
      --pipeline N        Override pipeline depth
      --cpus N            Override the CPU limit per container
      --memory SIZE       Override the memory limit per container
      --json              Print complete machine-readable results
  -h, --help              Show this help`;

export function help(): string {
  return HELP;
}

function positiveInteger(flag: string, value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0)
    throw new Error(`${flag} must be a positive integer`);
  return parsed;
}

export function parseOptions(args: string[]): Options {
  let quick = false;
  let selected: Feature[] | undefined;
  let image: string | undefined;
  let redisImage = REDIS_IMAGE;
  let json = false;
  let validate = false;
  const overrides: Partial<BenchmarkSettings> = {};

  const valueAfter = (index: number, flag: string): string => {
    const value = args[index + 1];
    if (!value || value.startsWith("-")) throw new Error(`${flag} requires a value`);
    return value;
  };

  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (flag === "-h" || flag === "--help") throw new Error("help");
    if (flag === "--validate") validate = true;
    else if (flag === "-q" || flag === "--quick") quick = true;
    else if (flag === "--json") json = true;
    else if (flag === "-f" || flag === "--feature") {
      const names = valueAfter(index, flag).split(",");
      index++;
      if (names.includes("all")) {
        if (names.length !== 1) throw new Error("all cannot be combined with another feature");
        selected = [...FEATURES];
      } else {
        for (const name of names) {
          if (!(FEATURES as readonly string[]).includes(name))
            throw new Error(`unknown feature: ${name}`);
        }
        selected = [...new Set(names as Feature[])];
      }
    } else if (flag === "-i" || flag === "--image") {
      image = valueAfter(index, flag);
      index++;
    } else if (flag === "--redis-image") {
      redisImage = valueAfter(index, flag);
      index++;
    } else if (flag === "--memory") {
      overrides.memory = valueAfter(index, flag);
      index++;
    } else {
      const fields: Record<string, keyof BenchmarkSettings> = {
        "--requests": "requests",
        "--warmup": "warmupRequests",
        "--repetitions": "repetitions",
        "--clients": "clients",
        "--threads": "threads",
        "--keyspace": "keyspace",
        "--pipeline": "pipeline",
        "--cpus": "cpus",
      };
      const field = fields[flag];
      if (!field) throw new Error(`unknown option: ${flag}`);
      overrides[field] = positiveInteger(flag, valueAfter(index, flag));
      index++;
    }
  }

  return {
    validate,
    quick,
    json,
    features: new Set(selected ?? FEATURES),
    image,
    redisImage,
    settings: { ...SETTINGS[quick ? "quick" : "standard"], ...overrides },
  };
}
