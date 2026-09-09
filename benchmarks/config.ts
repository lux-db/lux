export const HARNESS_VERSION = 2;

export const LUX_BUILD = {
	dockerfile: "Dockerfile",
	rust_toolchain: "1.98.0",
	cargo_profile: "release",
	cargo_command:
		"cargo build --locked --release --bin lux --bin lux-healthcheck --bin lux-maintenance",
} as const;

export const REDIS_IMAGE =
	"redis:8.2.1@sha256:5fa2edb1e408fa8235e6db8fab01d1afaaae96c9403ba67b70feceb8661e8621";
export const BENCHMARK_PASSWORD = "lux-benchmark-local-only";

export type BenchmarkSettings = {
	requests: number;
	warmupRequests: number;
	repetitions: number;
	clients: number;
	threads: number;
	keyspace: number;
	pipeline: number;
	cpus: number;
	memory: string;
};

export type BenchmarkScale = {
	tableRows: number;
	nativeRequests: number;
	vectorCount: number;
	vectorDimensions: number;
	vectorQueries: number;
	timeSeriesCount: number;
	samplesPerSeries: number;
	realtimeEvents: number;
	recoveryKeys: number[];
};

export const SETTINGS: Record<"quick" | "standard", BenchmarkSettings> = {
	quick: {
		requests: 20_000,
		warmupRequests: 2_000,
		repetitions: 1,
		clients: 8,
		threads: 1,
		keyspace: 1_000,
		pipeline: 8,
		cpus: 2,
		memory: "2g",
	},
	standard: {
		requests: 100_000,
		warmupRequests: 10_000,
		repetitions: 5,
		clients: 50,
		threads: 4,
		keyspace: 100_000,
		pipeline: 16,
		cpus: 4,
		memory: "4g",
	},
};

export const SCALES: Record<"quick" | "standard", BenchmarkScale> = {
	quick: {
		tableRows: 1_000,
		nativeRequests: 200,
		vectorCount: 500,
		vectorDimensions: 32,
		vectorQueries: 10,
		timeSeriesCount: 10,
		samplesPerSeries: 100,
		realtimeEvents: 100,
		recoveryKeys: [1_000],
	},
	standard: {
		tableRows: 50_000,
		nativeRequests: 1_000,
		vectorCount: 10_000,
		vectorDimensions: 128,
		vectorQueries: 50,
		timeSeriesCount: 100,
		samplesPerSeries: 1_000,
		realtimeEvents: 2_000,
		recoveryKeys: [10_000, 100_000],
	},
};

export function tieredMemoryLimit(quick: boolean): string {
	return quick ? "256kb" : "64mb";
}

export type Workload = {
	id: string;
	group: string;
	class: "compatibility" | "native";
	command: string[];
	description: string;
	dimensions?: Record<string, string | number>;
	pipeline?: number;
	clients?: number;
	threads?: number;
	keyspace?: number;
	requests?: number;
	warmupRequests?: number;
};

export function validateConfiguration(workloads: Workload[]): void {
	const ids = new Set<string>();
	for (const workload of workloads) {
		if (!/^[a-z][a-z0-9_]*$/.test(workload.id))
			throw new Error(`invalid workload id: ${workload.id}`);
		if (ids.has(workload.id))
			throw new Error(`duplicate workload id: ${workload.id}`);
		if (workload.command.length === 0)
			throw new Error(`${workload.id} has no command`);
		ids.add(workload.id);
	}
	if (!REDIS_IMAGE.includes("@sha256:"))
		throw new Error("Redis comparison image must be pinned by digest");
	for (const [name, settings] of Object.entries(SETTINGS)) {
		for (const [field, value] of Object.entries(settings)) {
			if (field === "memory") continue;
			if (!Number.isSafeInteger(value) || value <= 0)
				throw new Error(`${name}.${field} must be a positive integer`);
		}
	}
	for (const [name, scale] of Object.entries(SCALES)) {
		for (const [field, value] of Object.entries(scale)) {
			const values = Array.isArray(value) ? value : [value];
			if (
				values.some(
					(entry) => !Number.isSafeInteger(entry) || entry <= 0,
				)
			)
				throw new Error(
					`${name}.${field} must contain positive integers`,
				);
		}
	}
}
