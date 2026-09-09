import type { LifecycleEvidence } from "./lifecycle";
import type { Measurement } from "./measure";
import type { VectorEvidence } from "./native_features";
import type { TieredEvidence } from "./tiered";

type ReportResult = {
	mode: string;
	features: string[];
	source: { commit?: string; dirty?: boolean };
	build: { method: string };
	settings: {
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
	scale: Record<string, number | number[]>;
	images: {
		lux: { requested?: string; id?: string };
		redis: { requested?: string; id?: string };
	};
	system: {
		platform: string;
		arch: string;
		bun: string;
		docker: string;
		cpu: { model: string; logical: number };
		memory_bytes: number;
	};
	measurements: Measurement[];
	vector_quality?: VectorEvidence;
	lifecycle: LifecycleEvidence[];
	tiered: TieredEvidence[];
	resource_samples: Array<{
		stage: string;
		description: string;
		subjects: Record<string, { MemUsage?: string }>;
	}>;
};

function dimensions(values: Record<string, string | number>): string {
	return Object.entries(values)
		.filter(([key, value]) => key !== "operation" && value !== "-")
		.map(([key, value]) => `${key.replaceAll("_", " ")}=${value}`)
		.join(", ");
}

function groups(measurements: Measurement[]): Map<string, Measurement[]> {
	const grouped = new Map<string, Measurement[]>();
	for (const measurement of measurements) {
		const entries = grouped.get(measurement.group) ?? [];
		entries.push(measurement);
		grouped.set(measurement.group, entries);
	}
	return grouped;
}

function compatibilityTable(lines: string[], entries: Measurement[]): void {
	lines.push(
		"",
		"| Operation | Configuration | Lux ops/s | Redis ops/s | Lux/Redis | Lux p99 ms | Redis p99 ms |",
		"|---|---|---:|---:|---:|---:|---:|",
	);
	const workloads = new Map<string, Measurement[]>();
	for (const entry of entries) {
		const values = workloads.get(entry.workload) ?? [];
		values.push(entry);
		workloads.set(entry.workload, values);
	}
	for (const pair of workloads.values()) {
		const lux = pair.find((entry) => entry.subject === "lux");
		const redis = pair.find((entry) => entry.subject === "redis");
		if (!lux || !redis)
			throw new Error(
				`comparison workload ${pair[0].workload} is incomplete`,
			);
		const ratio =
			redis.summary.rps === 0
				? "-"
				: `${(lux.summary.rps / redis.summary.rps).toFixed(2)}x`;
		lines.push(
			`| ${lux.dimensions.operation ?? lux.workload} | ${dimensions(lux.dimensions)} | ${lux.summary.rps.toFixed(0)} | ${redis.summary.rps.toFixed(0)} | ${ratio} | ${lux.summary.p99_latency_ms.toFixed(3)} | ${redis.summary.p99_latency_ms.toFixed(3)} |`,
		);
	}
}

function nativeTable(lines: string[], entries: Measurement[]): void {
	lines.push(
		"",
		"| Operation | Configuration | Median ops/s | p50 ms | p99 ms | Range ops/s | CV |",
		"|---|---|---:|---:|---:|---:|---:|",
	);
	for (const entry of entries) {
		const value = entry.summary;
		lines.push(
			`| ${entry.dimensions.operation ?? entry.workload} | ${dimensions(entry.dimensions)} | ${value.rps.toFixed(0)} | ${value.p50_latency_ms.toFixed(3)} | ${value.p99_latency_ms.toFixed(3)} | ${value.rps_min.toFixed(0)}–${value.rps_max.toFixed(0)} | ${(value.rps_cv * 100).toFixed(2)}% |`,
		);
	}
}

export function markdown(result: ReportResult): string {
	const lines = [
		"# Lux benchmark results",
		"",
		`Harness source: ${result.source.commit ?? "unknown"}${result.source.dirty ? " (dirty checkout)" : ""}`,
		`Candidate source: ${result.images.lux.requested ?? "unknown"} (${result.images.lux.id ?? "unknown"})`,
		`Candidate input: ${result.build.method === "local_dockerfile" ? "image built by this run" : "existing image"}`,
		`Mode: ${result.mode}`,
		`Features: ${result.features.join(", ")}`,
		`Redis image: ${result.images.redis.requested ?? "unknown"} (${result.images.redis.id ?? "unknown"})`,
		`Runtime: Bun ${result.system.bun}; Docker ${result.system.docker}`,
		`Platform: ${result.system.platform}/${result.system.arch}`,
		`CPU: ${result.system.cpu.model} (${result.system.cpu.logical} logical)`,
		`Memory: ${(result.system.memory_bytes / 1024 ** 3).toFixed(1)} GiB`,
		`Default load: ${result.settings.requests} requests × ${result.settings.repetitions} repetitions; ${result.settings.clients} clients; ${result.settings.threads} threads; ${result.settings.cpus} CPUs; ${result.settings.memory}`,
		"",
		"Compatibility comparisons use identical commands, datasets, clients, and container limits. Lux-native results are not presented as Redis comparisons.",
	];

	for (const [group, entries] of groups(result.measurements)) {
		lines.push("", `## ${group}`);
		if (entries[0].class === "compatibility")
			compatibilityTable(lines, entries);
		else nativeTable(lines, entries);
	}

	if (result.vector_quality) {
		const quality = result.vector_quality;
		lines.push(
			"",
			"## Vector quality",
			"",
			`Recall@${quality.k}: **${(quality.recall_at_k * 100).toFixed(2)}%** across ${quality.queries} deterministic queries over ${quality.vectors} ${quality.dimensions}-dimensional vectors.`,
			`Filtered recall@${quality.k}: **${(quality.filtered_recall_at_k * 100).toFixed(2)}%** at 50% metadata selectivity.`,
			"Every query also verified that its exact source vector appeared in the result set and every filtered result matched the requested cohort.",
		);
	}

	if (result.lifecycle.length) {
		lines.push(
			"",
			"## Lifecycle",
			"",
			"Each case uses a fresh durable volume. Snapshot timing overlaps verified read traffic. The process is stopped after acknowledged post-snapshot writes, then recovery validates the complete key count, distributed base values, and every post-snapshot value.",
			"",
			"| Subject | Storage | Keys | Payload | Empty start | Snapshot | Snapshot peak memory | Read p99 during snapshot | Recovery | Verified |",
			"|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
		);
		for (const entry of result.lifecycle) {
			lines.push(
				`| ${entry.subject} | ${entry.storage} | ${entry.dataset_keys} | ${entry.payload_bytes} B | ${entry.empty_startup_ms.toFixed(1)} ms | ${entry.snapshot_ms.toFixed(1)} ms | ${(entry.snapshot_peak_memory_bytes / 1024 ** 2).toFixed(1)} MiB | ${entry.snapshot_read_traffic.p99_latency_ms.toFixed(3)} ms | ${entry.recovery_ms.toFixed(1)} ms | ${entry.verified_keys} values (${entry.post_snapshot_keys} post-snapshot) |`,
			);
		}
	}

	if (result.tiered.length) {
		lines.push(
			"",
			"## Tiered placement",
			"",
			"The dataset contains explicitly hot and disk-backed values. Every mixed read validates the returned value.",
			"",
			"| Disk keys before | Disk keys after | Memory before | Memory after | Configured ceiling | Within ceiling |",
			"|---:|---:|---:|---:|---:|---:|",
		);
		for (const entry of result.tiered) {
			lines.push(
				`| ${entry.before_reads.disk_keys} | ${entry.after_reads.disk_keys} | ${entry.before_reads.used_memory_bytes} B | ${entry.after_reads.used_memory_bytes} B | ${entry.configured_memory_bytes} B | ${entry.within_configured_memory ? "yes" : "NO"} |`,
			);
		}
	}

	if (result.resource_samples.length) {
		lines.push(
			"",
			"## Resident memory",
			"",
			"These isolated end-of-scenario samples describe the disclosed dataset state. They are not peak-memory claims; lifecycle snapshot peaks are measured separately.",
			"",
			"| Scenario | Subject | Usage / limit | Dataset state |",
			"|---|---|---:|---|",
		);
		for (const sample of result.resource_samples) {
			for (const [subject, resource] of Object.entries(sample.subjects))
				lines.push(
					`| ${sample.stage} | ${subject} | ${resource.MemUsage ?? "unavailable"} | ${sample.description} |`,
				);
		}
	}
	lines.push(
		"",
		"Run with `--json` to emit raw repetitions and complete configuration.",
		"",
	);
	return lines.join("\n");
}
