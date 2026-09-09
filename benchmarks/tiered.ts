import {
	BENCHMARK_PASSWORD,
	tieredMemoryLimit,
	type BenchmarkSettings,
	type Workload,
} from "./config";
import {
	measureCatalog,
	parseInfo,
	redisCli,
	type Measurement,
} from "./measure";
import { loadCommands, RespConnection } from "./resp";
import { progress } from "./runtime";
import { sampleFromLatencies, summarize, type Sample } from "./stats";
import type { Subject } from "./subjects";

export type TieredEvidence = {
	before_reads: Record<string, string>;
	after_reads: Record<string, string>;
	configured_memory_bytes: number;
	within_configured_memory: boolean;
};

function padded(index: number): string {
	return String(index).padStart(12, "0");
}

function tieredCommands(
	prefix: string,
	count: number,
	payload: string,
): Iterable<string[]> {
	return (function* () {
		for (let index = 0; index < count; index++)
			yield ["SET", `${prefix}:${padded(index)}`, payload];
	})();
}

function limitBytes(limit: string): number {
	const match = limit.match(/^(\d+)(kb|mb)$/);
	if (!match) throw new Error(`unsupported tiered memory limit: ${limit}`);
	return Number(match[1]) * (match[2] === "mb" ? 1_048_576 : 1_024);
}

async function mixedSample(
	subject: Subject,
	requests: number,
	concurrency: number,
	coldCount: number,
	hotCount: number,
	coldOffset: number,
): Promise<Sample> {
	const connections = await Promise.all(
		Array.from({ length: concurrency }, () =>
			RespConnection.connect(subject.resp_port, BENCHMARK_PASSWORD),
		),
	);
	let next = 0;
	const latencies: number[] = [];
	const started = performance.now();
	try {
		await Promise.all(
			connections.map(async (connection) => {
				while (true) {
					const index = next++;
					if (index >= requests) return;
					const hot = index % 10 !== 0;
					const keyIndex = hot
						? index % hotCount
						: (coldOffset + Math.floor(index / 10)) % coldCount;
					const expected = hot ? "hot" : "cold";
					const requestStarted = performance.now();
					const value = await connection.request([
						"GET",
						`benchmark:tiered:${expected}:${padded(keyIndex)}`,
					]);
					latencies.push(performance.now() - requestStarted);
					if (
						typeof value !== "string" ||
						!value.startsWith(expected)
					)
						throw new Error(
							`tiered ${expected} read returned ${JSON.stringify(value)}`,
						);
				}
			}),
		);
	} finally {
		for (const connection of connections) connection.close();
	}
	return sampleFromLatencies(latencies, performance.now() - started);
}

async function uniqueColdSample(
	subject: Subject,
	requests: number,
	concurrency: number,
	offset: number,
): Promise<Sample> {
	const connections = await Promise.all(
		Array.from({ length: concurrency }, () =>
			RespConnection.connect(subject.resp_port, BENCHMARK_PASSWORD),
		),
	);
	let next = 0;
	const latencies: number[] = [];
	const started = performance.now();
	try {
		await Promise.all(
			connections.map(async (connection) => {
				while (true) {
					const request = next++;
					if (request >= requests) return;
					const index = offset + request;
					const requestStarted = performance.now();
					const value = await connection.request([
						"GET",
						`benchmark:tiered:cold:${padded(index)}`,
					]);
					latencies.push(performance.now() - requestStarted);
					if (typeof value !== "string" || !value.startsWith("cold"))
						throw new Error(
							`tiered cold read returned ${JSON.stringify(value)}`,
						);
				}
			}),
		);
	} finally {
		for (const connection of connections) connection.close();
	}
	return sampleFromLatencies(latencies, performance.now() - started);
}

export async function measureTiered(
	subject: Subject,
	network: string,
	clientImage: string,
	quick: boolean,
	settings: BenchmarkSettings,
): Promise<{ measurements: Measurement[]; evidence: TieredEvidence[] }> {
	const coldCount =
		settings.warmupRequests +
		settings.requests * settings.repetitions +
		Math.ceil(settings.requests * settings.repetitions * 0.1) +
		1_000;
	const hotCount = quick ? 500 : 2_000;
	progress(
		`Preparing ${coldCount} cold and ${hotCount} hot tiered values...`,
	);
	await loadCommands(
		subject.resp_port,
		BENCHMARK_PASSWORD,
		tieredCommands(
			"benchmark:tiered:cold",
			coldCount,
			"cold".padEnd(1_024, "x"),
		),
	);
	await loadCommands(
		subject.resp_port,
		BENCHMARK_PASSWORD,
		tieredCommands("benchmark:tiered:hot", hotCount, "hot"),
	);
	const before = parseInfo(
		await redisCli(subject, network, clientImage, "INFO", "storage"),
	);
	if (Number(before.disk_keys) <= 0 || Number(before.used_disk_bytes) <= 0)
		throw new Error("tiered fixture did not place values on disk");

	const workloads: Workload[] = [
		{
			id: "tiered_hot_get",
			group: "Tiered storage",
			class: "native",
			description: "Read the intentionally hot working set",
			command: ["GET", "benchmark:tiered:hot:__rand_int__"],
			keyspace: hotCount,
			requests: settings.requests,
			dimensions: {
				operation: "hot_read",
				hot_percent: 100,
				keys: hotCount,
			},
		},
	];
	const measurements = await measureCatalog(
		[subject],
		workloads,
		network,
		clientImage,
		settings,
	);
	const concurrency = Math.min(settings.clients, 32);
	await uniqueColdSample(subject, settings.warmupRequests, concurrency, 0);
	const cold: Sample[] = [];
	let coldOffset = settings.warmupRequests;
	for (let repetition = 0; repetition < settings.repetitions; repetition++) {
		const sample = await uniqueColdSample(
			subject,
			settings.requests,
			concurrency,
			coldOffset,
		);
		coldOffset += settings.requests;
		cold.push(sample);
		progress(
			`  unique cold read run ${repetition + 1}: ${sample.rps.toFixed(0)} ops/s, p99 ${sample.p99_latency_ms.toFixed(3)} ms`,
		);
	}
	measurements.push({
		workload: "tiered_cold_get",
		group: "Tiered storage",
		class: "native",
		subject: "lux",
		description: "First read of distinct values seeded into the cold tier",
		dimensions: {
			operation: "cold_read",
			requests: settings.requests,
			warmup_requests: settings.warmupRequests,
			repetitions: settings.repetitions,
			hot_percent: 0,
			keys: coldCount,
			clients: concurrency,
			reuse: "none",
		},
		samples: cold,
		summary: summarize(cold),
	});
	const mixed: Sample[] = [];
	for (let repetition = 0; repetition < settings.repetitions; repetition++) {
		mixed.push(
			await mixedSample(
				subject,
				settings.requests,
				concurrency,
				coldCount,
				hotCount,
				coldOffset,
			),
		);
		coldOffset += Math.ceil(settings.requests * 0.1);
	}
	measurements.push({
		workload: "tiered_mixed_get",
		group: "Tiered storage",
		class: "native",
		subject: "lux",
		description: "Ninety-percent hot and ten-percent cold reads",
		dimensions: {
			operation: "mixed_read",
			requests: settings.requests,
			warmup_requests: 0,
			repetitions: settings.repetitions,
			hot_percent: 90,
			hot_keys: hotCount,
			cold_keys: coldCount,
			clients: concurrency,
		},
		samples: mixed,
		summary: summarize(mixed),
	});

	const configured = limitBytes(tieredMemoryLimit(quick));
	const after = parseInfo(
		await redisCli(subject, network, clientImage, "INFO", "storage"),
	);
	return {
		measurements,
		evidence: [
			{
				before_reads: before,
				after_reads: after,
				configured_memory_bytes: configured,
				within_configured_memory:
					Number(after.used_memory_bytes) <= configured,
			},
		],
	};
}
