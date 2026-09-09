import {
	BENCHMARK_PASSWORD,
	type BenchmarkScale,
	type BenchmarkSettings,
} from "./config";
import { parseInfo } from "./measure";
import { loadCommands, RespConnection } from "./resp";
import { command, docker, progress, publishedPort, waitReady } from "./runtime";
import { sampleFromLatencies, type Sample } from "./stats";
import { containerStats, startSubject, type Subject } from "./subjects";

export type LifecycleEvidence = {
	subject: "lux" | "redis";
	storage: "memory" | "tiered" | "redis_aof";
	dataset_keys: number;
	payload_bytes: number;
	empty_startup_ms: number;
	snapshot_ms: number;
	snapshot_peak_memory_bytes: number;
	snapshot_read_traffic: Sample;
	recovery_ms: number;
	verified_keys: number;
	post_snapshot_keys: number;
};

function datasetValue(index: number, bytes: number): string {
	const prefix = `${index}:`;
	if (prefix.length > bytes)
		throw new Error(`key index ${index} exceeds payload width ${bytes}`);
	return prefix.padEnd(bytes, "x");
}

function datasetCommands(count: number, bytes: number): Iterable<string[]> {
	return (function* () {
		for (let index = 0; index < count; index++)
			yield [
				"SET",
				`benchmark:recovery:${index}`,
				datasetValue(index, bytes),
			];
	})();
}

function parseMemory(value: string): number {
	const match = value.trim().match(/^([0-9.]+)([KMGT]?i?B)$/i);
	if (!match) throw new Error(`cannot parse Docker memory value: ${value}`);
	const units: Record<string, number> = {
		b: 1,
		kb: 1_000,
		kib: 1_024,
		mb: 1_000_000,
		mib: 1_048_576,
		gb: 1_000_000_000,
		gib: 1_073_741_824,
		tb: 1_000_000_000_000,
		tib: 1_099_511_627_776,
	};
	return Number(match[1]) * units[match[2].toLowerCase()];
}

async function currentMemory(subject: Subject): Promise<number> {
	const stats = await containerStats(subject);
	const usage = String(stats.MemUsage ?? "")
		.split("/")[0]
		.trim();
	return parseMemory(usage);
}

async function waitHostReady(subject: Subject): Promise<void> {
	const deadline = Date.now() + 30_000;
	while (Date.now() < deadline) {
		try {
			const connection = await RespConnection.connect(
				subject.resp_port,
				BENCHMARK_PASSWORD,
			);
			connection.close();
			return;
		} catch {
			await Bun.sleep(50);
		}
	}
	throw new Error(
		`${subject.kind} host port did not become ready after restart`,
	);
}

async function readTraffic(
	subject: Subject,
	requests: number,
	datasetKeys: number,
): Promise<Sample> {
	const concurrency = 16;
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
					const key = index % datasetKeys;
					const requestStarted = performance.now();
					const value = await connection.request([
						"GET",
						`benchmark:recovery:${key}`,
					]);
					latencies.push(performance.now() - requestStarted);
					if (
						typeof value !== "string" ||
						!value.startsWith(`${key}:`)
					)
						throw new Error(
							`${subject.kind} returned an incorrect value during snapshot`,
						);
				}
			}),
		);
	} finally {
		for (const connection of connections) connection.close();
	}
	return sampleFromLatencies(latencies, performance.now() - started);
}

async function snapshot(
	subject: Subject,
): Promise<{ duration: number; peak: number }> {
	const connection = await RespConnection.connect(
		subject.resp_port,
		BENCHMARK_PASSWORD,
	);
	let peak = await currentMemory(subject);
	const started = performance.now();
	try {
		await connection.request(["BGSAVE"]);
		const deadline = Date.now() + 120_000;
		while (Date.now() < deadline) {
			peak = Math.max(peak, await currentMemory(subject));
			const info = parseInfo(
				String(await connection.request(["INFO", "persistence"])),
			);
			if (info.rdb_bgsave_in_progress === "0") {
				if (info.rdb_last_bgsave_status !== "ok")
					throw new Error(
						`${subject.kind} snapshot failed: ${JSON.stringify(info)}`,
					);
				return { duration: performance.now() - started, peak };
			}
			await Bun.sleep(10);
		}
		throw new Error(
			`${subject.kind} snapshot did not complete within 120 seconds`,
		);
	} finally {
		connection.close();
	}
}

async function verifyDataset(
	subject: Subject,
	count: number,
	payloadBytes: number,
	postSnapshotKeys: number,
): Promise<number> {
	const connection = await RespConnection.connect(
		subject.resp_port,
		BENCHMARK_PASSWORD,
	);
	const samples = Math.min(100, count);
	try {
		const size = await connection.request(["DBSIZE"]);
		if (Number(size) !== count + postSnapshotKeys)
			throw new Error(
				`${subject.kind} recovered ${size} keys; expected ${count + postSnapshotKeys}`,
			);
		for (let sample = 0; sample < samples; sample++) {
			const index = Math.floor((sample * count) / samples);
			const value = await connection.request([
				"GET",
				`benchmark:recovery:${index}`,
			]);
			if (value !== datasetValue(index, payloadBytes))
				throw new Error(
					`${subject.kind} recovered an incorrect value for key ${index}`,
				);
		}
		for (let index = 0; index < postSnapshotKeys; index++) {
			const value = await connection.request([
				"GET",
				`benchmark:post-snapshot:${index}`,
			]);
			if (value !== `post-snapshot-${index}`)
				throw new Error(
					`${subject.kind} did not recover post-snapshot key ${index}`,
				);
		}
		return samples + postSnapshotKeys;
	} finally {
		connection.close();
	}
}

export async function measureLifecycle(
	luxImage: string,
	redisImage: string,
	network: string,
	nonce: string,
	quick: boolean,
	settings: BenchmarkSettings,
	scale: BenchmarkScale,
): Promise<LifecycleEvidence[]> {
	const evidence: LifecycleEvidence[] = [];
	const payloadBytes = 1_024;
	for (const keyCount of scale.recoveryKeys) {
		const cases = [
			{
				kind: "lux" as const,
				mode: "durable" as const,
				storage: "memory" as const,
			},
			{
				kind: "redis" as const,
				mode: "durable" as const,
				storage: "redis_aof" as const,
			},
			{
				kind: "lux" as const,
				mode: "tiered" as const,
				storage: "tiered" as const,
			},
		];
		for (const testCase of cases) {
			const { kind, mode, storage } = testCase;
			progress(
				`Lifecycle: ${kind}/${storage}, ${keyCount} durable 1 KiB values...`,
			);
			const subject = await startSubject(
				kind,
				kind === "lux" ? luxImage : redisImage,
				redisImage,
				network,
				`${nonce}-lifecycle-${keyCount}`,
				quick,
				settings,
				mode,
			);
			try {
				await loadCommands(
					subject.resp_port,
					BENCHMARK_PASSWORD,
					datasetCommands(keyCount, payloadBytes),
				);
				await Bun.sleep(1_100);
				const trafficCount = quick ? 1_000 : Math.max(10_000, keyCount);
				const [traffic, saved] = await Promise.all([
					readTraffic(subject, trafficCount, keyCount),
					snapshot(subject),
				]);
				const postSnapshotKeys = 100;
				await loadCommands(
					subject.resp_port,
					BENCHMARK_PASSWORD,
					(function* () {
						for (let index = 0; index < postSnapshotKeys; index++)
							yield [
								"SET",
								`benchmark:post-snapshot:${index}`,
								`post-snapshot-${index}`,
							];
					})(),
				);
				await Bun.sleep(1_100);
				await docker("kill", "--signal", "KILL", subject.name);
				const recoveryStarted = performance.now();
				await docker("start", subject.name);
				await waitReady(network, subject.alias, redisImage);
				subject.resp_port = await publishedPort(subject.name);
				await waitHostReady(subject);
				const recoveryMs = performance.now() - recoveryStarted;
				const verified = await verifyDataset(
					subject,
					keyCount,
					payloadBytes,
					postSnapshotKeys,
				);
				evidence.push({
					subject: kind,
					storage,
					dataset_keys: keyCount,
					payload_bytes: payloadBytes,
					empty_startup_ms: subject.startup_ms,
					snapshot_ms: saved.duration,
					snapshot_peak_memory_bytes: saved.peak,
					snapshot_read_traffic: traffic,
					recovery_ms: recoveryMs,
					verified_keys: verified,
					post_snapshot_keys: postSnapshotKeys,
				});
			} finally {
				await command(["docker", "rm", "-f", subject.name], {
					allowFailure: true,
					quiet: true,
				});
				await command(
					["docker", "volume", "rm", `${subject.name}-data`],
					{
						allowFailure: true,
						quiet: true,
					},
				);
			}
		}
	}
	return evidence;
}

export const testing = { datasetValue, parseMemory };
