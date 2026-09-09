import {
	BENCHMARK_PASSWORD,
	type BenchmarkSettings,
	type Workload,
} from "./config";
import { command, docker, progress, waitReady } from "./runtime";
import type { Subject } from "./subjects";
import {
	parseBenchmarkCsv,
	summarize,
	type Sample,
	type Summary,
} from "./stats";

export type Measurement = {
	workload: string;
	group: string;
	class: "compatibility" | "native";
	subject: "lux" | "redis";
	description: string;
	dimensions: Record<string, string | number>;
	samples: Sample[];
	summary: Summary;
};

export function parseInfo(output: string): Record<string, string> {
	const values: Record<string, string> = {};
	for (const line of output.split(/\r?\n/)) {
		if (!line || line.startsWith("#")) continue;
		const separator = line.indexOf(":");
		if (separator > 0)
			values[line.slice(0, separator)] = line.slice(separator + 1);
	}
	return values;
}

function benchmarkArgs(
	subject: Subject,
	network: string,
	clientImage: string,
	settings: BenchmarkSettings,
	workload: Workload,
	requests: number,
	seed: number,
): string[] {
	const pipeline = workload.pipeline ?? 1;
	return [
		"docker",
		"run",
		"--rm",
		"--network",
		network,
		"--cpus",
		String(settings.cpus),
		clientImage,
		"redis-benchmark",
		"-h",
		subject.alias,
		"-p",
		"6379",
		"-a",
		BENCHMARK_PASSWORD,
		"-c",
		String(workload.clients ?? settings.clients),
		"--threads",
		String(workload.threads ?? settings.threads),
		"-n",
		String(requests),
		"-r",
		String(workload.keyspace ?? settings.keyspace),
		"-P",
		String(pipeline),
		"--seed",
		String(seed),
		"--precision",
		"3",
		"--csv",
		...workload.command,
	];
}

export async function runWorkload(
	subject: Subject,
	network: string,
	clientImage: string,
	settings: BenchmarkSettings,
	workload: Workload,
	requests: number,
	seed: number,
): Promise<Sample> {
	const result = await command(
		benchmarkArgs(
			subject,
			network,
			clientImage,
			settings,
			workload,
			requests,
			seed,
		),
		{ quiet: true },
	);
	if (
		/error from server|benchmark aborted/i.test(
			result.stdout + result.stderr,
		)
	)
		throw new Error(
			`${workload.id} returned command errors\n${result.stdout}${result.stderr}`,
		);
	return parseBenchmarkCsv(result.stdout);
}

export async function redisCli(
	subject: Subject,
	network: string,
	clientImage: string,
	...args: string[]
): Promise<string> {
	const result = await command(
		[
			"docker",
			"run",
			"--rm",
			"--network",
			network,
			clientImage,
			"redis-cli",
			"-h",
			subject.alias,
			"-a",
			BENCHMARK_PASSWORD,
			...args,
		],
		{ quiet: true },
	);
	if (/^(ERR|WRONGTYPE|NOAUTH)/m.test(result.stdout))
		throw new Error(result.stdout);
	return result.stdout.trim();
}

export async function measureCatalog(
	subjects: Subject[],
	workloads: Workload[],
	network: string,
	clientImage: string,
	settings: BenchmarkSettings,
): Promise<Measurement[]> {
	const measured: Measurement[] = [];
	for (const workload of workloads) {
		progress(`\n${workload.id}: ${workload.description}`);
		const samples = new Map<Subject, Sample[]>();
		for (const subject of subjects) {
			await runWorkload(
				subject,
				network,
				clientImage,
				settings,
				workload,
				workload.warmupRequests ?? settings.warmupRequests,
				0,
			);
			samples.set(subject, []);
		}
		for (
			let repetition = 0;
			repetition < settings.repetitions;
			repetition++
		) {
			const order =
				repetition % 2 === 0 ? subjects : [...subjects].reverse();
			for (const subject of order) {
				const sample = await runWorkload(
					subject,
					network,
					clientImage,
					settings,
					workload,
					workload.requests ?? settings.requests,
					repetition + 1,
				);
				samples.get(subject)!.push(sample);
				progress(
					`  ${subject.kind} run ${repetition + 1}: ` +
						`${sample.rps.toFixed(0)} ops/s, p99 ${sample.p99_latency_ms.toFixed(3)} ms`,
				);
			}
		}
		for (const subject of subjects) {
			const values = samples.get(subject)!;
			measured.push({
				workload: workload.id,
				group: workload.group,
				class: workload.class,
				subject: subject.kind,
				description: workload.description,
				dimensions: {
					requests: workload.requests ?? settings.requests,
					warmup_requests:
						workload.warmupRequests ?? settings.warmupRequests,
					pipeline: workload.pipeline ?? 1,
					clients: workload.clients ?? settings.clients,
					threads: workload.threads ?? settings.threads,
					keyspace: workload.keyspace ?? settings.keyspace,
					payload_bytes: workload.dimensions?.payload_bytes ?? "-",
					...workload.dimensions,
				},
				samples: values,
				summary: summarize(values),
			});
		}
	}
	return measured;
}

export async function measureRecovery(
	subject: Subject,
	network: string,
	clientImage: string,
): Promise<{ subject: string; recovery_ms: number; value: string }> {
	await redisCli(
		subject,
		network,
		clientImage,
		"SET",
		"benchmark:recovery",
		"preserved",
	);
	await Bun.sleep(1_100);
	await docker("kill", "--signal", "KILL", subject.name);
	const started = performance.now();
	await docker("start", subject.name);
	await waitReady(network, subject.alias, clientImage);
	const value = await redisCli(
		subject,
		network,
		clientImage,
		"GET",
		"benchmark:recovery",
	);
	if (value !== "preserved")
		throw new Error(
			`${subject.kind} did not recover the acknowledged value`,
		);
	return {
		subject: subject.kind,
		recovery_ms: performance.now() - started,
		value,
	};
}
