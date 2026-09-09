export type Sample = {
	rps: number;
	avg_latency_ms: number;
	min_latency_ms: number;
	p50_latency_ms: number;
	p95_latency_ms: number;
	p99_latency_ms: number;
	max_latency_ms: number;
};

export type Summary = Sample & {
	repetitions: number;
	rps_min: number;
	rps_max: number;
	rps_cv: number;
};

export function median(values: number[]): number {
	if (values.length === 0)
		throw new Error("cannot summarize an empty sample");
	const sorted = [...values].sort((a, b) => a - b);
	const middle = Math.floor(sorted.length / 2);
	return sorted.length % 2 === 0
		? (sorted[middle - 1] + sorted[middle]) / 2
		: sorted[middle];
}

function coefficientOfVariation(values: number[]): number {
	const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
	if (mean === 0) return 0;
	const variance =
		values.reduce((sum, value) => sum + (value - mean) ** 2, 0) /
		values.length;
	return Math.sqrt(variance) / mean;
}

export function summarize(samples: Sample[]): Summary {
	const values = <K extends keyof Sample>(key: K) =>
		samples.map((sample) => sample[key]);
	const rps = values("rps");
	return {
		rps: median(rps),
		avg_latency_ms: median(values("avg_latency_ms")),
		min_latency_ms: median(values("min_latency_ms")),
		p50_latency_ms: median(values("p50_latency_ms")),
		p95_latency_ms: median(values("p95_latency_ms")),
		p99_latency_ms: median(values("p99_latency_ms")),
		max_latency_ms: median(values("max_latency_ms")),
		repetitions: samples.length,
		rps_min: Math.min(...rps),
		rps_max: Math.max(...rps),
		rps_cv: coefficientOfVariation(rps),
	};
}

export function sampleFromLatencies(
	latencies: number[],
	elapsedMs: number,
): Sample {
	if (latencies.length === 0)
		throw new Error("cannot measure an empty workload");
	const sorted = [...latencies].sort((a, b) => a - b);
	const at = (percentile: number) =>
		sorted[Math.max(0, Math.ceil((percentile / 100) * sorted.length) - 1)];
	return {
		rps: (sorted.length * 1_000) / elapsedMs,
		avg_latency_ms:
			sorted.reduce((sum, value) => sum + value, 0) / sorted.length,
		min_latency_ms: sorted[0],
		p50_latency_ms: at(50),
		p95_latency_ms: at(95),
		p99_latency_ms: at(99),
		max_latency_ms: sorted.at(-1)!,
	};
}

export function parseBenchmarkCsv(output: string): Sample {
	const rows = output
		.trim()
		.split("\n")
		.filter((line) => line.startsWith('"'))
		.map((line) =>
			[...line.matchAll(/"([^"]*)"/g)].map((match) => match[1]),
		);
	if (rows.length !== 2 || rows[0].length !== 8 || rows[1].length !== 8)
		throw new Error(`unexpected redis-benchmark CSV:\n${output}`);
	const expected = [
		"test",
		"rps",
		"avg_latency_ms",
		"min_latency_ms",
		"p50_latency_ms",
		"p95_latency_ms",
		"p99_latency_ms",
		"max_latency_ms",
	];
	if (rows[0].some((value, index) => value !== expected[index]))
		throw new Error(
			`unexpected redis-benchmark columns: ${rows[0].join(",")}`,
		);
	const numbers = rows[1].slice(1).map(Number);
	if (numbers.some((value) => !Number.isFinite(value)))
		throw new Error(`invalid redis-benchmark values: ${rows[1].join(",")}`);
	return {
		rps: numbers[0],
		avg_latency_ms: numbers[1],
		min_latency_ms: numbers[2],
		p50_latency_ms: numbers[3],
		p95_latency_ms: numbers[4],
		p99_latency_ms: numbers[5],
		max_latency_ms: numbers[6],
	};
}
