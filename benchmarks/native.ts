import {
	BENCHMARK_PASSWORD,
	type BenchmarkScale,
	type BenchmarkSettings,
	type Workload,
} from "./config";
import { measureCatalog, redisCli, type Measurement } from "./measure";
import { loadCommands, RespConnection } from "./resp";
import { progress } from "./runtime";
import { sampleFromLatencies, summarize, type Sample } from "./stats";
import type { Subject } from "./subjects";

function tableRows(count: number): Iterable<string[]> {
	return (function* () {
		for (let index = 0; index < count; index++) {
			yield [
				"TINSERT",
				"benchmark_users",
				"id",
				String(index),
				"status",
				index % 2 === 0 ? "active" : "inactive",
				"age",
				String(18 + (index % 60)),
				"score",
				(index % 1_000).toFixed(1),
				"body",
				`user-${index}-${"x".repeat(96)}`,
			];
		}
	})();
}

function postRows(count: number): Iterable<string[]> {
	return (function* () {
		for (let index = 0; index < count; index++)
			yield [
				"TINSERT",
				"benchmark_posts",
				"id",
				String(index),
				"user_id",
				String(index % count),
				"title",
				`post-${index}`,
			];
	})();
}

function tableWorkloads(scale: BenchmarkScale): Workload[] {
	const requests = scale.nativeRequests;
	const keyspace = scale.tableRows;
	const base = {
		class: "native" as const,
		group: "Typed tables over RESP",
		keyspace,
		requests,
		warmupRequests: Math.min(requests, 100),
	};
	return [
		{
			...base,
			id: "table_update",
			description: "Update an existing row by primary key",
			dimensions: { operation: "update", rows: keyspace, result_rows: 1 },
			command: [
				"TUPDATE",
				"benchmark_users",
				"SET",
				"status",
				"active",
				"age",
				"42",
				"score",
				"999",
				"body",
				"updated",
				"WHERE",
				"id",
				"=",
				"__rand_int__",
			],
		},
		{
			...base,
			id: "table_point",
			description: "Primary-key lookup",
			dimensions: {
				operation: "point_lookup",
				rows: keyspace,
				result_rows: 1,
			},
			command: [
				"TSELECT",
				"*",
				"FROM",
				"benchmark_users",
				"WHERE",
				"id",
				"=",
				"__rand_int__",
				"LIMIT",
				"1",
			],
		},
		{
			...base,
			id: "table_equality_filter",
			description: "Indexed equality filter with bounded result",
			dimensions: {
				operation: "equality_filter",
				rows: keyspace,
				result_rows: 100,
			},
			command: [
				"TSELECT",
				"*",
				"FROM",
				"benchmark_users",
				"WHERE",
				"status",
				"=",
				"active",
				"LIMIT",
				"100",
			],
		},
		{
			...base,
			id: "table_range_filter",
			description: "Indexed numeric range with bounded result",
			dimensions: {
				operation: "range_filter",
				rows: keyspace,
				result_rows: 100,
			},
			command: [
				"TSELECT",
				"*",
				"FROM",
				"benchmark_users",
				"WHERE",
				"age",
				">",
				"40",
				"LIMIT",
				"100",
			],
		},
		{
			...base,
			id: "table_page",
			description: "Ordered page from a populated table",
			dimensions: {
				operation: "ordered_page",
				rows: keyspace,
				result_rows: 100,
			},
			command: [
				"TSELECT",
				"*",
				"FROM",
				"benchmark_users",
				"ORDER",
				"BY",
				"id",
				"ASC",
				"LIMIT",
				"100",
				"OFFSET",
				String(Math.min(1_000, Math.floor(keyspace / 2))),
			],
		},
		{
			...base,
			id: "table_count",
			description: "Exact table row count",
			dimensions: { operation: "count", rows: keyspace, result_rows: 1 },
			command: ["TSELECT", "COUNT(*)", "FROM", "benchmark_users"],
		},
		{
			...base,
			id: "table_join",
			description: "One-to-many join with bounded result",
			dimensions: { operation: "join", rows: keyspace, result_rows: 100 },
			requests: Math.min(requests, 20),
			warmupRequests: Math.min(requests, 5),
			command: [
				"TSELECT",
				"*",
				"FROM",
				"benchmark_posts",
				"p",
				"JOIN",
				"benchmark_users",
				"u",
				"ON",
				"p.user_id",
				"=",
				"u.id",
				"LIMIT",
				"100",
			],
		},
	];
}

async function httpSample(
	requests: number,
	concurrency: number,
	execute: (index: number) => Promise<void>,
): Promise<Sample> {
	const latencies: number[] = [];
	let next = 0;
	const started = performance.now();
	await Promise.all(
		Array.from({ length: concurrency }, async () => {
			while (true) {
				const index = next++;
				if (index >= requests) return;
				const requestStarted = performance.now();
				await execute(index);
				latencies.push(performance.now() - requestStarted);
			}
		}),
	);
	return sampleFromLatencies(latencies, performance.now() - started);
}

async function checkedJson(
	response: Response,
	context: string,
): Promise<unknown> {
	const body = await response.text();
	if (!response.ok)
		throw new Error(`${context} returned HTTP ${response.status}: ${body}`);
	try {
		const parsed = JSON.parse(body);
		if (parsed && typeof parsed === "object" && "result" in parsed)
			return parsed.result;
		return parsed;
	} catch {
		throw new Error(`${context} returned invalid JSON`);
	}
}

async function measureHttpTables(
	subject: Subject,
	settings: BenchmarkSettings,
	scale: BenchmarkScale,
): Promise<Measurement[]> {
	const base = `http://127.0.0.1:${subject.http_port}`;
	const authorization = { authorization: `Bearer ${BENCHMARK_PASSWORD}` };
	const concurrency = Math.min(settings.clients, 32);
	const requests = scale.nativeRequests;
	const scenarios = [
		{
			id: "http_table_insert",
			description: "HTTP row insert with JSON encoding and decoding",
			dimensions: {
				operation: "insert",
				rows: scale.tableRows,
				result_rows: 1,
			},
			execute: async (index: number) => {
				const value = await checkedJson(
					await fetch(`${base}/v1/tables/benchmark_http_writes`, {
						method: "POST",
						headers: {
							...authorization,
							"content-type": "application/json",
						},
						body: JSON.stringify({
							status: index % 2 === 0 ? "active" : "inactive",
							body: `write-${index}`,
						}),
					}),
					"HTTP table insert",
				);
				if (value === null || value === undefined)
					throw new Error("HTTP table insert returned no result");
			},
		},
		{
			id: "http_table_point",
			description: "HTTP primary-key lookup with JSON decoding",
			dimensions: {
				operation: "point_lookup",
				rows: scale.tableRows,
				result_rows: 1,
			},
			execute: async (index: number) => {
				const id = (index * 7_919) % scale.tableRows;
				const value = await checkedJson(
					await fetch(`${base}/v1/tables/benchmark_users/${id}`, {
						headers: authorization,
					}),
					"HTTP point lookup",
				);
				if (!value || typeof value !== "object")
					throw new Error("HTTP point lookup lost its row");
			},
		},
		{
			id: "http_table_filter",
			description: "HTTP indexed filter with JSON decoding",
			dimensions: {
				operation: "equality_filter",
				rows: scale.tableRows,
				result_rows: 50,
			},
			execute: async () => {
				const value = await checkedJson(
					await fetch(
						`${base}/v1/tables/benchmark_users?where=status%3Dactive&limit=50`,
						{ headers: authorization },
					),
					"HTTP table filter",
				);
				if (!Array.isArray(value) || value.length !== 50)
					throw new Error(
						`HTTP table filter returned ${Array.isArray(value) ? value.length : "non-array"} rows`,
					);
			},
		},
		{
			id: "http_table_count",
			description: "HTTP exact count with JSON decoding",
			dimensions: {
				operation: "count",
				rows: scale.tableRows,
				result_rows: 1,
			},
			execute: async () => {
				const value = await checkedJson(
					await fetch(`${base}/v1/tables/benchmark_users/count`, {
						headers: authorization,
					}),
					"HTTP table count",
				);
				if (Number(value) !== scale.tableRows)
					throw new Error(
						`HTTP table count returned ${JSON.stringify(value)}`,
					);
			},
		},
	];
	const measurements: Measurement[] = [];
	for (const scenario of scenarios) {
		await httpSample(
			Math.min(100, requests),
			concurrency,
			scenario.execute,
		);
		const samples: Sample[] = [];
		for (
			let repetition = 0;
			repetition < settings.repetitions;
			repetition++
		) {
			const sample = await httpSample(
				requests,
				concurrency,
				scenario.execute,
			);
			samples.push(sample);
			progress(
				`  ${scenario.id} run ${repetition + 1}: ${sample.rps.toFixed(0)} ops/s, p99 ${sample.p99_latency_ms.toFixed(3)} ms`,
			);
		}
		measurements.push({
			workload: scenario.id,
			group: "Application HTTP tables",
			class: "native",
			subject: "lux",
			description: scenario.description,
			dimensions: {
				requests,
				warmup_requests: Math.min(100, requests),
				repetitions: settings.repetitions,
				clients: concurrency,
				protocol: "HTTP/JSON",
				...scenario.dimensions,
			},
			samples,
			summary: summarize(samples),
		});
	}
	return measurements;
}

export async function measureTables(
	subject: Subject,
	network: string,
	clientImage: string,
	settings: BenchmarkSettings,
	scale: BenchmarkScale,
): Promise<Measurement[]> {
	progress(`Preparing ${scale.tableRows} typed rows and join fixtures...`);
	await redisCli(subject, network, clientImage, "FLUSHALL");
	const connection = await RespConnection.connect(
		subject.resp_port,
		BENCHMARK_PASSWORD,
	);
	try {
		await connection.request([
			"TCREATE",
			"benchmark_users",
			"id INT PRIMARY KEY,",
			"status STR,",
			"age INT,",
			"score FLOAT,",
			"body STR",
		]);
		await connection.request([
			"TCREATE",
			"benchmark_posts",
			"id INT PRIMARY KEY,",
			"user_id INT,",
			"title STR",
		]);
		await connection.request([
			"TCREATE",
			"benchmark_http_writes",
			"status STR,",
			"body STR",
		]);
	} finally {
		connection.close();
	}
	await loadCommands(
		subject.resp_port,
		BENCHMARK_PASSWORD,
		tableRows(scale.tableRows),
	);
	await loadCommands(
		subject.resp_port,
		BENCHMARK_PASSWORD,
		postRows(scale.tableRows),
	);

	const measurements = await measureCatalog(
		[subject],
		tableWorkloads(scale),
		network,
		clientImage,
		settings,
	);
	measurements.push(...(await measureHttpTables(subject, settings, scale)));

	const verify = await RespConnection.connect(
		subject.resp_port,
		BENCHMARK_PASSWORD,
	);
	try {
		const count = await verify.request([
			"TSELECT",
			"COUNT(*)",
			"FROM",
			"benchmark_users",
		]);
		if (
			!Array.isArray(count) ||
			!JSON.stringify(count).includes(String(scale.tableRows))
		)
			throw new Error(
				`typed table verification failed: ${JSON.stringify(count)}`,
			);
		const joined = await verify.request([
			"TSELECT",
			"*",
			"FROM",
			"benchmark_posts",
			"p",
			"JOIN",
			"benchmark_users",
			"u",
			"ON",
			"p.user_id",
			"=",
			"u.id",
			"LIMIT",
			"1",
		]);
		if (!Array.isArray(joined) || joined.length !== 1)
			throw new Error(
				`typed join verification failed: ${JSON.stringify(joined)}`,
			);
	} finally {
		verify.close();
	}
	return measurements;
}
