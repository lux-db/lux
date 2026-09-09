import { describe, expect, test } from "bun:test";
import { median, parseBenchmarkCsv, summarize } from "./stats";
import { parseInfo } from "./measure";

describe("benchmark statistics", () => {
	test("median handles odd and even samples", () => {
		expect(median([3, 1, 2])).toBe(2);
		expect(median([4, 1, 3, 2])).toBe(2.5);
	});

	test("CSV parsing rejects format drift", () => {
		const csv =
			'"test","rps","avg_latency_ms","min_latency_ms","p50_latency_ms","p95_latency_ms","p99_latency_ms","max_latency_ms"\n' +
			'"SET","4000.00","1.109","0.520","0.991","2.055","2.207","2.399"\n';
		expect(parseBenchmarkCsv(csv)).toEqual({
			rps: 4000,
			avg_latency_ms: 1.109,
			min_latency_ms: 0.52,
			p50_latency_ms: 0.991,
			p95_latency_ms: 2.055,
			p99_latency_ms: 2.207,
			max_latency_ms: 2.399,
		});
		expect(() => parseBenchmarkCsv('"test","rps"\n"SET","1"\n')).toThrow();
	});

	test("summaries retain spread rather than hiding repetitions", () => {
		const sample = (rps: number) => ({
			rps,
			avg_latency_ms: 1,
			min_latency_ms: 0.5,
			p50_latency_ms: 1,
			p95_latency_ms: 2,
			p99_latency_ms: 3,
			max_latency_ms: 4,
		});
		const result = summarize([sample(100), sample(110), sample(90)]);
		expect(result.rps).toBe(100);
		expect(result.rps_min).toBe(90);
		expect(result.rps_max).toBe(110);
		expect(result.rps_cv).toBeCloseTo(0.08165, 4);
	});

	test("INFO parsing retains exact metric values", () => {
		expect(
			parseInfo("# Storage\r\nused_disk_bytes:4096\r\ndisk_keys:3\r\n"),
		).toEqual({
			used_disk_bytes: "4096",
			disk_keys: "3",
		});
	});
});
