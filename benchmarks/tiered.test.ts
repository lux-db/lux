import { describe, expect, test } from "bun:test";
import { tieredKey } from "./tiered";

describe("tiered benchmark fixtures", () => {
	test("hot keys match redis-benchmark substitution and cold keys sort lexically", () => {
		const benchmarkKey = "benchmark:tiered:hot:__rand_int__".replace(
			"__rand_int__",
			"42",
		);
		expect(tieredKey("hot", 42)).toBe(benchmarkKey);
		expect(tieredKey("cold", 42)).toBe(
			"benchmark:tiered:cold:000000000042",
		);
	});
});
