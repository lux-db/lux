import { describe, expect, test } from "bun:test";
import { testing } from "./lifecycle";

describe("lifecycle resource parsing", () => {
	test("parses Docker memory units", () => {
		expect(testing.parseMemory("852KiB")).toBe(872_448);
		expect(testing.parseMemory("78.5MiB")).toBe(82_313_216);
		expect(testing.parseMemory("1GB")).toBe(1_000_000_000);
	});

	test("builds exact-width recovery values", () => {
		expect(testing.datasetValue(42, 1_024)).toHaveLength(1_024);
		expect(testing.datasetValue(42, 16)).toStartWith("42:");
	});
});
