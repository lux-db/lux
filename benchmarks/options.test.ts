import { describe, expect, test } from "bun:test";
import { FEATURES, parseOptions } from "./options";

describe("benchmark options", () => {
  test("no arguments runs every feature with standard settings", () => {
    const options = parseOptions([]);
    expect([...options.features]).toEqual([...FEATURES]);
    expect(options.quick).toBeFalse();
    expect(options.settings.repetitions).toBe(5);
    expect(options.image).toBeUndefined();
  });

  test("features and settings can be selected without exposing presets", () => {
    const options = parseOptions([
      "--quick",
      "--feature",
      "tables,realtime",
      "--requests",
      "42",
      "-i",
      "lux:test",
    ]);
    expect([...options.features]).toEqual(["tables", "realtime"]);
    expect(options.settings.requests).toBe(42);
    expect(options.settings.repetitions).toBe(1);
    expect(options.image).toBe("lux:test");
  });

  test("rejects unknown features and invalid numeric overrides", () => {
    expect(() => parseOptions(["--feature", "nope"])).toThrow("unknown feature");
    expect(() => parseOptions(["--clients", "0"])).toThrow("positive integer");
  });
});
