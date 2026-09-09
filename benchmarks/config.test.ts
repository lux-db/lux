import { describe, expect, test } from "bun:test";
import { compatibilityWorkloads } from "./compatibility";
import { SETTINGS, validateConfiguration } from "./config";

describe("benchmark catalog", () => {
  test("standard compatibility catalog is valid and retains the full pipeline curve", () => {
    const workloads = compatibilityWorkloads(false, SETTINGS.standard);
    expect(() => validateConfiguration(workloads)).not.toThrow();
    expect(workloads.some((workload) => workload.id === "pipeline_set_512")).toBeTrue();
    expect(workloads.some((workload) => workload.id === "geo_geosearch_5000km_512")).toBeTrue();
    expect(workloads.some((workload) => workload.group === "Data structures")).toBeTrue();
  });

  test("pipeline override is represented in the quick curve", () => {
    const settings = { ...SETTINGS.quick, pipeline: 64 };
    const workloads = compatibilityWorkloads(true, settings);
    expect(workloads.some((workload) => workload.id === "pipeline_get_64")).toBeTrue();
  });
});
