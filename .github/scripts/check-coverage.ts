import { fileURLToPath } from "node:url";

type FileCoverage = {
  path: string;
  linesCovered: number;
  linesTotal: number;
  branchesCovered: number;
  branchesTotal: number;
};

type CoverageGroup = {
  name: string;
  include: string[];
  exclude?: string[];
  minimum: { lines: number; branches?: number };
};

type CoverageSuite = {
  format: "llvm" | "lcov";
  path_marker: string;
  path_prefix: string;
  exclude?: string[];
  groups: CoverageGroup[];
};

type CoveragePolicy = { suites: Record<string, CoverageSuite> };

function normalizePath(path: string, suite: CoverageSuite): string {
  const normalized = path.replaceAll("\\", "/");
  if (normalized.startsWith(suite.path_prefix)) return normalized;

  const marker = suite.path_marker.replace(/^\/+|\/+$/g, "");
  const needle = `/${marker}/`;
  const index = normalized.indexOf(needle);
  return index === -1
    ? normalized
    : suite.path_prefix + normalized.slice(index + needle.length);
}

function readLlvm(report: unknown, suite: CoverageSuite): FileCoverage[] {
  const data = report as {
    data?: Array<{
      files?: Array<{
        filename: string;
        summary: {
          lines: { covered: number; count: number };
          branches: { covered: number; count: number };
        };
      }>;
    }>;
  };

  return (data.data?.[0]?.files ?? []).map((file) => ({
    path: normalizePath(file.filename, suite),
    linesCovered: file.summary.lines.covered,
    linesTotal: file.summary.lines.count,
    branchesCovered: file.summary.branches.covered,
    branchesTotal: file.summary.branches.count,
  }));
}

function readLcov(report: string, suite: CoverageSuite): FileCoverage[] {
  const files: FileCoverage[] = [];
  let current: FileCoverage | undefined;

  for (const line of report.split(/\r?\n/)) {
    const separator = line.indexOf(":");
    if (separator === -1) continue;
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);

    if (key === "SF") {
      current = {
        path: normalizePath(value, suite),
        linesCovered: 0,
        linesTotal: 0,
        branchesCovered: 0,
        branchesTotal: 0,
      };
      files.push(current);
    } else if (current && key === "LH") {
      current.linesCovered = Number(value);
    } else if (current && key === "LF") {
      current.linesTotal = Number(value);
    } else if (current && key === "BRH") {
      current.branchesCovered = Number(value);
    } else if (current && key === "BRF") {
      current.branchesTotal = Number(value);
    }
  }

  return files;
}

function percent(covered: number, total: number): number {
  return total === 0 ? 0 : (100 * covered) / total;
}

function matches(path: string, patterns: string[]): boolean {
  return patterns.some((pattern) => new RegExp(pattern).test(path));
}

const [suiteName, reportPath, policyArgument] = Bun.argv.slice(2);
if (!suiteName || !reportPath || Bun.argv.length > 5) {
  console.error("usage: bun check-coverage.ts SUITE REPORT [POLICY]");
  process.exit(2);
}

const policyPath =
  policyArgument ?? fileURLToPath(new URL("../coverage-policy.json", import.meta.url));
const policy = (await Bun.file(policyPath).json()) as CoveragePolicy;
const suite = policy.suites[suiteName];
if (!suite) {
  console.error(`coverage gate failed: unknown suite ${JSON.stringify(suiteName)}`);
  process.exit(2);
}

const reportFile = Bun.file(reportPath);
if (!(await reportFile.exists())) {
  console.error(`coverage gate failed: report not found: ${reportPath}`);
  process.exit(1);
}

const files =
  suite.format === "llvm"
    ? readLlvm(await reportFile.json(), suite)
    : readLcov(await reportFile.text(), suite);
if (files.length === 0) {
  console.error(`coverage gate failed: ${reportPath} contains no source files`);
  process.exit(1);
}

const failures: string[] = [];
console.log(`${suiteName} coverage`);
console.log(
  `${"area".padEnd(24)} ${"files".padStart(5)} ${"lines".padStart(18)} ${"branches".padStart(18)}`,
);

for (const group of suite.groups) {
  const excluded = [...(suite.exclude ?? []), ...(group.exclude ?? [])];
  const selected = files.filter(
    (file) => matches(file.path, group.include) && !matches(file.path, excluded),
  );
  if (selected.length === 0) {
    failures.push(`${group.name}: matched no source files`);
    continue;
  }

  const linesCovered = selected.reduce((sum, file) => sum + file.linesCovered, 0);
  const linesTotal = selected.reduce((sum, file) => sum + file.linesTotal, 0);
  const branchesCovered = selected.reduce((sum, file) => sum + file.branchesCovered, 0);
  const branchesTotal = selected.reduce((sum, file) => sum + file.branchesTotal, 0);
  const linePercent = percent(linesCovered, linesTotal);
  const branchPercent = percent(branchesCovered, branchesTotal);
  const lineDisplay = `${linePercent.toFixed(2)}% (${linesCovered}/${linesTotal})`;
  const branchDisplay = branchesTotal
    ? `${branchPercent.toFixed(2)}% (${branchesCovered}/${branchesTotal})`
    : "n/a";

  console.log(
    `${group.name.padEnd(24)} ${String(selected.length).padStart(5)} ${lineDisplay.padStart(18)} ${branchDisplay.padStart(18)}`,
  );

  if (linesTotal === 0) {
    failures.push(`${group.name}: contains no coverable lines`);
  } else if (linePercent + 1e-9 < group.minimum.lines) {
    failures.push(
      `${group.name}: line coverage ${linePercent.toFixed(2)}% is below ${group.minimum.lines.toFixed(2)}%`,
    );
  }

  if (group.minimum.branches !== undefined) {
    if (branchesTotal === 0) {
      failures.push(`${group.name}: contains no coverable branches`);
    } else if (branchPercent + 1e-9 < group.minimum.branches) {
      failures.push(
        `${group.name}: branch coverage ${branchPercent.toFixed(2)}% is below ${group.minimum.branches.toFixed(2)}%`,
      );
    }
  }
}

if (failures.length > 0) {
  console.error("\ncoverage gate failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}
