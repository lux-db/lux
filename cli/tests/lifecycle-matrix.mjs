import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

assert(
  process.argv.length === 5 || process.argv.length === 6,
  "usage: node cli/tests/lifecycle-matrix.mjs CLI_BINARY SOURCE_IMAGE CANDIDATE_IMAGE [EVIDENCE_DIR]",
);

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const cli = resolve(process.argv[2]);
const sourceImage = process.argv[3];
const candidateImage = process.argv[4];
const timestamp = new Date().toISOString().replaceAll(":", "-");
const evidenceDir = resolve(
  process.argv[5] ?? join(root, ".scratch/lifecycle", timestamp),
);
assert(existsSync(cli), `CLI binary does not exist: ${cli}`);
assert(/^[a-zA-Z0-9]/.test(sourceImage) && /^[a-zA-Z0-9]/.test(candidateImage));
mkdirSync(evidenceDir, { recursive: true });

const results = [];
const startedAt = new Date().toISOString();
const finalImage = `lux-lifecycle-final:${process.pid}`;
let sourceId = null;
let candidateId = null;
let finalFixtureBuilt = false;

function run(label, command, args, options = {}) {
  console.log(`\n==> ${label}`);
  const started = Date.now();
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      cwd: root,
      env: { ...process.env, ...options.env },
      stdio: [options.input ? "pipe" : "ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), options.timeout ?? 180_000);
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      process.stdout.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      process.stderr.write(chunk);
    });
    child.on("error", rejectRun);
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      const result = {
        label,
        command: [command, ...args],
        duration_ms: Date.now() - started,
        exit_code: code,
        signal,
      };
      results.push(result);
      writeFileSync(join(evidenceDir, `${label}.log`), stdout + stderr);
      if (code === 0) resolveRun(stdout);
      else rejectRun(new Error(`${label} failed with exit ${code ?? signal}`));
    });
    if (options.input) child.stdin.end(options.input);
  });
}

async function output(command, args) {
  return (await run(`inventory-${results.length + 1}`, command, args, { timeout: 30_000 })).trim();
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

let failure = null;
try {
  sourceId = await output("docker", ["image", "inspect", "--format", "{{.Id}}", sourceImage]);
  candidateId = await output("docker", ["image", "inspect", "--format", "{{.Id}}", candidateImage]);
  assert.notEqual(sourceId, candidateId, "source and candidate images must differ");

  await run("fresh-install", "bun", ["cli/tests/e2e-docker.ts"], {
    env: {
      LUX_E2E_CLI_BIN: cli,
      LUX_E2E_ENGINE_IMAGE: candidateImage,
    },
  });

  const modes = [
    ["upgrade-tiered", "normal", "tiered"],
    ["upgrade-memory", "normal", "memory"],
    ["backup-rollback", "backup-rollback", "tiered"],
    ["verification-isolation", "verification-write", "tiered"],
    ["source-snapshot-refusal", "snapshot-failure", "tiered"],
    ["stopped-snapshot-refusal", "stopped-snapshot-failure", "tiered"],
    ["candidate-start-refusal", "probe-failure", "tiered"],
    ["candidate-import-refusal", "import-failure", "tiered"],
    ["stopped-stack", "stopped", "tiered"],
    ["prepare-resume", "prepare-interruption", "tiered"],
    ["cutover-resume", "cutover-interruption", "tiered"],
  ];
  for (const [label, mode, storage] of modes) {
    await run(label, "node", [
      "cli/tests/upgrade.mjs",
      cli,
      sourceImage,
      candidateImage,
    ], {
      env: {
        AUTO_TEST_MODE: mode,
        LUX_SOURCE_STORAGE_MODE: storage,
      },
    });
  }

  await run("downgrade-refusal", "node", [
    "cli/tests/upgrade.mjs",
    cli,
    candidateImage,
    sourceImage,
  ], {
    env: {
      AUTO_TEST_MODE: "unsupported-downgrade",
      LUX_SOURCE_STORAGE_MODE: "tiered",
    },
  });

  await run(
    "build-final-transition-fixture",
    "docker",
    ["build", "--tag", finalImage, "-"],
    {
      input: `FROM ${candidateImage}\nLABEL local.lifecycle.transition=final\n`,
      timeout: 120_000,
    },
  );
  finalFixtureBuilt = true;
  await run("candidate-to-final", "node", [
    "cli/tests/upgrade.mjs",
    cli,
    candidateImage,
    finalImage,
  ], {
    env: {
      AUTO_TEST_MODE: "normal",
      LUX_SOURCE_STORAGE_MODE: "tiered",
    },
  });
} catch (error) {
  failure = error instanceof Error ? error.message : String(error);
  process.exitCode = 1;
} finally {
  if (finalFixtureBuilt)
    await run("cleanup-final-transition-fixture", "docker", ["image", "rm", finalImage], {
      timeout: 30_000,
    }).catch(() => {});
  const summary = {
    result: failure ? "fail" : "pass",
    failure,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    git_commit: await output("git", ["rev-parse", "HEAD"]).catch(() => null),
    cli: { path: cli, sha256: sha256(cli) },
    source_image: { reference: sourceImage, id: sourceId },
    candidate_image: { reference: candidateImage, id: candidateId },
    results,
  };
  writeFileSync(join(evidenceDir, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
  console.log(`\nLifecycle evidence: ${evidenceDir}`);
  if (failure) console.error(failure);
}
