// Run against an explicitly selected, already-built image; never pull or retag latest.
// LUX_E2E_ENGINE_VERSION=local-test LUX_E2E_CLI_BIN=/path/to/lux bun cli/tests/e2e-docker.ts
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, symlinkSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const version = process.env.LUX_E2E_ENGINE_VERSION;
assert(version && /^[A-Za-z0-9_.-]+$/.test(version), 'set LUX_E2E_ENGINE_VERSION to a locally built image tag');
const binary = resolve(process.env.LUX_E2E_CLI_BIN ?? join(repo, 'cli/target/debug/lux'));
assert(existsSync(binary), 'build the CLI first');
const image = `ghcr.io/lux-db/lux:${version}`;
assert.equal(Bun.spawnSync(['docker', 'image', 'inspect', image], { stdout: 'ignore', stderr: 'ignore' }).exitCode, 0, 'build the selected engine image first');
mkdirSync(join(repo, '.scratch'), { recursive: true });
const project = mkdtempSync(join(repo, '.scratch', 'cli-docker-'));
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('LUX_') && key !== 'OPENROUTER_API_KEY'));
const realDocker = Bun.which('docker');
assert(realDocker);
const testBin = join(project, 'bin');
mkdirSync(testBin);
const boundary = join(repo, 'cli/tests/docker-boundary.mjs');
symlinkSync(boundary, join(testBin, 'docker'));
const registryLog = join(project, 'registry.log');
env.PATH = `${testBin}:${env.PATH}`;
env.LUX_E2E_REAL_DOCKER = realDocker;
env.LUX_E2E_REGISTRY_LOG = registryLog;
const statePath = join(project, 'lux/.lux-local.json');
const state = () => JSON.parse(readFileSync(statePath, 'utf8'));
function cli(args: string[], success = true, extraEnv: Record<string, string> = {}): string {
  const result = Bun.spawnSync([binary, ...args], { cwd: project, env: { ...env, ...extraEnv }, timeout: 120_000 });
  const output = result.stdout.toString() + result.stderr.toString();
  assert(success ? result.exitCode === 0 : result.exitCode !== 0,
    `${args[0]}: unexpected exit ${result.exitCode}\n${output}`);
  return output;
}
function command(...args: string[]): string {
  const current = state();
  return cli(['exec', 'local', '--host', '127.0.0.1', '--port', String(current.resp_port), '--password', current.password, ...args]).trim();
}
function containerId(): string {
  const result = Bun.spawnSync(['docker', 'inspect', '--format', '{{.Id}}', state().container]);
  assert.equal(result.exitCode, 0);
  return result.stdout.toString().trim();
}
let completed = false;
try {
  cli(['init']);
  const config = `engine_version = "${version}"\n[engine.logging]\nformat = "json"\n`;
  writeFileSync(join(project, 'lux/config.toml'), config);
  writeFileSync(join(project, '.env.local'), '# application settings\nAPP_MARKER=preserved\n');
  writeFileSync(join(project, 'lux/migrations/001_create.lux'), 'TCREATE local_rows id INT PRIMARY KEY, value STR;\n');
  writeFileSync(join(project, 'lux/seed.lux'), 'INCR seed_runs;\nTINSERT local_rows id 1 value seeded;\n');
  cli(['init']);
  assert.equal(readFileSync(join(project, 'lux/config.toml'), 'utf8'), config);
  cli(['start', '--no-studio'], false, { LUX_E2E_INTERRUPT_AFTER_RUN: '1' });
  cli(['start', '--no-studio']);
  cli(['migrate', 'status', '--check']);
  assert.equal(command('GET', 'seed_runs'), '1');
  assert.match(readFileSync(join(project, '.env.local'), 'utf8'), /APP_MARKER=preserved/);
  const first = containerId();

  writeFileSync(join(project, 'lux/migrations/002_followup.lux'), 'TINSERT local_rows id 2 value migrated;\n');
  cli(['start', '--no-studio']);
  cli(['migrate', 'status', '--check']);
  assert.equal(containerId(), first, 'migration reconciliation must reuse the running container');
  assert.equal(command('GET', 'seed_runs'), '1', 'repeated start must not reseed');
  assert.match(command('TSELECT', '*', 'FROM', 'local_rows'), /migrated/);

  writeFileSync(join(project, 'lux/migrations/003_partial.lux'), 'SET partial_marker recorded;\nTINSERT repair_rows id 1;\n');
  cli(['start', '--no-studio'], false);
  cli(['migrate', 'status', '--check'], false);
  assert.equal(command('GET', 'partial_marker'), 'recorded');
  command('TCREATE', 'repair_rows', 'id INT PRIMARY KEY');
  cli(['migrate', 'repair', '003_partial.lux', 'resume', '1']);

  writeFileSync(join(project, 'lux/config.toml'), `${config}\n[engine.limits]\nresp_connections = 64\n`);
  cli(['start', '--no-studio']);
  assert.notEqual(containerId(), first, 'changed settings must recreate the container');
  assert.equal(command('GET', 'seed_runs'), '1');
  assert.match(command('TSELECT', '*', 'FROM', 'local_rows'), /migrated/);
  cli(['stop']);
  cli(['start', '--no-studio']);
  assert.equal(command('GET', 'seed_runs'), '1');
  assert.match(command('TSELECT', '*', 'FROM', 'local_rows'), /migrated/);
  cli(['doctor']);
  // Doctor may explicitly inspect image versions; startup must not do so.
  if (existsSync(registryLog)) rmSync(registryLog);

  cli(['stop', '--clear']);
  rmSync(join(project, 'lux/migrations/003_partial.lux'));
  writeFileSync(join(project, 'lux/seed.lux'), 'INCR seed_runs;\nTINSERT missing_seed_table id 1;\n');
  cli(['start', '--no-studio'], false);
  assert.equal(command('GET', 'seed_runs'), '1');
  cli(['start', '--no-studio'], false);
  assert.equal(command('GET', 'seed_runs'), '1', 'failed seeds must not replay implicitly');
  writeFileSync(join(project, 'lux/seed.lux'), 'SET seed_runs 1;\n');
  cli(['seed', 'run']);
  cli(['start', '--no-studio']);
  assert.equal(state().seed_status, 'complete');
  assert(!existsSync(registryLog), 'cached startup must not query the registry');
  writeFileSync(join(project, 'lux/seed.lux'), 'TINSERT missing_seed_table id 1;\n');
  cli(['seed', 'run'], false);
  assert.equal(state().seed_status, 'complete', 'an optional seed run must not reset completed initialization');
  cli(['start', '--no-studio']);
  writeFileSync(join(project, 'lux/seed.lux'), 'SET seed_runs 1;\n');

  const restarting = state().container;
  cli(['stop']);
  assert.equal(Bun.spawnSync([realDocker, 'run', '-d', '--name', restarting, '--restart', 'always', '--entrypoint', '/lux-healthcheck', image, 'invalid-test-mode']).exitCode, 0);
  const deadline = Date.now() + 10_000;
  let observedRestart = false;
  while (Date.now() < deadline) {
    const status = Bun.spawnSync([realDocker, 'inspect', '--format', '{{.State.Status}}', restarting]).stdout.toString().trim();
    if (status === 'restarting') { observedRestart = true; break; }
    await Bun.sleep(50);
  }
  assert(observedRestart, 'fixture must reproduce a restarting container');
  cli(['start', '--no-studio']);
  assert.equal(command('GET', 'seed_runs'), '1', 'restart-loop recovery must preserve the data volume');
  assert.equal(Bun.spawnSync([realDocker, 'pause', state().container]).exitCode, 0);
  cli(['stop']);
  cli(['start', '--no-studio']);
  assert.equal(command('GET', 'seed_runs'), '1', 'paused-container recovery must preserve data');

  const volumeHolder = `${state().container}-volume-holder`;
  try {
    assert.equal(Bun.spawnSync([realDocker, 'run', '-d', '--name', volumeHolder, '-v', `${state().volume}:/data`, '--entrypoint', '/lux-healthcheck', image, 'invalid-test-mode']).exitCode, 0);
    cli(['start', '--fresh', '--no-studio'], false);
    cli(['stop', '--clear'], false);
  } finally {
    assert.equal(Bun.spawnSync([realDocker, 'rm', '-f', volumeHolder]).exitCode, 0);
  }
  cli(['start', '--no-studio']);
  assert.equal(command('GET', 'seed_runs'), '1', 'failed volume removal must not reset initialization or discard data');

  const beforeInvalidRestore = containerId();
  const invalidSnapshot = join(project, 'invalid.dat');
  writeFileSync(invalidSnapshot, 'not a Lux snapshot');
  cli(['restore', invalidSnapshot], false);
  assert.equal(containerId(), beforeInvalidRestore, 'invalid restore must leave the running engine alone');
  assert.equal(command('GET', 'seed_runs'), '1');

  const current = state();
  const response = await fetch(`http://127.0.0.1:${current.http_port}/v1/snapshot`, {
    headers: { Authorization: `Bearer ${current.password}` },
  });
  assert.equal(response.status, 200);
  const snapshotPath = join(project, 'valid.dat');
  writeFileSync(snapshotPath, new Uint8Array(await response.arrayBuffer()), { mode: 0o600 });
  command('SET', 'after_snapshot', 'temporary');
  cli(['restore', snapshotPath]);
  assert.notEqual(containerId(), beforeInvalidRestore);
  assert.equal(command('GET', 'seed_runs'), '1');
  assert.match(command('TSELECT', '*', 'FROM', 'local_rows'), /migrated/);
  assert.doesNotMatch(command('GET', 'after_snapshot'), /temporary/);
  cli(['migrate', 'status', '--check']);
  completed = true;
  console.log('Docker lifecycle passed: interrupted initialization, explicit failed-seed recovery, migrations and repair, offline startup, restarting/paused container recovery, refused volume removal, and invalid/valid snapshot restore.');
} finally {
  if (existsSync(statePath)) {
    const current = state();
    assert(current.container.startsWith('lux-cli-docker-'), 'refusing cleanup outside fixture');
    cli(['stop', '--clear']);
  }
  if (completed) rmSync(project, { recursive: true });
  else console.error(`Failure fixture retained at ${project}`);
}
