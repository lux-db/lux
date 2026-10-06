#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';

const args = process.argv.slice(2);
const docker = process.env.LUX_E2E_REAL_DOCKER;
if (!docker?.startsWith('/')) throw new Error('an absolute real Docker executable is required');
if (args[0] === 'pull' || (args[0] === 'buildx' && args[1] === 'imagetools')) {
  appendFileSync(process.env.LUX_E2E_REGISTRY_LOG, `${args[0]}\n`);
  console.error('test registry is unavailable');
  process.exit(1);
}
const result = spawnSync(docker, args, { maxBuffer: 16 * 1024 * 1024 });
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
if (result.status === 0 && args[0] === 'run' && process.env.LUX_E2E_INTERRUPT_AFTER_RUN === '1') {
  // The CLI waits for this child. Terminate that test CLI only after Docker
  // has actually created its container, before it can initialize project data.
  process.kill(process.ppid, 'SIGKILL');
}
process.exit(result.status ?? 1);
