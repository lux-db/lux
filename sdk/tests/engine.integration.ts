import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { accessSync, constants, mkdirSync, mkdtempSync, openSync, closeSync } from 'node:fs';
import { createServer } from 'node:net';
import { createServer as createHTTPServer } from 'node:http';
import { join } from 'node:path';
import Lux from '../dist/esm/index.js';
import { createClient } from '../dist/esm/project.js';
import { createBrowserClient } from '../dist/esm/browser.js';
import { createServerClient } from '../dist/esm/ssr.js';

const binary = process.env.LUX_TEST_ENGINE_BIN;
assert(binary, 'Set LUX_TEST_ENGINE_BIN to the Engine binary under test');
accessSync(binary, constants.X_OK);
const evidence = process.env.LUX_TEST_WORK_DIR;
assert(evidence, 'Set LUX_TEST_WORK_DIR to a disposable test-output directory');
mkdirSync(evidence, { recursive: true });
const fixture = mkdtempSync(join(evidence, 'run-'));
const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('LUX_')));
const processes: Array<{ process: ReturnType<typeof spawn>; exited: Promise<unknown> }> = [];
const subscriptions: any[] = [];
const timer = setTimeout(() => {
  for (const child of processes) child.process.kill('SIGKILL');
  console.error('Integration run exceeded its four-minute deadline');
  process.exit(1);
}, 240_000);
const checked: string[] = [];
const ports = new Set<number>();
function result<T>(r: {data: T | null; error: unknown}, name: string): T {
  assert.equal(r.error, null, `${name}: ${JSON.stringify(r.error)}`);
  checked.push(name);
  return r.data!;
}
async function port() {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {server.once('error', reject); server.listen(0, '127.0.0.1', resolve);});
  const value = (server.address() as any).port;
  await new Promise<void>(resolve => server.close(() => resolve()));
  if (ports.has(value)) return port();
  ports.add(value);
  return value;
}
async function start(name: string) {
  const dir = join(fixture, name); mkdirSync(dir);
  const http = await port(); const resp = await port();
  const url = `http://127.0.0.1:${http}`;
  const pub = `lux_pub_sdk_${name}`; const secret = `lux_sk_sdk_${name}`;
  const fd = openSync(join(dir, 'engine.log'), 'w', 0o600);
  const process = spawn(binary, [], {
    cwd: dir, stdio: ['ignore', fd, fd], env: {...cleanEnv,
      LUX_DATA_DIR: dir, LUX_PORT: String(resp), LUX_HTTP_PORT: String(http),
      LUX_BIND_HOST: '127.0.0.1', LUX_PASSWORD: `sdk-fixture-${name}`,
      LUX_AUTH_ENABLED: '1', LUX_AUTH_PUBLISHABLE_KEY: pub, LUX_AUTH_SECRET_KEY: secret,
      LUX_ENC_AUTO_INIT: '1', LUX_SHARDS: '2', LUX_RUNTIME_THREADS: '2', RAYON_NUM_THREADS: '2',
    },
  });
  closeSync(fd);
  const exited = new Promise(resolve => process.once('exit', resolve));
  processes.push({process, exited});
  const deadline = Date.now() + 15_000;
  while (true) {
    try { if ((await fetch(`${url}/health/ready`, {signal: AbortSignal.timeout(500)})).ok) break; } catch {}
    assert(Date.now() < deadline, `${name} not ready: ${dir}/engine.log`);
    await Bun.sleep(50);
  }
  return {url, pub, secret, resp};
}

try {
  const stalled = createHTTPServer((_request, _response) => {});
  await new Promise<void>(resolve => stalled.listen(0, '127.0.0.1', resolve));
  try {
    const stalledURL = `http://127.0.0.1:${(stalled.address() as any).port}`;
    const deadlineClient = createClient(stalledURL, 'lux_pub_fixture', {requestTimeoutMs:30});
    assert.equal((await deadlineClient.ping()).error?.details?.code, 'LUX_REQUEST_TIMEOUT');
    const controller = new AbortController();
    const cancelledClient = createClient(stalledURL, 'lux_pub_fixture', {signal:controller.signal});
    const pending = cancelledClient.auth.signInAnonymously();
    controller.abort();
    assert.equal((await pending).error?.details?.code, 'LUX_REQUEST_ABORTED');
    checked.push('real HTTP deadline and cancellation');
  } finally {
    stalled.closeAllConnections();
    await new Promise<void>(resolve => stalled.close(() => resolve()));
  }
  const a = await start('a'); const b = await start('b');
  const values = new Map<string, string>();
  const cookies = {
    getAll: () => [...values].map(([name, value]) => ({name, value})),
    setAll: (updates: any[]) => { for (const {name, value, options} of updates) {
      if (options.maxAge === 0) values.delete(name); else values.set(name, value);
    } },
  };
  const direct = new Lux({host:'127.0.0.1', port:a.resp, password:'sdk-fixture-a', lazyConnect:true});
  try {
    assert.equal(await direct.ping(), 'PONG');
    await direct.set('sdk:counter', '1');
    assert.equal(await direct.incr('sdk:counter'), 2);
    assert.equal(await direct.get('sdk:counter'), '2');
    checked.push('packaged direct RESP connection/read/write');
  } finally { direct.disconnect(); }
  const admin = createClient(a.url, a.secret);
  result(await admin.createTable('notes', ['id STR PRIMARY KEY', 'user_id STR', 'body STR']), 'create table');
  result(await admin.exec('GRANT read, write ON notes WHERE user_id = auth.uid()'), 'row grant');
  const sockets: WebSocket[] = [];
  class TrackedSocket extends WebSocket { constructor(url: string | URL, protocols?: string | string[]) { super(url, protocols); sockets.push(this); } }
  const browser = createBrowserClient(a.url, a.pub, {cookies, websocket:TrackedSocket, isSingleton: true, auth: {autoRefreshToken: false}});
  const other = createBrowserClient(b.url, b.pub, {cookies, isSingleton: true, auth: {autoRefreshToken: false}});
  assert.notEqual(browser, other);
  const signup = result(await browser.auth.signUp({email: 'sdk@example.test', password: 'local-sdk-fixture-password'}), 'signup');
  assert(signup.session);
  assert.equal(result(await browser.auth.updateUser({data:{source:'sdk-integration'}}), 'update user metadata').user.user_metadata?.source, 'sdk-integration');
  assert((await browser.auth.admin.listUsers()).error, 'publishable client must not administer users');
  const createdUser = result(await admin.auth.admin.createUser({email:'admin-created@example.test',password:'fixture-password'}), 'admin create user');
  result(await admin.auth.admin.getUserById(createdUser.id), 'admin read user');
  result(await admin.auth.admin.updateUserById(createdUser.id, {user_metadata:{source:'admin'}}), 'admin update user');
  result(await admin.auth.admin.listUsers(), 'admin list users');
  result(await admin.auth.admin.deleteUser(createdUser.id), 'admin delete user');
  result(await admin.auth.listApiKeys(), 'admin list keys');
  result(await admin.auth.listProviders(), 'admin list providers');
  result(await admin.auth.getSettings(), 'admin read settings');
  assert.equal((await other.auth.getSession()).data?.session, null);
  const server = createServerClient(a.url, a.pub, {cookies});
  assert.equal((await server.auth.getUser()).data?.user.id, signup.user.id);
  checked.push('browser/SSR same-project session, second project isolated');
  result(await browser.table('notes').insert({id:'mine', user_id:signup.user.id, body:'one'}), 'owned row insert');
  assert((await browser.table('notes').insert({id:'not-mine', user_id:'someone-else', body:'no'})).error);
  const rows = result(await server.table('notes').select(), 'SSR row read');
  assert.equal(rows.length, 1);
  assert.equal(result(await browser.table('notes').select().eq('id','mine').single(), 'single row').id, 'mine');
  assert.equal(result(await browser.table('notes').select().eq('id','absent').maybeSingle(), 'optional missing row'), null);
  result(await browser.table('notes').upsert({id:'temporary',user_id:signup.user.id,body:'initial'}), 'upsert insert');
  result(await browser.table('notes').upsert({id:'temporary',user_id:signup.user.id,body:'replacement'}), 'upsert update');
  result(await browser.table('notes').delete().eq('id','temporary'), 'owned row delete');
  const live = await browser.table('notes').live(); assert.equal(live.error, null); subscriptions.push(live.live);
  const iterator = live.live![Symbol.asyncIterator]();
  assert.equal((await iterator.next()).value?.type, 'snapshot');
  result(await browser.table('notes').update({body:'two'}).eq('id','mine'), 'owned row update');
  assert.equal((await iterator.next()).value?.type, 'update'); checked.push('live snapshot/update');
  sockets.at(-1)!.close();
  assert.equal((await iterator.next()).value?.type, 'snapshot'); checked.push('live reconnect snapshot');
  await live.live!.unsubscribe(); subscriptions.pop();
  const refreshed = await Promise.all(Array.from({length:8}, () => browser.auth.refreshSession(signup.session!.refresh_token)));
  const tokens = refreshed.map(r => result(r, 'concurrent refresh').session.refresh_token);
  assert.equal(new Set(tokens).size, 1);
  const device = result(await browser.push.register({token:'ab'.repeat(32), environment:'sandbox'}), 'push register');
  assert(result(await browser.push.devices(), 'push list').some(d => d.id === device.id));
  result(await browser.push.unregister(device.id), 'push unregister');
  result(await admin.vectorSet('vec', [1,0,0], {kind:'sdk'}), 'vector write');
  assert(JSON.stringify(result(await admin.vectorSearch({vector:[1,0,0], k:1}), 'vector search')).includes('"vec"'));
  result(await admin.tsAdd('cpu', 42, {timestamp:1000}), 'timeseries write');
  assert((await admin.tsAdd('cpu', 99, {timestamp:1.5})).error, 'invalid timestamps must report command errors');
  const samples = JSON.stringify(result(await admin.tsRange('cpu', {from:0,to:2000}), 'timeseries read'));
  assert(samples.includes('1000') && samples.includes('42'));
  result(await admin.request('POST', '/v1/ts/raw-numeric', {timestamp:2000,value:7}), 'numeric HTTP timestamp');
  assert(JSON.stringify(result(await admin.tsRange('raw-numeric', {from:2000,to:2000}), 'numeric HTTP timestamp read')).includes('2000'));
  result(await browser.auth.signOut(), 'sign out');
  result(await browser.auth.signInWithPassword({email:'sdk@example.test',password:'local-sdk-fixture-password'}), 'password login');
  result(await browser.auth.signOut(), 'final sign out');
  result(await other.auth.signInAnonymously(), 'second project anonymous login');
  assert.equal((await browser.auth.getSession()).data?.session, null);
  result(await other.auth.signOut(), 'second project sign out');
  console.log(JSON.stringify({fixture, checked, result:'pass'}, null, 2));
} finally {
  clearTimeout(timer);
  for (const sub of subscriptions) await sub.unsubscribe();
  for (const {process} of processes) process.kill('SIGTERM');
  const stop = setTimeout(() => {for (const {process} of processes) process.kill('SIGKILL');}, 10_000);
  await Promise.all(processes.map(({exited}) => exited)); clearTimeout(stop);
}
