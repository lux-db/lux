import { describe, expect, test } from 'bun:test';
import { createClient } from '../src/project';
import { createServerClient } from '../src/ssr';
import { createBrowserClient } from '../src/browser';
import { LuxAuthClient } from '../src/auth';
import { fetchText, requestTimeout } from '../src/http';

describe('HTTP request lifecycle', () => {
	test('command errors inside successful HTTP responses remain SDK errors', async () => {
		const client = createClient('http://localhost', 'public', {
			fetch:(async () => Response.json({error:'ERR invalid timestamp'})) as typeof fetch,
		});
		const result = await client.tsAdd('cpu', 1, {timestamp:1.5});
		expect(result.data).toBeNull();
		expect(result.error?.message).toBe('ERR invalid timestamp');
	});
	test('default deadline is finite and invalid timer values fail at construction', () => {
		expect(requestTimeout()).toBe(30_000);
		for (const value of [0, -1, NaN, Infinity, 1.5, 2_147_483_648]) {
			expect(() => createClient('http://localhost', 'public', { requestTimeoutMs: value })).toThrow();
			expect(() => new LuxAuthClient({ requestTimeoutMs: value })).toThrow();
		}
	});

	test('deadline stops waiting for headers, including a custom fetch that ignores cancellation', async () => {
		let signal: AbortSignal | null | undefined;
		const fetchImpl = ((_url, init) => {
			signal = init?.signal;
			return new Promise<Response>(() => {});
		}) as typeof fetch;
		await expect(fetchText(fetchImpl, 'http://localhost', {}, 10)).rejects.toMatchObject({ code: 'LUX_REQUEST_TIMEOUT' });
		expect(signal?.aborted).toBe(true);
	});

	test('deadline also covers a stalled response body', async () => {
		const fetchImpl = (async () => ({ text: () => new Promise<string>(() => {}) })) as unknown as typeof fetch;
		await expect(fetchText(fetchImpl, 'http://localhost', {}, 10)).rejects.toMatchObject({ code: 'LUX_REQUEST_TIMEOUT' });
	});

	test('an already-cancelled request never reaches fetch', async () => {
		const controller = new AbortController(); controller.abort();
		let calls = 0;
		const fetchImpl = (async () => { calls++; return new Response('{}'); }) as typeof fetch;
		await expect(fetchText(fetchImpl, 'http://localhost', {signal:controller.signal}, 100)).rejects.toMatchObject({ code: 'LUX_REQUEST_ABORTED' });
		expect(calls).toBe(0);
	});

	test('client cancellation reaches project requests and authentication', async () => {
		const controller = new AbortController();
		const fetchImpl = (() => new Promise<Response>(() => {})) as typeof fetch;
		const client = createClient('http://localhost', 'public', {fetch: fetchImpl, signal:controller.signal});
		const request = client.ping();
		const signin = client.auth.signInAnonymously();
		controller.abort();
		expect((await request).error?.details).toMatchObject({code:'LUX_REQUEST_ABORTED'});
		expect((await signin).error?.details).toMatchObject({code:'LUX_REQUEST_ABORTED'});
	});

	test('browser and SSR helpers forward deadlines', async () => {
		const fetchImpl = (() => new Promise<Response>(() => {})) as typeof fetch;
		const options = {fetch:fetchImpl, requestTimeoutMs:10, isSingleton:false};
		for (const client of [createBrowserClient('http://localhost', 'public', options), createServerClient('http://localhost', 'public', options)]) {
			expect((await client.ping()).error?.details).toMatchObject({code:'LUX_REQUEST_TIMEOUT'});
			expect((await client.auth.signInAnonymously()).error?.details).toMatchObject({code:'LUX_REQUEST_TIMEOUT'});
		}
	});

	test('completed requests detach cancellation listeners', async () => {
		const controller = new AbortController();
		let added = 0; let removed = 0;
		const add = controller.signal.addEventListener.bind(controller.signal);
		const remove = controller.signal.removeEventListener.bind(controller.signal);
		controller.signal.addEventListener = (...args: Parameters<typeof add>) => {added++; add(...args);};
		controller.signal.removeEventListener = (...args: Parameters<typeof remove>) => {removed++; remove(...args);};
		await fetchText((async () => new Response('{}')) as typeof fetch, 'http://localhost', {signal:controller.signal}, 100);
		expect(added).toBe(removed);
		controller.abort();
	});
});
