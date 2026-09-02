import { describe, expect, test } from 'bun:test';
import Lux, { createAuthClient, createClient } from '../src';

type DirectCall = [command: string, ...args: unknown[]];

function mockClient(responses: unknown[]) {
	const client = new Lux({ lazyConnect: true });
	const calls: DirectCall[] = [];
	let responseIndex = 0;
	client.call = async (command: string, ...args: unknown[]) => {
		calls.push([command, ...args]);
		const response = responses[responseIndex++];
		if (response instanceof Error) throw response;
		return response;
	};
	return { calls, client };
}

describe('Lux direct client', () => {
	test('decodes table rows through one cached schema lookup', async () => {
		const { calls, client } = mockClient([
			[
				['id', '42', 'payload', '{"ok":true}', 'tags', '[1,2]', 'broken', '{'],
				'not-a-row',
				['id', 'external-id', 'payload', ''],
			],
			['id INT', 'payload JSON', 'tags ARRAY', 'broken JSON'],
			[['id', '7', 'payload', '{"cached":true}']],
			[['id', '8']],
			null,
		]);

		expect(await client._tselect(['*', 'FROM', 'documents'])).toEqual([
			{ id: 42, payload: { ok: true }, tags: [1, 2], broken: '{' },
			{ id: 'external-id', payload: '' },
		]);
		expect(await client._tselect(['*', 'FROM', 'documents'])).toEqual([
			{ id: 7, payload: { cached: true } },
		]);
		expect(await client._tselect(['*'])).toEqual([{ id: 8 }]);
		expect(await client._tselect(['*', 'FROM', 'documents'])).toEqual([]);
		expect(calls.filter(([command]) => command === 'TSCHEMA')).toEqual([
			['TSCHEMA', 'documents'],
		]);
		expect(client.table('documents')).toBeDefined();
		client.disconnect();
	});

	test('serializes and decodes the direct vector surface', async () => {
		const { calls, client } = mockClient([
			'OK',
			'OK',
			null,
			['2', '1.25', '-2.5', '{"kind":"document"}'],
			['1', '3', '{'],
			null,
			[
				['doc:1', '0.9', '{"tag":"a"}'],
				['doc:2', '0.5', 'not-json'],
			],
			2,
		]);

		expect(await client.vset('doc:1', [1, 2], { metadata: { tag: 'a' }, ex: 30 })).toBe('OK');
		expect(await client.vset('doc:2', [3], { px: 250 })).toBe('OK');
		expect(await client.vget('missing')).toBeNull();
		expect(await client.vget('doc:1')).toEqual({
			dims: 2,
			vector: [1.25, -2.5],
			metadata: { kind: 'document' },
		});
		expect(await client.vget('doc:2')).toEqual({ dims: 1, vector: [3] });
		expect(await client.vsearch([1, 0], { k: 2 })).toEqual([]);
		expect(
			await client.vsearch([1, 0], {
				k: 2,
				filter: { key: 'kind', value: 'document' },
				meta: true,
			}),
		).toEqual([
			{ key: 'doc:1', similarity: 0.9, metadata: { tag: 'a' } },
			{ key: 'doc:2', similarity: 0.5, metadata: { _raw: 'not-json' } },
		]);
		expect(await client.vcard()).toBe(2);

		expect(calls).toEqual([
			['VSET', 'doc:1', 2, 1, 2, 'META', '{"tag":"a"}', 'EX', 30],
			['VSET', 'doc:2', 1, 3, 'PX', 250],
			['VGET', 'missing'],
			['VGET', 'doc:1'],
			['VGET', 'doc:2'],
			['VSEARCH', 2, 1, 0, 'K', 2],
			['VSEARCH', 2, 1, 0, 'K', 2, 'FILTER', 'kind', 'document', 'META'],
			['VCARD'],
		]);
		client.disconnect();
	});

	test('serializes and decodes the direct time-series surface', async () => {
		const { calls, client } = mockClient([
			100,
			101,
			'OK',
			null,
			['100', '1.5'],
			null,
			[['100', '1.5'], ['200', '2.5']],
			null,
			[['cpu', [['host', 'web']], [['100', '1.5']]]],
			null,
			['totalSamples', 3, 'labels', [['host', 'web']]],
		]);

		expect(
			await client.tsadd('cpu', '*', 1.5, {
				retention: 60_000,
				labels: { host: 'web', region: 'use1' },
			}),
		).toBe(100);
		expect(await client.tsadd('cpu', 100, 2.5)).toBe(101);
		expect(await client.tsmadd(['cpu', '*', 1], ['memory', 100, 2])).toBe('OK');
		expect(await client.tsget('missing')).toBeNull();
		expect(await client.tsget('cpu')).toEqual({ timestamp: 100, value: 1.5 });
		expect(await client.tsrange('missing', '-', '+')).toEqual([]);
		expect(
			await client.tsrange('cpu', 0, '+', {
				aggregation: { type: 'avg', bucketSize: 1_000 },
				count: 2,
			}),
		).toEqual([
			{ timestamp: 100, value: 1.5 },
			{ timestamp: 200, value: 2.5 },
		]);
		expect(await client.tsmrange('-', '+', 'host=none')).toEqual([]);
		expect(
			await client.tsmrange(0, 200, 'host=web', {
				aggregation: { type: 'sum', bucketSize: 100 },
			}),
		).toEqual([
			{ key: 'cpu', labels: { host: 'web' }, samples: [{ timestamp: 100, value: 1.5 }] },
		]);
		expect(await client.tsinfo('missing')).toEqual({});
		expect(await client.tsinfo('cpu')).toEqual({
			totalSamples: 3,
			labels: { host: 'web' },
		});

		expect(calls).toEqual([
			['TSADD', 'cpu', '*', 1.5, 'RETENTION', 60_000, 'LABELS', 'host', 'web', 'region', 'use1'],
			['TSADD', 'cpu', 100, 2.5],
			['TSMADD', 'cpu', '*', 1, 'memory', 100, 2],
			['TSGET', 'missing'],
			['TSGET', 'cpu'],
			['TSRANGE', 'missing', '-', '+'],
			['TSRANGE', 'cpu', 0, '+', 'AGGREGATION', 'avg', 1_000, 'COUNT', 2],
			['TSMRANGE', '-', '+', 'FILTER', 'host=none'],
			['TSMRANGE', 0, 200, 'AGGREGATION', 'sum', 100, 'FILTER', 'host=web'],
			['TSINFO', 'missing'],
			['TSINFO', 'cpu'],
		]);
		client.disconnect();
	});

	test('routes vector and time-series namespaces through the direct client', async () => {
		const { calls, client } = mockClient([
			'OK',
			['1', '2'],
			[['doc:1', '0.8', '{"kind":"note"}']],
			1,
			100,
			['100', '2'],
			[['100', '2']],
			[['cpu', [], [['100', '2']]]],
			['labels', []],
		]);

		expect(await client.vectors.set('doc:1', [2], { kind: 'note' })).toBe('OK');
		expect(await client.vectors.get('doc:1')).toEqual({ dims: 1, vector: [2] });
		expect(await client.vectors.search([2], { topK: 1 })).toEqual([
			{ key: 'doc:1', similarity: 0.8, metadata: { kind: 'note' } },
		]);
		expect(await client.vectors.count()).toBe(1);
		expect(await client.timeseries.add('cpu', 2, { timestamp: 100 })).toBe(100);
		expect(await client.timeseries.get('cpu')).toEqual({ timestamp: 100, value: 2 });
		expect(await client.timeseries.range('cpu', 0, 100)).toEqual([
			{ timestamp: 100, value: 2 },
		]);
		expect(await client.timeseries.mrange(0, 100, 'host=web')).toEqual([
			{ key: 'cpu', labels: {}, samples: [{ timestamp: 100, value: 2 }] },
		]);
		expect(await client.timeseries.info('cpu')).toEqual({ labels: {} });
		expect(calls[0]).toEqual(['VSET', 'doc:1', 1, 2, 'META', '{"kind":"note"}']);
		client.disconnect();
	});

	test('delivers key subscription frames and preserves unrelated replies', () => {
		const client = new Lux({ lazyConnect: true });
		const events: unknown[] = [];
		const calls: unknown[][] = [];
		const forwarded: unknown[] = [];
		let disconnected = false;
		const dataHandler = {
			returnReply(reply: unknown) {
				forwarded.push(reply);
				return 'forwarded';
			},
		};
		const subscriptionClient = {
			_dataHandler: dataHandler,
			on: () => subscriptionClient,
			call: (...args: unknown[]) => calls.push(args),
			disconnect: () => { disconnected = true; },
		};
		client.duplicate = () => subscriptionClient as never;

		const subscription = client.ksub(['user:*'], (event) => events.push(event));
		expect(calls).toEqual([['KSUB', 'user:*']]);
		expect(dataHandler.returnReply(['kmessage', 'user:*', 'user:1', 'set'])).toBeUndefined();
		expect(events).toEqual([{ pattern: 'user:*', key: 'user:1', operation: 'set' }]);
		expect(dataHandler.returnReply(['pong'])).toBe('forwarded');
		expect(forwarded).toEqual([['pong']]);
		subscription.unsubscribe();
		expect(disconnected).toBeTrue();
		client.disconnect();
	});

	test('recovers key subscription events from ioredis queue errors', () => {
		const client = new Lux({ lazyConnect: true });
		const events: unknown[] = [];
		const emitted: unknown[][] = [];
		const subscriptionClient = {
			on: () => subscriptionClient,
			call: () => undefined,
			disconnect: () => undefined,
			emit: (event: string, ...args: unknown[]) => {
				emitted.push([event, ...args]);
				return false;
			},
		};
		client.duplicate = () => subscriptionClient as never;
		client.ksub(['order:*'], (event) => events.push(event));

		const recovered = subscriptionClient.emit(
			'error',
			new Error('Command queue state error. Last reply: kmessage,order:*,order:1,del'),
		);
		expect(recovered).toBeTrue();
		expect(events).toEqual([{ pattern: 'order:*', key: 'order:1', operation: 'del' }]);
		expect(subscriptionClient.emit('ready')).toBeFalse();
		expect(emitted).toEqual([['ready']]);
		client.disconnect();
	});

	test('selects project, direct, and auth client factories by signature', async () => {
		const project = createClient('http://localhost:3957/v1/project', 'lux_pub_test');
		expect(project.constructor.name).toBe('LuxProjectClient');

		const direct = createClient({ lazyConnect: true });
		expect(direct).toBeInstanceOf(Lux);
		const calls: unknown[][] = [];
		direct.call = async (...args: unknown[]) => {
			calls.push(args);
			return 'OK';
		};
		expect(await (direct.auth as unknown as (password: string) => Promise<string>)('password')).toBe('OK');
		expect(calls).toEqual([['AUTH', 'password']]);
		expect(createAuthClient({ persistSession: false })).toBeDefined();
		direct.disconnect();
	});
});
