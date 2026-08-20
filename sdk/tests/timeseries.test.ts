import { describe, expect, test } from 'bun:test';
import Lux from '../src';

describe('TSRANGE options', () => {
	test('serializes aggregation before COUNT for the direct API', async () => {
		let seen: Array<string | number> = [];
		const client = new Lux({ lazyConnect: true });
		client.call = async (_command: string, ...args: Array<string | number>) => {
			seen = args;
			return [];
		};

		await client.tsrange('cpu', '-', '+', {
			aggregation: { type: 'avg', bucketSize: 1_000 },
			count: 3,
		});

		expect(seen).toEqual(['cpu', '-', '+', 'AGGREGATION', 'avg', 1_000, 'COUNT', 3]);
		client.disconnect();
	});

	test('serializes COUNT through the timeseries namespace', async () => {
		let seen: Array<string | number> = [];
		const client = new Lux({ lazyConnect: true });
		client.call = async (_command: string, ...args: Array<string | number>) => {
			seen = args;
			return [];
		};

		await client.timeseries.range('cpu', 0, 10, { count: 2 });

		expect(seen).toEqual(['cpu', 0, 10, 'COUNT', 2]);
		client.disconnect();
	});

	test('preserves aggregation through the multi-range namespace', async () => {
		let seen: Array<string | number> = [];
		const client = new Lux({ lazyConnect: true });
		client.call = async (_command: string, ...args: Array<string | number>) => {
			seen = args;
			return [];
		};

		await client.timeseries.mrange('-', '+', 'host=web', {
			aggregation: { type: 'sum', bucketSize: 60_000 },
		});

		expect(seen).toEqual(['-', '+', 'AGGREGATION', 'sum', 60_000, 'FILTER', 'host=web']);
		client.disconnect();
	});
});
