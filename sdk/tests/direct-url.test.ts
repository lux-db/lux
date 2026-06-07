import { describe, expect, test } from 'bun:test';
import Lux from '../src';

describe('direct connection URLs', () => {
	test('accepts secure Lux URLs', () => {
		const client = new Lux('luxs://localhost:6380');
		client.disconnect();
		expect(client.options.tls).toBeTruthy();
	});

	test('accepts secure Redis-compatible URLs', () => {
		const client = new Lux('rediss://localhost:6380');
		client.disconnect();
		expect(client.options.tls).toBeTruthy();
	});
});
