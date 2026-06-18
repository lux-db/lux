import { describe, expect, test } from 'bun:test';
import { createProjectClient } from '../src/project';

describe('Lux storage client', () => {
	test('creates bucket clients without bucket management calls', async () => {
		const seen: Array<{ url: string; method?: string; body?: any }> = [];
		const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit) => {
			seen.push({
				url: String(input),
				method: init?.method,
				body: init?.body ? JSON.parse(String(init.body)) : undefined,
			});
			return new Response(JSON.stringify({ data: null }), { status: 200 });
		};
		const client = createProjectClient({
			url: 'https://api.luxdb.dev/v1/project',
			key: 'lux_sec_test',
			fetch: fetchImpl as typeof fetch,
		});

		expect(client.storage.bucket('avatars').name).toBe('avatars');
		expect('createBucket' in client.storage).toBe(false);
		expect('listBuckets' in client.storage).toBe(false);
		expect('updateBucket' in client.storage).toBe(false);
		expect('deleteBucket' in client.storage).toBe(false);
		expect(seen).toEqual([]);
	});

	test('upload signs, puts to R2, then completes metadata', async () => {
		const calls: Array<{ url: string; method?: string; body?: any; headers?: any }> = [];
		const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			calls.push({
				url,
				method: init?.method,
				body: typeof init?.body === 'string' ? JSON.parse(init.body) : init?.body ? 'bytes' : undefined,
				headers: init?.headers,
			});
			if (url === 'https://r2.example.test/upload') {
				return new Response('', { status: 200 });
			}
			if (url.endsWith('/storage/object/upload/sign/avatars/users/1.png')) {
				return new Response(JSON.stringify({ data: { url: 'https://r2.example.test/upload' } }), { status: 200 });
			}
			return new Response(
				JSON.stringify({
					data: {
						id: 'obj-1',
						path: 'users/1.png',
						size: 4,
						type: 'image/png',
						url: null,
					},
				}),
				{ status: 200 },
			);
		};
		const client = createProjectClient({
			url: 'https://api.luxdb.dev/v1/project',
			key: 'lux_pub_test',
			fetch: fetchImpl as typeof fetch,
			auth: { authToken: 'user-jwt' },
		});

		const result = await client.storage.bucket('avatars').upload('users/1.png', new Blob(['test']), {
			contentType: 'image/png',
			upsert: true,
			metadata: { user_id: '1' },
		});

		expect(result.error).toBeNull();
		expect(result.data?.path).toBe('users/1.png');
		expect(calls.map((call) => [call.method, call.url])).toEqual([
			['POST', 'https://api.luxdb.dev/v1/project/storage/object/upload/sign/avatars/users/1.png'],
			['PUT', 'https://r2.example.test/upload'],
			['POST', 'https://api.luxdb.dev/v1/project/storage/object/upload/complete/avatars/users/1.png'],
		]);
	});

	test('url resolves the active R2 custom-domain URL through Lux', async () => {
		const calls: string[] = [];
		const client = createProjectClient({
			url: 'https://api.luxdb.dev/v1/project',
			key: 'lux_pub_test',
			fetch: (async (input: RequestInfo | URL) => {
				calls.push(String(input));
				return new Response(JSON.stringify({ data: { url: 'https://s-test.storage.luxdb.dev/albums/one.png' } }), {
					status: 200,
				});
			}) as typeof fetch,
		});

		const result = await client.storage.bucket('album-covers').url('albums/one.png');

		expect(result).toEqual({
			data: {
				url: 'https://s-test.storage.luxdb.dev/albums/one.png',
			},
			error: null,
		});
		expect(calls).toEqual(['https://api.luxdb.dev/v1/project/storage/object/url/album-covers/albums/one.png']);
	});

	test('download signs and fetches the temporary URL', async () => {
		const calls: string[] = [];
		const fetchImpl = async (input: RequestInfo | URL) => {
			const url = String(input);
			calls.push(url);
			if (url.includes('/storage/object/sign/')) {
				return new Response(JSON.stringify({ data: { url: 'https://r2.example.test/get', expires_in: 300 } }), {
					status: 200,
				});
			}
			return new Response('file-bytes', { status: 200 });
		};
		const client = createProjectClient({
			url: 'https://api.luxdb.dev/v1/project',
			key: 'lux_pub_test',
			fetch: fetchImpl as typeof fetch,
		});

		const result = await client.storage.bucket('avatars').download('user.png');

		expect(result.error).toBeNull();
		expect(await result.data?.text()).toBe('file-bytes');
		expect(calls).toEqual([
			'https://api.luxdb.dev/v1/project/storage/object/sign/avatars/user.png',
			'https://r2.example.test/get',
		]);
	});
});
