import { describe, expect, test } from 'bun:test';
import { createProjectClient } from '../src/project';

type SeenRequest = { method: string; url: string; body?: unknown };

function clientWithResponses(responses: unknown[]) {
	const seen: SeenRequest[] = [];
	let index = 0;
	const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit) => {
		seen.push({
			method: init?.method ?? 'GET',
			url: String(input),
			body: init?.body ? JSON.parse(String(init.body)) : undefined,
		});
		return new Response(JSON.stringify(responses[index++] ?? {}), { status: 200 });
	};
	return {
		client: createProjectClient({
			url: 'http://localhost:3957/v1/project',
			key: 'lux_sec_test',
			fetch: fetchImpl as typeof fetch,
		}),
		seen,
	};
}

function replaceGlobal(name: 'Notification' | 'navigator', value: unknown): () => void {
	const descriptor = Object.getOwnPropertyDescriptor(globalThis, name);
	Object.defineProperty(globalThis, name, { configurable: true, value });
	return () => {
		if (descriptor) Object.defineProperty(globalThis, name, descriptor);
		else delete (globalThis as Record<string, unknown>)[name];
	};
}

describe('Lux push namespace', () => {
	test('device lifecycle and multi-subject delivery map to the project API', async () => {
		const { client, seen } = clientWithResponses([
			{ id: 'dev_1' },
			{ id: 'dev_2' },
			{ deleted: true },
			{ deleted: true },
			{ devices: [{ id: 'dev_1' }] },
			{ devices: [{ id: 'dev_2' }] },
			{ enqueued: 2 },
		]);

		expect(await client.push.register({ token: 'ios-token' })).toEqual({
			data: { id: 'dev_1' },
			error: null,
		});
		expect(
			await client.push.registerFor('user/one', {
				token: 'web-token',
				platform: 'web',
				app_id: 'dashboard',
				environment: 'sandbox',
			}),
		).toEqual({ data: { id: 'dev_2' }, error: null });
		expect(await client.push.unregister('device/one')).toEqual({
			data: { deleted: true },
			error: null,
		});
		expect(await client.push.unregisterByToken('ios-token')).toEqual({
			data: { deleted: true },
			error: null,
		});
		expect(await client.push.devices()).toEqual({
			data: [{ id: 'dev_1' }],
			error: null,
		});
		expect(await client.push.devices('user/one')).toEqual({
			data: [{ id: 'dev_2' }],
			error: null,
		});
		expect(await client.push.send(['user-1', 'user-2'], { body: 'hello' })).toEqual({
			data: { enqueued: 2 },
			error: null,
		});

		expect(seen).toEqual([
			{
				method: 'POST',
				url: 'http://localhost:3957/v1/project/push/devices',
				body: { token: 'ios-token', platform: 'ios', app_id: 'default', environment: '' },
			},
			{
				method: 'POST',
				url: 'http://localhost:3957/v1/project/push/devices',
				body: {
					subject_id: 'user/one',
					token: 'web-token',
					platform: 'web',
					app_id: 'dashboard',
					environment: 'sandbox',
				},
			},
			{
				method: 'DELETE',
				url: 'http://localhost:3957/v1/project/push/devices/device%2Fone',
				body: undefined,
			},
			{
				method: 'DELETE',
				url: 'http://localhost:3957/v1/project/push/devices',
				body: { token: 'ios-token' },
			},
			{
				method: 'GET',
				url: 'http://localhost:3957/v1/project/push/devices',
				body: undefined,
			},
			{
				method: 'GET',
				url: 'http://localhost:3957/v1/project/push/devices?subject_id=user%2Fone',
				body: undefined,
			},
			{
				method: 'POST',
				url: 'http://localhost:3957/v1/project/push/send',
				body: { subject_ids: ['user-1', 'user-2'], notification: { body: 'hello' } },
			},
		]);
	});

	test('device and VAPID reads preserve errors and normalize missing payloads', async () => {
		const failingFetch = async () =>
			new Response(JSON.stringify({ error: { code: 'FORBIDDEN', message: 'no access' } }), {
				status: 403,
			});
		const failing = createProjectClient({
			url: 'http://localhost:3957/v1/project',
			key: 'lux_pub_test',
			fetch: failingFetch as typeof fetch,
		});
		expect((await failing.push.devices()).error?.code).toBe('LUX_PROJECT_REQUEST_ERROR');
		expect((await failing.push.getVapidPublicKey()).error?.code).toBe(
			'LUX_PROJECT_REQUEST_ERROR',
		);

		const { client } = clientWithResponses([{}, {}, { public_key: 'vapid-key' }]);
		expect(await client.push.devices()).toEqual({ data: [], error: null });
		expect(await client.push.getVapidPublicKey()).toEqual({ data: '', error: null });
		expect(await client.push.getVapidPublicKey()).toEqual({ data: 'vapid-key', error: null });
	});

	test('web push reports unavailable configuration and denied permission', async () => {
		const { client } = clientWithResponses([{}]);
		expect((await client.push.subscribeWebPush()).error?.code).toBe('LUX_PUSH_NO_VAPID');

		const restoreNotification = replaceGlobal('Notification', {
			requestPermission: async () => 'denied',
		});
		const restoreNavigator = replaceGlobal('navigator', {
			serviceWorker: { ready: Promise.resolve({}) },
		});
		try {
			expect(
				(await client.push.subscribeWebPush({ vapidPublicKey: 'AQID' })).error?.code,
			).toBe('LUX_PUSH_PERMISSION_DENIED');
		} finally {
			restoreNavigator();
			restoreNotification();
		}
	});

	test('web push subscribes with decoded VAPID bytes and returns provider failures', async () => {
		const { client, seen } = clientWithResponses([{ id: 'web_1' }]);
		let subscriptionOptions: PushSubscriptionOptionsInit | undefined;
		const registration = {
			pushManager: {
				subscribe: async (options: PushSubscriptionOptionsInit) => {
					subscriptionOptions = options;
					return { endpoint: 'https://push.example/subscription' };
				},
			},
		};
		const restoreNotification = replaceGlobal('Notification', {
			requestPermission: async () => 'granted',
		});
		const restoreNavigator = replaceGlobal('navigator', { serviceWorker: { ready: registration } });
		try {
			expect(
				await client.push.subscribeWebPush({
					vapidPublicKey: 'AQID',
					serviceWorker: registration as unknown as ServiceWorkerRegistration,
				}),
			).toEqual({ data: { id: 'web_1' }, error: null });
			expect(Array.from(subscriptionOptions?.applicationServerKey as Uint8Array)).toEqual([1, 2, 3]);
			expect(seen[0]?.body).toEqual({
				token: JSON.stringify({ endpoint: 'https://push.example/subscription' }),
				platform: 'web',
				app_id: 'default',
				environment: '',
			});

			registration.pushManager.subscribe = async () => {
				throw new Error('provider unavailable');
			};
			const failed = await client.push.subscribeWebPush({
				vapidPublicKey: 'AQID',
				serviceWorker: registration as unknown as ServiceWorkerRegistration,
			});
			expect(failed.error?.code).toBe('LUX_PUSH_SUBSCRIBE_ERROR');
			expect(failed.error?.details).toMatchObject({ message: 'provider unavailable' });
		} finally {
			restoreNavigator();
			restoreNotification();
		}
	});
});
