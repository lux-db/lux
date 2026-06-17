import { describe, expect, test } from 'bun:test';
import { createBrowserClient } from '../src/browser';
import { createServerClient } from '../src/ssr';
import { createBrowserClient as rootCreateBrowserClient, createServerClient as rootCreateServerClient } from '../src';

describe('browser and SSR clients', () => {
	test('browser and SSR helpers are exported from package root', () => {
		expect(rootCreateBrowserClient).toBe(createBrowserClient);
		expect(rootCreateServerClient).toBe(createServerClient);
	});

	test('browser client persists sessions by default', async () => {
		const storage = new Map<string, string>();
		const client = createBrowserClient('http://localhost:3957/v1/project', 'lux_pub_test', {
			auth: {
				autoRefreshToken: false,
				storage: {
					getItem: (key) => storage.get(key) ?? null,
					setItem: (key, value) => storage.set(key, value),
					removeItem: (key) => storage.delete(key),
				},
			},
		});

		await client.auth.setSession({
			access_token: 'access-token',
			refresh_token: 'refresh-token',
			expires_in: 3600,
			token_type: 'bearer',
			user: { id: 'usr_123', email: 'user@example.com' },
		});

		expect(storage.has('lux.auth.session')).toBe(true);
	});

	test('server client stores sessions through cookie methods', async () => {
		const cookies = new Map<string, string>();
		const client = createServerClient('http://localhost:3957/v1/project', 'lux_pub_test', {
			cookies: {
				get: (name) => cookies.get(name),
				set: (name, value) => cookies.set(name, value),
				remove: (name) => cookies.delete(name),
			},
		});

		await client.auth.setSession({
			access_token: 'access-token',
			refresh_token: 'refresh-token',
			expires_in: 3600,
			token_type: 'bearer',
			user: { id: 'usr_123', email: 'user@example.com' },
		});
		expect(cookies.has('lux-auth-session')).toBe(true);

		const restored = createServerClient('http://localhost:3957/v1/project', 'lux_pub_test', {
			cookies: {
				get: (name) => cookies.get(name),
				set: (name, value) => cookies.set(name, value),
				remove: (name) => cookies.delete(name),
			},
		});

		expect((await restored.auth.getSession()).data?.session?.access_token).toBe('access-token');

		await restored.auth.clearSession();
		expect(cookies.has('lux-auth-session')).toBe(false);
	});

	test('server client works without cookies (stateless backend)', async () => {
		// A backend with the secret key has no cookies to plumb; createServerClient
		// must not require them.
		const client = createServerClient('http://localhost:3957/v1/project', 'lux_sec_test');

		// setSession is in-memory only (no persistence), but must not throw.
		await client.auth.setSession({
			access_token: 'access-token',
			refresh_token: 'refresh-token',
			expires_in: 3600,
			token_type: 'bearer',
			user: { id: 'usr_123', email: 'user@example.com' },
		});
		expect((await client.auth.getSession()).data?.session?.access_token).toBe('access-token');

		// A fresh stateless client has nothing persisted to restore.
		const fresh = createServerClient('http://localhost:3957/v1/project', 'lux_sec_test');
		expect((await fresh.auth.getSession()).data?.session).toBeNull();
	});
});
