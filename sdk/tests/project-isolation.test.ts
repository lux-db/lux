import { describe, expect, test } from 'bun:test';
import { createBrowserClient } from '../src/browser';
import { createServerClient } from '../src/ssr';
import { LuxAuthClient } from '../src/auth';
import { projectStorageKey } from '../src/utils';
import type { LuxBrowserCookieMethods } from '../src/cookies';

function cookieJar(): LuxBrowserCookieMethods {
	const values = new Map<string, string>();
	return {
		getAll: () => [...values].map(([name, value]) => ({ name, value })),
		setAll: (cookies) => {
			for (const { name, value, options } of cookies) {
				if (options.maxAge === 0) values.delete(name);
				else values.set(name, value);
			}
		},
	};
}

const session = {
	access_token: 'project-a-session',
	refresh_token: 'project-a-refresh',
	expires_in: 3600,
	token_type: 'bearer',
	user: { id: 'project-a-user', email: 'project-a@example.test' },
};

describe('project isolation', () => {
	test('browser helper rejects known secret-key formats', () => {
		for (const key of ['lux_sec_fixture', 'lux_sk_fixture']) {
			expect(() => createBrowserClient('http://localhost', key)).toThrow('publishable key');
		}
	});
	test('different cookie adapters or deadlines never inherit cached configuration', () => {
		const options = { isSingleton:true, cookies:cookieJar(), requestTimeoutMs:100,
			auth:{autoRefreshToken:false} };
		const first = createBrowserClient('http://localhost:41009', 'public', options);
		expect(createBrowserClient('http://localhost:41009', 'public', options)).toBe(first);
		expect(createBrowserClient('http://localhost:41009', 'public', {...options,cookies:cookieJar()})).not.toBe(first);
		expect(createBrowserClient('http://localhost:41009', 'public', {...options,requestTimeoutMs:200})).not.toBe(first);
	});
	test('session names preserve distinct ports and paths, but ignore trailing slashes', () => {
		const name = (url: string) => projectStorageKey(url, 'lux-auth-session');
		expect(name('https://example.test/v1/a/')).toBe(name('https://example.test/v1/a'));
		expect(name('https://example.test/v1/a')).not.toBe(name('https://example.test/v1/b'));
		expect(name('http://localhost:41001')).not.toBe(name('http://localhost:41002'));
		expect(name('https://example.test/a%2Fb')).not.toBe(name('https://example.test/a/b'));
	});

	test('persisted auth clients do not read or clear another project session', async () => {
		const values = new Map<string, string>();
		const storage = {
			getItem: (key: string) => values.get(key) ?? null,
			setItem: (key: string, value: string) => { values.set(key, value); },
			removeItem: (key: string) => { values.delete(key); },
		};
		const options = { storage, persistSession: true, autoRefreshToken: false };
		const first = new LuxAuthClient({ ...options, httpUrl: 'https://example.test/v1/a' });
		const second = new LuxAuthClient({ ...options, httpUrl: 'https://example.test/v1/b' });
		await first.setSession(session);
		expect((await second.getSession()).data?.session).toBeNull();
		await second.clearSession();
		expect((await first.getSession()).data?.session?.access_token).toBe(session.access_token);
	});

	test('explicit project cookie names still work across browser and SSR', async () => {
		const cookies = cookieJar();
		const auth = { storageKey: 'my-project-session', autoRefreshToken: false };
		const server = createServerClient('http://localhost:41005', 'lux_pub_a', { cookies, auth });
		await server.auth.setSession(session);
		const browser = createBrowserClient('http://localhost:41005', 'lux_pub_a', {
			cookies, auth, isSingleton: false,
		});
		expect((await browser.auth.getSession()).data?.session?.access_token).toBe(session.access_token);
		expect((await cookies.getAll())?.map(({ name }) => name)).toEqual(['my-project-session']);
	});

	test('browser singleton belongs to its URL and project key', () => {
		const options = {
			isSingleton: true,
			auth: { persistSession: false, autoRefreshToken: false, storage: null },
		};
		const first = createBrowserClient('http://localhost:41001', 'lux_pub_a', options);
		const second = createBrowserClient('http://localhost:41002', 'lux_pub_b', options);
		const rotated = createBrowserClient('http://localhost:41001', 'lux_pub_rotated', options);
		expect(second).not.toBe(first);
		expect(rotated).not.toBe(first);
		expect(createBrowserClient('http://localhost:41001', 'lux_pub_a', options)).toBe(first);
	});

	test('default cookies isolate projects while sharing browser and SSR sessions', async () => {
		const cookies = cookieJar();
		const first = createServerClient('http://localhost:41003', 'lux_pub_a', { cookies });
		await first.auth.setSession(session);
		const second = createServerClient('http://localhost:41004', 'lux_pub_b', { cookies });
		expect((await second.auth.getSession()).data?.session).toBeNull();
		const browser = createBrowserClient('http://localhost:41003', 'lux_pub_a', {
			cookies,
			isSingleton: false,
			auth: { autoRefreshToken: false },
		});
		expect((await browser.auth.getSession()).data?.session?.access_token)
			.toBe(session.access_token);
		await second.auth.clearSession();
		expect((await first.auth.getSession()).data?.session?.access_token)
			.toBe(session.access_token);
	});
});
