import { describe, expect, test } from 'bun:test';
import { createBrowserClient } from '../src/browser';
import { createServerClient } from '../src/ssr';
import { createBrowserClient as rootCreateBrowserClient, createServerClient as rootCreateServerClient } from '../src';
import {
	createBrowserClient as browserRootCreateBrowserClient,
	createServerClient as browserRootCreateServerClient,
} from '../src/index.browser';
import type { LuxBrowserCookieMethods, LuxCookieOptions } from '../src/cookies';

describe('browser and SSR clients', () => {
	test('browser and SSR helpers are exported from package root', () => {
		expect(rootCreateBrowserClient).toBe(createBrowserClient);
		expect(rootCreateServerClient).toBe(createServerClient);
		expect(browserRootCreateBrowserClient).toBe(createBrowserClient);
		expect(browserRootCreateServerClient).toBe(createServerClient);
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

	test('browser client accepts getAll and setAll cookie methods', async () => {
		const cookies = new Map<string, string>();
		let optionsWereProvided = false;
		const client = createBrowserClient(
			'http://localhost:3957/v1/project',
			'lux_pub_test',
			{
				isSingleton: false,
				auth: { autoRefreshToken: false },
				cookies: cookieMethods(cookies, (options) => {
					optionsWereProvided = options.path === '/';
				}),
			},
		);

		await client.auth.setSession({
			access_token: 'access-token',
			refresh_token: 'refresh-token',
			expires_in: 3600,
			token_type: 'bearer',
			user: { id: 'usr_browser', email: 'browser@example.com' },
		});

		expect(cookies.has('lux-auth-session')).toBe(true);
		expect(optionsWereProvided).toBe(true);
		expect((await client.auth.getSession()).data?.session?.user.id).toBe('usr_browser');
	});

	test('server client stores sessions through cookie methods', async () => {
		const cookies = new Map<string, string>();
		let writtenOptions: Record<string, unknown> | undefined;
		let writtenHeaders: Record<string, string> | undefined;
		const client = createServerClient('http://localhost:3957/v1/project', 'lux_pub_test', {
			cookies: cookieMethods(cookies, (options, headers) => {
				writtenOptions = options;
				writtenHeaders = headers;
			}),
		});

		await client.auth.setSession({
			access_token: 'access-token',
			refresh_token: 'refresh-token',
			expires_in: 3600,
			token_type: 'bearer',
			user: { id: 'usr_123', email: 'user@example.com' },
		});
		expect(cookies.has('lux-auth-session')).toBe(true);
		expect(writtenOptions).toMatchObject({
			httpOnly: false,
			path: '/',
			sameSite: 'lax',
		});
		expect(writtenHeaders).toMatchObject({
			'Cache-Control': 'private, no-cache, no-store, must-revalidate, max-age=0',
			Expires: '0',
			Pragma: 'no-cache',
		});

		const restored = createServerClient('http://localhost:3957/v1/project', 'lux_pub_test', {
			cookies: cookieMethods(cookies),
		});

		expect((await restored.auth.getSession()).data?.session?.access_token).toBe('access-token');

		await restored.auth.clearSession();
		expect(cookies.has('lux-auth-session')).toBe(false);
	});

	test('server client chunks large session cookies and restores them', async () => {
		const cookies = new Map<string, string>();
		const client = createServerClient('http://localhost:3957/v1/project', 'lux_pub_test', {
			cookies: cookieMethods(cookies),
		});
		const largeAccessToken = 'access-token-'.repeat(400);

		await client.auth.setSession({
			access_token: largeAccessToken,
			refresh_token: 'refresh-token',
			expires_in: 3600,
			token_type: 'bearer',
			user: { id: 'usr_chunked', email: 'chunked@example.com' },
		});

		expect(cookies.has('lux-auth-session')).toBe(false);
		expect(cookies.has('lux-auth-session.0')).toBe(true);
		expect(cookies.has('lux-auth-session.1')).toBe(true);
		for (const [name, value] of cookies) {
			if (name.startsWith('lux-auth-session.')) {
				expect(value.length).toBeLessThanOrEqual(3180);
			}
		}

		const restored = createServerClient('http://localhost:3957/v1/project', 'lux_pub_test', {
			cookies: cookieMethods(cookies),
		});
		expect((await restored.auth.getSession()).data?.session?.access_token)
			.toBe(largeAccessToken);
	});

	test('session cookie updates remove stale chunks', async () => {
		const cookies = new Map<string, string>();
		const client = createServerClient('http://localhost:3957/v1/project', 'lux_pub_test', {
			cookies: cookieMethods(cookies),
		});

		await client.auth.setSession({
			access_token: 'large-'.repeat(1200),
			refresh_token: 'refresh-token',
			expires_in: 3600,
			token_type: 'bearer',
			user: { id: 'usr_chunks', email: 'chunks@example.com' },
		});
		expect(cookies.has('lux-auth-session.2')).toBe(true);

		await client.auth.setSession({
			access_token: 'small-access-token',
			refresh_token: 'refresh-token',
			expires_in: 3600,
			token_type: 'bearer',
			user: { id: 'usr_chunks', email: 'chunks@example.com' },
		});

		expect(cookies.has('lux-auth-session')).toBe(true);
		expect([...cookies.keys()].some((name) => name.startsWith('lux-auth-session.')))
			.toBe(false);
		expect((await client.auth.getSession()).data?.session?.access_token)
			.toBe('small-access-token');
	});

	test('clearing a session removes every cookie chunk', async () => {
		const cookies = new Map<string, string>();
		const client = createServerClient('http://localhost:3957/v1/project', 'lux_pub_test', {
			cookies: cookieMethods(cookies),
		});

		await client.auth.setSession({
			access_token: 'large-'.repeat(1200),
			refresh_token: 'refresh-token',
			expires_in: 3600,
			token_type: 'bearer',
			user: { id: 'usr_clear_chunks', email: 'clear-chunks@example.com' },
		});
		expect([...cookies.keys()].some((name) => name.startsWith('lux-auth-session.')))
			.toBe(true);

		await client.auth.clearSession();

		expect([...cookies.keys()].some((name) => name === 'lux-auth-session' ||
			name.startsWith('lux-auth-session.'))).toBe(false);
	});

	test('server client can read cookies when setAll is unavailable', async () => {
		const cookies = new Map<string, string>();
		const writer = createServerClient('http://localhost:3957/v1/project', 'lux_pub_test', {
			cookies: cookieMethods(cookies),
		});
		await writer.auth.setSession({
			access_token: 'read-only-access-token',
			refresh_token: 'read-only-refresh-token',
			expires_in: 3600,
			token_type: 'bearer',
			user: { id: 'usr_read_only', email: 'readonly@example.com' },
		});

		const reader = createServerClient('http://localhost:3957/v1/project', 'lux_pub_test', {
			cookies: {
				getAll: () => [...cookies].map(([name, value]) => ({ name, value })),
			},
		});

		expect((await reader.auth.getSession()).data?.session?.access_token)
			.toBe('read-only-access-token');
	});

	test('browser and SSR clients share the default session cookie', async () => {
		const cookies = new Map<string, string>();
		const server = createServerClient('http://localhost:3957/v1/project', 'lux_pub_test', {
			cookies: cookieMethods(cookies),
		});

		await server.auth.setSession({
			access_token: 'server-access-token',
			refresh_token: 'server-refresh-token',
			expires_in: 3600,
			token_type: 'bearer',
			user: { id: 'usr_shared', email: 'shared@example.com' },
		});

		const originalDocument = (globalThis as any).document;
		const browserCookies = new Map<string, string>([
			['lux-auth-session', cookies.get('lux-auth-session')!],
		]);
		(globalThis as any).document = createCookieDocument(browserCookies);

		try {
			const browser = createBrowserClient(
				'http://localhost:3957/v1/project',
				'lux_pub_test',
				{ isSingleton: false, auth: { autoRefreshToken: false } },
			);

			expect((await browser.auth.getSession()).data?.session?.access_token)
				.toBe('server-access-token');

			await browser.auth.setSession({
				access_token: 'browser-access-token',
				refresh_token: 'browser-refresh-token',
				expires_in: 3600,
				token_type: 'bearer',
				user: { id: 'usr_shared', email: 'shared@example.com' },
			});

			cookies.set('lux-auth-session', browserCookies.get('lux-auth-session')!);
			const nextServer = createServerClient(
				'http://localhost:3957/v1/project',
				'lux_pub_test',
				{
					cookies: cookieMethods(cookies),
				},
			);
			expect((await nextServer.auth.getSession()).data?.session?.access_token)
				.toBe('browser-access-token');
		} finally {
			if (originalDocument === undefined) {
				delete (globalThis as any).document;
			} else {
				(globalThis as any).document = originalDocument;
			}
		}
	});

	test('browser auth recovers cookie changes when the document becomes visible', async () => {
		const originalDocument = (globalThis as any).document;
		const browserCookies = new Map<string, string>();
		const document = createCookieDocument(browserCookies);
		(globalThis as any).document = document;

		try {
			const browser = createBrowserClient(
				'http://localhost:3957/v1/project',
				'lux_pub_test',
				{ isSingleton: false, auth: { autoRefreshToken: false } },
			);
			const events: string[] = [];
			const subscription = browser.auth.onAuthStateChange((event, session) => {
				events.push(`${event}:${session?.access_token ?? 'none'}`);
			});

			await waitFor(() => events.includes('INITIAL_SESSION:none'));

			browserCookies.set('lux-auth-session', encodeSessionCookie({
				access_token: 'ssr-access-token',
				refresh_token: 'ssr-refresh-token',
				expires_in: 3600,
				token_type: 'bearer',
				user: { id: 'usr_ssr', email: 'ssr@example.com' },
			}));
			document.dispatchVisibilityChange('visible');
			await waitFor(() => events.includes('SIGNED_IN:ssr-access-token'));

			browserCookies.delete('lux-auth-session');
			document.dispatchVisibilityChange('visible');
			await waitFor(() => events.includes('SIGNED_OUT:none'));

			subscription.unsubscribe();
		} finally {
			if (originalDocument === undefined) {
				delete (globalThis as any).document;
			} else {
				(globalThis as any).document = originalDocument;
			}
		}
	});

	test('browser auth broadcasts cookie changes from client load', async () => {
		const originalDocument = (globalThis as any).document;
		const originalBroadcastChannel = (globalThis as any).BroadcastChannel;
		const browserCookies = new Map<string, string>();
		const channels = new Map<string, Set<FakeBroadcastChannel>>();
		const document = createCookieDocument(browserCookies);
		(globalThis as any).document = document;
		(globalThis as any).BroadcastChannel = class extends FakeBroadcastChannel {
			constructor(name: string) {
				super(name, channels);
			}
		};

		try {
			const receiver = createBrowserClient(
				'http://localhost:3957/v1/project',
				'lux_pub_test',
				{ isSingleton: false, auth: { autoRefreshToken: false } },
			);
			const events: string[] = [];
			const subscription = receiver.auth.onAuthStateChange((event, session) => {
				events.push(`${event}:${session?.access_token ?? 'none'}`);
			});

			await waitFor(() => events.includes('INITIAL_SESSION:none'));

			const value = encodeSessionCookie({
				access_token: 'server-load-access-token',
				refresh_token: 'server-load-refresh-token',
				expires_in: 3600,
				token_type: 'bearer',
				user: { id: 'usr_server_load', email: 'server-load@example.com' },
			});
			browserCookies.set('lux-auth-session', value);
			createBrowserClient(
				'http://localhost:3957/v1/project',
				'lux_pub_test',
				{
					isSingleton: false,
					auth: { autoRefreshToken: false },
				},
			);

			await waitFor(() => events.includes('SIGNED_IN:server-load-access-token'));
			subscription.unsubscribe();
		} finally {
			if (originalDocument === undefined) {
				delete (globalThis as any).document;
			} else {
				(globalThis as any).document = originalDocument;
			}
			if (originalBroadcastChannel === undefined) {
				delete (globalThis as any).BroadcastChannel;
			} else {
				(globalThis as any).BroadcastChannel = originalBroadcastChannel;
			}
		}
	});

	test('browser singleton syncs cookie changes on repeated client load', async () => {
		const originalDocument = (globalThis as any).document;
		const browserCookies = new Map<string, string>();
		const document = createCookieDocument(browserCookies);
		(globalThis as any).document = document;

		try {
			const browser = createBrowserClient(
				'http://localhost:3957/v1/project-singleton-sync',
				'lux_pub_sync',
				{ auth: { autoRefreshToken: false } },
			);
			const events: string[] = [];
			const subscription = browser.auth.onAuthStateChange((event, session) => {
				events.push(`${event}:${session?.access_token ?? 'none'}`);
			});

			await waitFor(() => events.includes('INITIAL_SESSION:none'));

			browserCookies.set('lux-auth-session', encodeSessionCookie({
				access_token: 'singleton-sync-access-token',
				refresh_token: 'singleton-sync-refresh-token',
				expires_in: 3600,
				token_type: 'bearer',
				user: { id: 'usr_singleton_sync', email: 'singleton-sync@example.com' },
			}));
			const sameBrowser = createBrowserClient(
				'http://localhost:3957/v1/project-singleton-sync',
				'lux_pub_sync',
				{ auth: { autoRefreshToken: false } },
			);

			expect(sameBrowser).toBe(browser);
			await waitFor(() => events.includes('SIGNED_IN:singleton-sync-access-token'));
			subscription.unsubscribe();
		} finally {
			if (originalDocument === undefined) {
				delete (globalThis as any).document;
			} else {
				(globalThis as any).document = originalDocument;
			}
		}
	});

	test('client sign out reconciles a session created by an SSR redirect', async () => {
		const originalDocument = (globalThis as any).document;
		const browserCookies = new Map<string, string>();
		(globalThis as any).document = createCookieDocument(browserCookies);
		let authorization = '';

		try {
			const browser = createBrowserClient(
				'http://localhost:3957/v1/project',
				'lux_pub_test',
				{
					isSingleton: false,
					auth: { autoRefreshToken: false },
					fetch: (async (_input: RequestInfo | URL, init?: RequestInit) => {
						authorization = String(
							(init?.headers as Record<string, string> | undefined)?.Authorization ?? '',
						);
						return new Response('{}', { status: 200 });
					}) as typeof fetch,
				},
			);
			const events: string[] = [];
			browser.auth.onAuthStateChange((event) => events.push(event));

			// The singleton was created on the sign-in page before the server
			// action wrote a session cookie.
			expect((await browser.auth.getSession()).data?.session).toBeNull();

			// SvelteKit applies Set-Cookie and performs a client-side redirect,
			// without reloading the browser client or changing visibility.
			browserCookies.set('lux-auth-session', encodeSessionCookie({
				access_token: 'ssr-access-token',
				refresh_token: 'ssr-refresh-token',
				expires_in: 3600,
				token_type: 'bearer',
				user: { id: 'usr_ssr', email: 'ssr@example.com' },
			}));

			const result = await browser.auth.signOut();

			expect(result.error).toBeNull();
			expect(authorization).toBe('Bearer ssr-access-token');
			expect(browserCookies.has('lux-auth-session')).toBe(false);
			expect(events.filter((event) => event === 'SIGNED_IN')).toHaveLength(0);
			expect(events.filter((event) => event === 'SIGNED_OUT')).toHaveLength(1);
		} finally {
			if (originalDocument === undefined) {
				delete (globalThis as any).document;
			} else {
				(globalThis as any).document = originalDocument;
			}
		}
	});

	test('browser client is a singleton by default in browser environments', () => {
		const originalDocument = (globalThis as any).document;
		(globalThis as any).document = createCookieDocument(new Map());
		try {
			const first = createBrowserClient(
				'http://localhost:3957/v1/project-singleton',
				'lux_pub_singleton',
			);
			const second = createBrowserClient(
				'http://localhost:3957/v1/project-singleton',
				'lux_pub_singleton',
			);
			expect(second).toBe(first);
		} finally {
			if (originalDocument === undefined) {
				delete (globalThis as any).document;
			} else {
				(globalThis as any).document = originalDocument;
			}
		}
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

function createCookieDocument(cookies: Map<string, string>): {
	cookie: string;
	visibilityState: string;
	addEventListener(type: string, listener: () => void): void;
	dispatchVisibilityChange(state: string): void;
} {
	const listeners = new Set<() => void>();
	return {
		visibilityState: 'visible',
		get cookie() {
			return [...cookies].map(([name, value]) => `${name}=${value}`).join('; ');
		},
		set cookie(serialized: string) {
			const [pair, ...attributes] = serialized.split(';').map((part) => part.trim());
			const separator = pair.indexOf('=');
			const name = pair.slice(0, separator);
			const value = pair.slice(separator + 1);
			const removesCookie = attributes.some((attribute) =>
				attribute.toLowerCase() === 'max-age=0'
			);
			if (removesCookie) cookies.delete(name);
			else cookies.set(name, value);
		},
		addEventListener(type: string, listener: () => void) {
			if (type === 'visibilitychange') listeners.add(listener);
		},
		dispatchVisibilityChange(state: string) {
			this.visibilityState = state;
			for (const listener of listeners) listener();
		},
	};
}

class FakeBroadcastChannel {
	private listeners = new Set<(event: { data?: unknown }) => void>();

	constructor(
		private name: string,
		private channels: Map<string, Set<FakeBroadcastChannel>>,
	) {
		const peers = channels.get(name) ?? new Set();
		peers.add(this);
		channels.set(name, peers);
	}

	addEventListener(_type: string, listener: (event: { data?: unknown }) => void) {
		this.listeners.add(listener);
	}

	postMessage(data: unknown) {
		for (const peer of this.channels.get(this.name) ?? []) {
			if (peer === this) continue;
			for (const listener of peer.listeners) listener({ data });
		}
	}
}

async function waitFor(predicate: () => boolean, timeoutMs = 1_000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() >= deadline) throw new Error('Timed out waiting for condition');
		await Bun.sleep(10);
	}
}

function cookieMethods(
	cookies: Map<string, string>,
	onSet?: (options: LuxCookieOptions, headers: Record<string, string>) => void,
): LuxBrowserCookieMethods {
	return {
		getAll: () => [...cookies].map(([name, value]) => ({ name, value })),
		setAll: (cookiesToSet, headers) => {
			for (const { name, value, options } of cookiesToSet) {
				onSet?.(options, headers);
				if (options.maxAge === 0) cookies.delete(name);
				else cookies.set(name, value);
			}
		},
	};
}

function encodeSessionCookie(session: Record<string, unknown>): string {
	const bytes = new TextEncoder().encode(JSON.stringify(session));
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return `base64-${btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`;
}
