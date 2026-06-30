import { describe, expect, test } from 'bun:test';
import { LuxAuthClient, type LuxAuthStorage } from '../src/auth';

function memoryStorage(seed: Record<string, string> = {}): LuxAuthStorage & { data: Map<string, string> } {
	const data = new Map(Object.entries(seed));
	return {
		data,
		getItem: (key) => data.get(key) ?? null,
		setItem: (key, value) => {
			data.set(key, value);
		},
		removeItem: (key) => {
			data.delete(key);
		},
	};
}

function session(overrides: Record<string, unknown> = {}) {
	return {
		access_token: 'access-token',
		refresh_token: 'refresh-token',
		expires_in: 3600,
		token_type: 'bearer' as const,
		user: { id: 'usr_123', email: 'user@example.com' },
		...overrides,
	};
}

describe('LuxAuthClient session state', () => {
	test('persists, restores, and clears sessions through storage', async () => {
		const storage = memoryStorage();
		const auth = new LuxAuthClient({
			persistSession: true,
			autoRefreshToken: false,
			storage,
			storageKey: 'lux.test.session',
		});

		await auth.setSession(session());
		expect(storage.data.has('lux.test.session')).toBe(true);

		const restored = new LuxAuthClient({
			persistSession: true,
			autoRefreshToken: false,
			storage,
			storageKey: 'lux.test.session',
		});
		expect((await restored.getSession()).data?.session?.access_token).toBe('access-token');

		await restored.clearSession();
		expect((await restored.getSession()).data?.session).toBeNull();
		expect(storage.data.has('lux.test.session')).toBe(false);
	});

	test('emits auth state changes', async () => {
		const auth = new LuxAuthClient({ persistSession: false, autoRefreshToken: false });
		const events: string[] = [];
		const subscription = auth.onAuthStateChange((event, nextSession) => {
			events.push(`${event}:${nextSession ? 'session' : 'none'}`);
		});

		await Promise.resolve();
		await auth.setSession(session());
		await auth.clearSession();
		subscription.unsubscribe();

		expect(events).toContain('INITIAL_SESSION:none');
		expect(events).toContain('SESSION_UPDATED:session');
		expect(events).toContain('SIGNED_OUT:none');
	});

	test('broadcasts browser auth changes across clients', async () => {
		const originalDocument = (globalThis as any).document;
		const originalBroadcastChannel = (globalThis as any).BroadcastChannel;
		const channels = new Map<string, Set<FakeBroadcastChannel>>();
		(globalThis as any).document = {
			visibilityState: 'visible',
			addEventListener() {},
		};
		(globalThis as any).BroadcastChannel = class extends FakeBroadcastChannel {
			constructor(name: string) {
				super(name, channels);
			}
		};

		try {
			const sharedStorage = memoryStorage();
			const first = new LuxAuthClient({
				persistSession: true,
				autoRefreshToken: false,
				storage: sharedStorage,
				storageKey: 'lux.broadcast.session',
			});
			const second = new LuxAuthClient({
				persistSession: true,
				autoRefreshToken: false,
				storage: sharedStorage,
				storageKey: 'lux.broadcast.session',
			});
			const events: string[] = [];
			let resolveInitial!: () => void;
			const initial = new Promise<void>((resolve) => {
				resolveInitial = resolve;
			});
			second.onAuthStateChange((event, nextSession) => {
				events.push(`${event}:${nextSession?.access_token ?? 'none'}`);
				if (event === 'INITIAL_SESSION') resolveInitial();
			});
			await initial;

			await first.setSession(session({ access_token: 'broadcast-token' }));
			await Promise.resolve();

			expect(events).toContain('SESSION_UPDATED:broadcast-token');
			expect((await second.getSession()).data?.session?.access_token)
				.toBe('broadcast-token');
		} finally {
			if (originalDocument === undefined) delete (globalThis as any).document;
			else (globalThis as any).document = originalDocument;
			if (originalBroadcastChannel === undefined) delete (globalThis as any).BroadcastChannel;
			else (globalThis as any).BroadcastChannel = originalBroadcastChannel;
		}
	});

	test('broadcast sign-in survives storage reconciliation in the receiving tab', async () => {
		const originalDocument = (globalThis as any).document;
		const originalBroadcastChannel = (globalThis as any).BroadcastChannel;
		const channels = new Map<string, Set<FakeBroadcastChannel>>();
		(globalThis as any).document = {
			visibilityState: 'visible',
			addEventListener() {},
		};
		(globalThis as any).BroadcastChannel = class extends FakeBroadcastChannel {
			constructor(name: string) {
				super(name, channels);
			}
		};

		try {
			const firstStorage = memoryStorage();
			const secondBacking = new Map<string, string>();
			const writes: string[] = [];
			const secondStorage: LuxAuthStorage = {
				getItem: (key) => secondBacking.get(key) ?? null,
				setItem: (key, value) => {
					writes.push(value);
					secondBacking.set(key, value);
				},
				removeItem: (key) => {
					secondBacking.delete(key);
				},
			};
			const first = new LuxAuthClient({
				persistSession: true,
				autoRefreshToken: false,
				storage: firstStorage,
				storageKey: 'lux.broadcast.reconcile',
			});
			const second = new LuxAuthClient({
				persistSession: true,
				autoRefreshToken: false,
				storage: secondStorage,
				storageKey: 'lux.broadcast.reconcile',
			});
			const events: string[] = [];
			let resolveInitial!: () => void;
			const initial = new Promise<void>((resolve) => {
				resolveInitial = resolve;
			});
			second.onAuthStateChange((event, nextSession) => {
				events.push(`${event}:${nextSession?.access_token ?? 'none'}`);
				if (event === 'INITIAL_SESSION') resolveInitial();
			});
			await initial;

			await first.setSession(session({ access_token: 'broadcast-token' }));
			await Promise.resolve();

			expect(events).toContain('SESSION_UPDATED:broadcast-token');
			expect(writes).toHaveLength(1);
			expect((await second.getSession()).data?.session?.access_token)
				.toBe('broadcast-token');
		} finally {
			if (originalDocument === undefined) delete (globalThis as any).document;
			else (globalThis as any).document = originalDocument;
			if (originalBroadcastChannel === undefined) delete (globalThis as any).BroadcastChannel;
			else (globalThis as any).BroadcastChannel = originalBroadcastChannel;
		}
	});

	test('signOut clears local state when remote logout fails', async () => {
		const storage = memoryStorage();
		const auth = new LuxAuthClient({
			httpUrl: 'http://localhost:3957/v1/project',
			fetch: (async () => new Response(
				JSON.stringify({ error: 'session already revoked' }),
				{ status: 401 },
			)) as typeof fetch,
			persistSession: true,
			autoRefreshToken: false,
			storage,
		});
		await auth.setSession(session());

		const events: string[] = [];
		auth.onAuthStateChange((event) => events.push(event));
		const result = await auth.signOut();

		expect(result.error?.code).toBe('LUX_AUTH_LOGOUT_ERROR');
		expect(storage.data.has('lux.auth.session')).toBe(false);
		expect((await auth.getSession()).data?.session).toBeNull();
		expect(events).toContain('SIGNED_OUT');
	});

	test('signInWithPassword stores returned session and sends project apikey', async () => {
		const storage = memoryStorage();
		let seen: { url: string; headers: Record<string, string>; body: any } | null = null;
		const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit) => {
			seen = {
				url: String(input),
				headers: init?.headers as Record<string, string>,
				body: JSON.parse(String(init?.body)),
			};
			return new Response(JSON.stringify(session({ access_token: 'signed-in' })), { status: 200 });
		};

		const auth = new LuxAuthClient({
			httpUrl: 'http://localhost:3957/v1/project',
			apiKey: 'lux_pub_test',
			fetch: fetchImpl as typeof fetch,
			persistSession: true,
			autoRefreshToken: false,
			storage,
		});

		const next = await auth.signInWithPassword({ email: 'user@example.com', password: 'password' });

		expect(next.data?.session?.access_token).toBe('signed-in');
		expect(next.data?.user?.id).toBe('usr_123');
		expect(next.error).toBeNull();
		expect((await auth.getSession()).data?.session?.access_token).toBe('signed-in');
		expect(seen?.url).toBe('http://localhost:3957/v1/project/auth/v1/token');
		expect(seen?.headers.apikey).toBe('lux_pub_test');
		expect(seen?.body).toEqual({
			grant_type: 'password',
			email: 'user@example.com',
			password: 'password',
		});
	});

	test('getUser uses the stored bearer token', async () => {
		let authorization = '';
		const fetchImpl = async (_input: RequestInfo | URL, init?: RequestInit) => {
			authorization = String((init?.headers as Record<string, string>).Authorization || '');
			return new Response(JSON.stringify({ user: { id: 'usr_123', email: 'user@example.com' } }), { status: 200 });
		};
		const auth = new LuxAuthClient({
			httpUrl: 'http://localhost:3957/v1/project',
			fetch: fetchImpl as typeof fetch,
			persistSession: false,
			autoRefreshToken: false,
		});
		await auth.setSession(session({ access_token: 'stored-token' }));

		const user = await auth.getUser();

		expect(user.data?.user?.id).toBe('usr_123');
		expect(user.error).toBeNull();
		expect(authorization).toBe('Bearer stored-token');
	});

	test('admin user facade calls Supabase-compatible admin routes', async () => {
		const calls: Array<{ url: string; method?: string; headers: Record<string, string>; body?: unknown }> = [];
		const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit) => {
			calls.push({
				url: String(input),
				method: init?.method,
				headers: init?.headers as Record<string, string>,
				body: init?.body ? JSON.parse(String(init.body)) : undefined,
			});
			if (init?.method === 'GET' && String(input).endsWith('/admin/users')) {
				return new Response(JSON.stringify({ users: [{ id: 'usr_123', email: 'user@example.com' }] }), { status: 200 });
			}
			return new Response(JSON.stringify({ user: { id: 'usr_123', email: 'user@example.com' } }), { status: 200 });
		};
		const auth = new LuxAuthClient({
			httpUrl: 'http://localhost:3957/v1/project',
			apiKey: 'lux_sec_test',
			fetch: fetchImpl as typeof fetch,
			persistSession: false,
			autoRefreshToken: false,
		});

		await auth.admin.createUser({
			id: 'usr_123',
			email: 'user@example.com',
			encrypted_password: '$2b$04$hash',
			email_confirmed: true,
		});
		await auth.admin.getUserById('usr_123');
		await auth.admin.updateUserById('usr_123', { email: 'next@example.com' });
		await auth.admin.deleteUser('usr_123');
		await auth.admin.listUsers();

		expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
			'POST http://localhost:3957/v1/project/auth/v1/admin/users',
			'GET http://localhost:3957/v1/project/auth/v1/admin/users/usr_123',
			'PATCH http://localhost:3957/v1/project/auth/v1/admin/users/usr_123',
			'DELETE http://localhost:3957/v1/project/auth/v1/admin/users/usr_123',
			'GET http://localhost:3957/v1/project/auth/v1/admin/users',
		]);
		expect(calls.every((call) => call.headers.apikey === 'lux_sec_test')).toBe(true);
		expect(calls[0].body).toEqual({
			id: 'usr_123',
			email: 'user@example.com',
			encrypted_password: '$2b$04$hash',
			email_confirmed: true,
		});
		expect(calls[2].body).toEqual({ email: 'next@example.com' });
	});

	test('admin settings facade uses secret-key settings routes', async () => {
		const calls: Array<{ url: string; method?: string; headers: Record<string, string>; body?: unknown }> = [];
		const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit) => {
			calls.push({
				url: String(input),
				method: init?.method,
				headers: init?.headers as Record<string, string>,
				body: init?.body ? JSON.parse(String(init.body)) : undefined,
			});
			return new Response(
				JSON.stringify({
					settings: {
						email_confirmation_required: true,
						flow_token_ttl_seconds: 120,
						site_url: 'http://app.test/auth',
						email_provider: 'postmark',
						email_delivery_managed: false,
						email_delivery_configured: true,
						email_from: 'Auth <auth@app.test>',
						email_reply_to: null,
						email_postmark_message_stream: 'outbound',
						has_email_postmark_server_token: true,
						email_app_name: 'App',
						email_from_name: null,
					},
				}),
				{ status: 200 },
			);
		};
		const auth = new LuxAuthClient({
			httpUrl: 'http://localhost:3957/v1/project',
			apiKey: 'lux_sec_test',
			fetch: fetchImpl as typeof fetch,
			persistSession: false,
			autoRefreshToken: false,
		});

		const getResult = await auth.admin.getSettings();
		const updateResult = await auth.admin.updateSettings({
			email_confirmation_required: true,
			flow_token_ttl_seconds: 120,
			site_url: 'http://app.test/auth',
			email_provider: 'postmark',
			email_from: 'Auth <auth@app.test>',
			email_postmark_server_token: 'server-token',
			email_app_name: 'App',
		});

		expect(getResult.data?.email_confirmation_required).toBe(true);
		expect(updateResult.data?.flow_token_ttl_seconds).toBe(120);
		expect(updateResult.data?.has_email_postmark_server_token).toBe(true);
		expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
			'GET http://localhost:3957/v1/project/auth/v1/admin/settings',
			'PATCH http://localhost:3957/v1/project/auth/v1/admin/settings',
		]);
		expect(calls.every((call) => call.headers.apikey === 'lux_sec_test')).toBe(true);
		expect(calls[1].body).toEqual({
			email_confirmation_required: true,
			flow_token_ttl_seconds: 120,
			site_url: 'http://app.test/auth',
			email_provider: 'postmark',
			email_from: 'Auth <auth@app.test>',
			email_postmark_server_token: 'server-token',
			email_app_name: 'App',
		});
	});

	test('signup accepts Supabase options shape and nullable confirmation session', async () => {
		let body: any;
		const fetchImpl = async (_input: RequestInfo | URL, init?: RequestInit) => {
			body = init?.body ? JSON.parse(String(init.body)) : undefined;
			return new Response(JSON.stringify({
				access_token: null,
				refresh_token: null,
				token_type: 'bearer',
				expires_in: 0,
				user: { id: 'usr_confirm', email: 'confirm@example.com' },
			}), { status: 200 });
		};
		const auth = new LuxAuthClient({
			httpUrl: 'http://localhost:3957/v1/project',
			apiKey: 'lux_pub_test',
			fetch: fetchImpl as typeof fetch,
		});

		const result = await auth.signUp({
			email: 'confirm@example.com',
			password: 'password123',
			options: {
				data: { name: 'Confirm Me' },
				emailRedirectTo: 'http://app.test/confirm',
			},
		});

		expect(result.error).toBeNull();
		expect(result.data?.session).toBeNull();
		expect(result.data?.user.email).toBe('confirm@example.com');
		expect(body).toEqual({
			email: 'confirm@example.com',
			password: 'password123',
			data: { name: 'Confirm Me' },
			email_redirect_to: 'http://app.test/confirm',
		});
	});

	test('password recovery, verifyOtp, updateUser, and getClaims use Lux auth routes', async () => {
		const calls: Array<{ url: string; method?: string; headers: Record<string, string>; body?: unknown }> = [];
		const payload = { sub: 'usr_123', email: 'user@example.com', role: 'authenticated' };
		const token = `h.${btoa(JSON.stringify(payload)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}.s`;
		const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit) => {
			calls.push({
				url: String(input),
				method: init?.method,
				headers: init?.headers as Record<string, string>,
				body: init?.body ? JSON.parse(String(init.body)) : undefined,
			});
			if (String(input).endsWith('/recover')) {
				return new Response(JSON.stringify({}), { status: 200 });
			}
			if (String(input).endsWith('/verify')) {
				return new Response(JSON.stringify(session({ access_token: token })), { status: 200 });
			}
			return new Response(JSON.stringify({ user: { id: 'usr_123', email: 'user@example.com' } }), { status: 200 });
		};
		const auth = new LuxAuthClient({
			httpUrl: 'http://localhost:3957/v1/project',
			apiKey: 'lux_pub_test',
			fetch: fetchImpl as typeof fetch,
			persistSession: true,
			autoRefreshToken: false,
			storage: memoryStorage(),
		});

		await auth.resetPasswordForEmail('user@example.com', { redirectTo: 'http://app.test/update-password' });
		await auth.verifyOtp({ type: 'recovery', token_hash: 'tok_123' });
		await auth.updateUser({ password: 'newpassword123', data: { name: 'Updated' } });
		const claims = await auth.getClaims();

		expect(claims.data?.claims).toEqual(payload);
		expect(calls.map((call) => `${call.method} ${call.url}`)).toEqual([
			'POST http://localhost:3957/v1/project/auth/v1/recover',
			'POST http://localhost:3957/v1/project/auth/v1/verify',
			'PUT http://localhost:3957/v1/project/auth/v1/user',
		]);
		expect(calls[0].body).toEqual({
			email: 'user@example.com',
			redirect_to: 'http://app.test/update-password',
		});
		expect(calls[1].body).toEqual({ type: 'recovery', token_hash: 'tok_123' });
		expect(calls[2].headers.Authorization).toBe(`Bearer ${token}`);
		expect(calls[2].body).toEqual({ password: 'newpassword123', data: { name: 'Updated' } });
	});

	test('default fetch is bound for browser auth requests', async () => {
		const originalFetch = globalThis.fetch;
		let receiver: unknown;
		globalThis.fetch = (async function (this: unknown) {
			receiver = this;
			return new Response(JSON.stringify({ user: { id: 'usr_123', email: 'user@example.com' } }), { status: 200 });
		}) as typeof fetch;
		try {
			const auth = new LuxAuthClient({
				httpUrl: 'http://localhost:3957/v1/project',
				authToken: 'stored-token',
				persistSession: false,
				autoRefreshToken: false,
			});
			await auth.getUser();
			expect(receiver).toBe(globalThis);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	test('signInWithOAuth builds project authorize URL without forcing redirect', async () => {
		const auth = new LuxAuthClient({
			httpUrl: 'http://localhost:3957/v1/project',
			persistSession: false,
			autoRefreshToken: false,
		});

		const result = await auth.signInWithOAuth({
			provider: 'github',
			redirectTo: 'http://localhost:5173/callback',
			skipRedirect: true,
		});

		expect(result.data?.url).toBe(
			'http://localhost:3957/v1/project/auth/v1/authorize?provider=github&redirect_to=http%3A%2F%2Flocalhost%3A5173%2Fcallback',
		);
		expect(result.error).toBeNull();
	});

	test('signInWithOAuth accepts nested Supabase options and code flow', async () => {
		const auth = new LuxAuthClient({
			httpUrl: 'http://localhost:3957/v1/project',
			persistSession: false,
			autoRefreshToken: false,
		});

		const result = await auth.signInWithOAuth({
			provider: 'github',
			options: {
				redirectTo: 'http://localhost:5173/callback',
				skipRedirect: true,
				flow: 'code',
			},
		});

		expect(result.data?.url).toBe(
			'http://localhost:3957/v1/project/auth/v1/authorize?provider=github&redirect_to=http%3A%2F%2Flocalhost%3A5173%2Fcallback&flow=code',
		);
		expect(result.error).toBeNull();
	});

	test('consumeOAuthRedirect stores access, refresh, and loaded user from hash', async () => {
		const storage = memoryStorage();
		let authorization = '';
		const fetchImpl = async (_input: RequestInfo | URL, init?: RequestInit) => {
			authorization = String((init?.headers as Record<string, string>).Authorization || '');
			return new Response(JSON.stringify({ user: { id: 'usr_oauth', email: 'oauth@example.com' } }), { status: 200 });
		};
		const auth = new LuxAuthClient({
			httpUrl: 'http://localhost:3957/v1/project',
			fetch: fetchImpl as typeof fetch,
			persistSession: true,
			autoRefreshToken: false,
			storage,
		});

		const result = await auth.consumeOAuthRedirect(
			'http://localhost:5173/callback#access_token=access&refresh_token=refresh&token_type=bearer&expires_in=3600',
		);

		expect(result.data?.session?.access_token).toBe('access');
		expect(result.data?.session?.refresh_token).toBe('refresh');
		expect(result.data?.user).toEqual({ id: 'usr_oauth', email: 'oauth@example.com' });
		expect(result.error).toBeNull();
		expect(authorization).toBe('Bearer access');
		expect(storage.data.has('lux.auth.session')).toBe(true);
	});

	test('consumeOAuthRedirect returns an error when callback tokens are missing', async () => {
		const auth = new LuxAuthClient();

		const result = await auth.consumeOAuthRedirect('https://app.example.com/auth/callback');

		expect(result.data).toBeNull();
		expect(result.error?.code).toBe('LUX_AUTH_OAUTH_ERROR');
	});

	test('consumeOAuthRedirect exchanges code callbacks for sessions', async () => {
		let seenBody: unknown;
		const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit) => {
			seenBody = init?.body ? JSON.parse(String(init.body)) : undefined;
			expect(String(input)).toBe('http://localhost:3957/v1/project/auth/v1/token?grant_type=authorization_code');
			return new Response(JSON.stringify(session({ access_token: 'code-access' })), { status: 200 });
		};
		const auth = new LuxAuthClient({
			httpUrl: 'http://localhost:3957/v1/project',
			apiKey: 'lux_pub_test',
			fetch: fetchImpl as typeof fetch,
			persistSession: false,
			autoRefreshToken: false,
		});

		const result = await auth.consumeOAuthRedirect('https://app.example.com/auth/callback?code=auth-code');

		expect(result.error).toBeNull();
		expect(result.data?.session?.access_token).toBe('code-access');
		expect(seenBody).toEqual({ grant_type: 'authorization_code', code: 'auth-code' });
	});
});

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
