import { createClient, type LuxProjectOptions } from './project';
import type { LuxAuthStorage } from './auth';

export interface LuxCookieOptions {
	domain?: string;
	expires?: Date;
	httpOnly?: boolean;
	maxAge?: number;
	path?: string;
	sameSite?: 'lax' | 'strict' | 'none';
	secure?: boolean;
}

export interface LuxCookieMethods {
	get(name: string): string | null | undefined | Promise<string | null | undefined>;
	set?(name: string, value: string, options?: LuxCookieOptions): void | Promise<void>;
	remove?(name: string, options?: LuxCookieOptions): void | Promise<void>;
}

export interface LuxServerClientOptions extends Omit<LuxProjectOptions, 'url' | 'key' | 'auth'> {
	auth?: Omit<NonNullable<LuxProjectOptions['auth']>, 'storage'> & {
		cookieOptions?: LuxCookieOptions;
	};
	/**
	 * Cookie adapter for SSR session persistence (Next/SvelteKit/etc). Omit it
	 * for a stateless backend client (secret key, or `setSession` per request):
	 * `createServerClient(url, key)` then works with no cookie plumbing.
	 */
	cookies?: LuxCookieMethods;
}

const DEFAULT_COOKIE = 'lux-auth-session';

export function createServerClient(
	url: string,
	key: string,
	options: LuxServerClientOptions = {},
) {
	const storageKey = options.auth?.storageKey ?? DEFAULT_COOKIE;
	const cookieOptions = options.auth?.cookieOptions ?? {
		path: '/',
		sameSite: 'lax',
	};
	const { cookieOptions: _cookieOptions, ...authOptions } = options.auth ?? {};

	// With cookies -> cookie-backed session (SSR). Without -> stateless backend
	// client: no session storage, nothing to persist.
	const hasCookies = options.cookies !== undefined;

	return createClient(url, key, {
		fetch: options.fetch,
		auth: {
			persistSession: hasCookies,
			autoRefreshToken: false,
			...authOptions,
			storageKey,
			storage: hasCookies ? cookieStorage(options.cookies as LuxCookieMethods, cookieOptions) : null,
		},
	});
}

function cookieStorage(cookies: LuxCookieMethods, options: LuxCookieOptions): LuxAuthStorage {
	return {
		async getItem(key) {
			return await cookies.get(key) ?? null;
		},
		async setItem(key, value) {
			if (!cookies.set) return;
			await cookies.set(key, value, options);
		},
		async removeItem(key) {
			if (!cookies.remove) return;
			await cookies.remove(key, { ...options, maxAge: 0, expires: new Date(0) });
		},
	};
}
