import { createClient, type LuxProjectOptions } from './project';
import type { LuxSchema } from './types';
import {
	cookieStorage,
	DEFAULT_SESSION_COOKIE,
	DEFAULT_SESSION_COOKIE_OPTIONS,
	type LuxServerCookieMethods,
	type LuxCookieOptions,
} from './cookies';

export type {
	LuxBrowserCookieMethods,
	LuxCookie,
	LuxCookieOptions,
	LuxCookieToSet,
	LuxServerCookieMethods,
} from './cookies';

export interface LuxServerClientOptions extends Omit<LuxProjectOptions, 'url' | 'key' | 'auth'> {
	auth?: Omit<NonNullable<LuxProjectOptions['auth']>, 'storage'> & {
		cookieOptions?: LuxCookieOptions;
	};
	/**
	 * Cookie adapter for SSR session persistence (Next/SvelteKit/etc). Omit it
	 * for a stateless backend client (secret key, or `setSession` per request):
	 * `createServerClient(url, key)` then works with no cookie plumbing.
	 */
	cookies?: LuxServerCookieMethods;
}

export function createServerClient<DB extends Record<string, object> = LuxSchema>(
	url: string,
	key: string,
	options: LuxServerClientOptions = {},
) {
	const storageKey = options.auth?.storageKey ?? DEFAULT_SESSION_COOKIE;
	const cookieOptions = {
		...DEFAULT_SESSION_COOKIE_OPTIONS,
		...options.auth?.cookieOptions,
	};
	const { cookieOptions: _cookieOptions, ...authOptions } = options.auth ?? {};

	// With cookies -> cookie-backed session (SSR). Without -> stateless backend
	// client: no session storage, nothing to persist.
	const hasCookies = options.cookies !== undefined;

	return createClient<DB>(url, key, {
		fetch: options.fetch,
		auth: {
			persistSession: hasCookies,
			autoRefreshToken: false,
			...authOptions,
			storageKey,
			storage: hasCookies ? cookieStorage(options.cookies as LuxServerCookieMethods, cookieOptions) : null,
		},
	});
}
