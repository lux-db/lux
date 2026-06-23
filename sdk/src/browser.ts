import { createClient, type LuxProjectClient, type LuxProjectOptions } from './project';
import type { LuxSchema } from './types';
import {
	browserCookieStorage,
	DEFAULT_SESSION_COOKIE,
	DEFAULT_SESSION_COOKIE_OPTIONS,
	type LuxBrowserCookieMethods,
	type LuxCookieOptions,
} from './cookies';

export type {
	LuxBrowserCookieMethods,
	LuxCookie,
	LuxCookieOptions,
	LuxCookieToSet,
	LuxServerCookieMethods,
} from './cookies';

export interface LuxBrowserClientOptions extends Omit<LuxProjectOptions, 'url' | 'key' | 'auth'> {
	isSingleton?: boolean;
	cookies?: LuxBrowserCookieMethods;
	auth?: NonNullable<LuxProjectOptions['auth']> & {
		cookieOptions?: LuxCookieOptions;
	};
}

let browserClient: LuxProjectClient<any> | undefined;

export function createBrowserClient<DB extends Record<string, object> = LuxSchema>(
	url: string,
	key: string,
	options: LuxBrowserClientOptions = {},
): LuxProjectClient<DB> {
	const {
		cookieOptions,
		...authOptions
	} = options.auth ?? {};
	const resolvedCookieOptions = {
		...DEFAULT_SESSION_COOKIE_OPTIONS,
		...cookieOptions,
	};
	const usesDefaultCookieStorage = authOptions.storage === undefined;
	const isBrowser = typeof globalThis !== 'undefined' && Boolean((globalThis as any).document);
	const isSingleton = options.isSingleton ?? isBrowser;
	const storageKey = authOptions.storageKey ?? (
		usesDefaultCookieStorage ? DEFAULT_SESSION_COOKIE : 'lux.auth.session'
	);
	if (isSingleton && browserClient) {
		syncBrowserClient(browserClient);
		return browserClient as LuxProjectClient<DB>;
	}

	const client = createClient<DB>(url, key, {
		fetch: options.fetch,
		websocket: options.websocket,
		auth: {
			persistSession: true,
			autoRefreshToken: true,
			...authOptions,
			storageKey,
			storage: usesDefaultCookieStorage
				? browserCookieStorage(resolvedCookieOptions, options.cookies)
				: authOptions.storage,
		},
	});
	syncBrowserClient(client);
	if (isSingleton) browserClient = client;
	return client;
}

function syncBrowserClient(client: LuxProjectClient<any>): void {
	void client.auth.syncSessionFromStorage(undefined, { broadcast: true });
}
