import { createClient, type LuxProjectClient, type LuxProjectOptions } from './project';
import type { LuxSchema } from './types';
import { projectStorageKey } from './utils';
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

const browserClients = new Map<string, { client: LuxProjectClient<any>; config: Record<string, unknown> }>();

export function createBrowserClient<DB extends Record<string, object> = LuxSchema>(
	url: string,
	key: string,
	options: LuxBrowserClientOptions = {},
): LuxProjectClient<DB> {
	if (key.startsWith('lux_sec_') || key.startsWith('lux_sk_')) {
		throw new Error('Browser clients require a publishable key, not a secret key');
	}
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
	const storageKey = authOptions.storageKey ?? projectStorageKey(
		url, usesDefaultCookieStorage ? DEFAULT_SESSION_COOKIE : 'lux.auth.session',
	);
	const singletonKey = JSON.stringify([url.replace(/\/+$/, ''), key, storageKey]);
	const config = {
		...Object.fromEntries(Object.entries(authOptions).map(([name, value]) => [`auth:${name}`, value])),
		...Object.fromEntries(Object.entries(resolvedCookieOptions).map(([name, value]) => [`cookie:${name}`, value])),
		fetch: options.fetch,
		websocket: options.websocket,
		cookies: options.cookies,
		signal: options.signal,
		requestTimeoutMs: options.requestTimeoutMs,
	};
	const cached = isSingleton ? browserClients.get(singletonKey) : undefined;
	if (cached && Object.keys(config).length === Object.keys(cached.config).length &&
		Object.entries(config).every(([name, value]) => Object.is(value, cached.config[name]))) {
		syncBrowserClient(cached.client);
		return cached.client as LuxProjectClient<DB>;
	}

	const client = createClient<DB>(url, key, {
		fetch: options.fetch,
		websocket: options.websocket,
		requestTimeoutMs: options.requestTimeoutMs,
		signal: options.signal,
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
	if (isSingleton) browserClients.set(singletonKey, { client, config });
	return client;
}

function syncBrowserClient(client: LuxProjectClient<any>): void {
	void client.auth.syncSessionFromStorage(undefined, { broadcast: true });
}
