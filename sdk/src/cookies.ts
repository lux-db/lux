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

export interface LuxCookie {
	name: string;
	value: string;
}

export interface LuxCookieToSet extends LuxCookie {
	options: LuxCookieOptions;
}

export interface LuxBrowserCookieMethods {
	getAll(): LuxCookie[] | null | Promise<LuxCookie[] | null>;
	setAll(
		cookies: LuxCookieToSet[],
		headers: Record<string, string>,
	): void | Promise<void>;
}

export interface LuxServerCookieMethods {
	getAll(): LuxCookie[] | null | Promise<LuxCookie[] | null>;
	setAll?(
		cookies: LuxCookieToSet[],
		headers: Record<string, string>,
	): void | Promise<void>;
}

export const DEFAULT_SESSION_COOKIE = 'lux-auth-session';

export const DEFAULT_SESSION_COOKIE_OPTIONS: LuxCookieOptions = {
	httpOnly: false,
	path: '/',
	sameSite: 'lax',
};

export const AUTH_COOKIE_RESPONSE_HEADERS: Record<string, string> = {
	'Cache-Control': 'private, no-cache, no-store, must-revalidate, max-age=0',
	Expires: '0',
	Pragma: 'no-cache',
};

const BASE64_PREFIX = 'base64-';

export function browserCookieStorage(
	options: LuxCookieOptions,
	cookies: LuxBrowserCookieMethods = documentCookieMethods(),
): LuxAuthStorage {
	return cookieStorage(cookies, options, true);
}

export function cookieStorage(
	cookies: LuxServerCookieMethods,
	options: LuxCookieOptions,
	requireSetAll = false,
): LuxAuthStorage {
	const setAll = cookies.setAll ?? (() => {
		if (requireSetAll) {
			throw new Error('Lux browser cookie methods require setAll');
		}
		console.warn(
			'Lux server client needs setAll to persist auth cookie changes. ' +
			'This server context can read sessions, but sign-in, refresh, and sign-out cookie updates will not persist.',
		);
	});
	return {
		async getItem(key) {
			const allCookies = await cookies.getAll() ?? [];
			const cookie = allCookies.find(({ name }) => name === key);
			if (!cookie) return null;
			return decodeCookieValue(cookie.value);
		},
		async setItem(key, value) {
			await setAll(
				[{ name: key, value: encodeCookieValue(value), options }],
				AUTH_COOKIE_RESPONSE_HEADERS,
			);
		},
		async removeItem(key) {
			await setAll(
				[{
					name: key,
					value: '',
					options: {
						...options,
						expires: new Date(0),
						maxAge: 0,
					},
				}],
				AUTH_COOKIE_RESPONSE_HEADERS,
			);
		},
	};
}

function encodeCookieValue(value: string): string {
	const bytes = new TextEncoder().encode(value);
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return BASE64_PREFIX + globalThis.btoa(binary)
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

function decodeCookieValue(value: string): string {
	if (value.startsWith(BASE64_PREFIX)) {
		const encoded = value.slice(BASE64_PREFIX.length)
			.replace(/-/g, '+')
			.replace(/_/g, '/');
		const padded = encoded.padEnd(Math.ceil(encoded.length / 4) * 4, '=');
		const binary = globalThis.atob(padded);
		const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
		return new TextDecoder().decode(bytes);
	}
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

function documentCookieMethods(): LuxBrowserCookieMethods {
	return {
		getAll() {
			const document = browserDocument();
			if (!document) return [];
			return parseCookies(document.cookie);
		},
		setAll(cookies) {
			const document = browserDocument();
			if (!document) return;
			for (const { name, value, options } of cookies) {
				document.cookie = serializeCookie(name, value, options);
			}
		},
	};
}

function browserDocument(): { cookie: string } | null {
	if (typeof globalThis === 'undefined') return null;
	return (globalThis as any).document ?? null;
}

function parseCookies(cookieHeader: string): LuxCookie[] {
	const cookies: LuxCookie[] = [];
	for (const part of cookieHeader.split(';')) {
		const cookie = part.trim();
		const separator = cookie.indexOf('=');
		if (separator < 0) continue;
		cookies.push({
			name: cookie.slice(0, separator),
			value: cookie.slice(separator + 1),
		});
	}
	return cookies;
}

function serializeCookie(name: string, value: string, options: LuxCookieOptions): string {
	const parts = [`${name}=${value}`];
	if (options.domain) parts.push(`Domain=${options.domain}`);
	if (options.expires) parts.push(`Expires=${options.expires.toUTCString()}`);
	if (options.maxAge != null) parts.push(`Max-Age=${Math.floor(options.maxAge)}`);
	if (options.path) parts.push(`Path=${options.path}`);
	if (options.sameSite) parts.push(`SameSite=${capitalize(options.sameSite)}`);
	if (options.secure) parts.push('Secure');
	return parts.join('; ');
}

function capitalize(value: string): string {
	return value.charAt(0).toUpperCase() + value.slice(1);
}
