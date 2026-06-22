import type { LuxResult } from './types';
import { err, ok, toLuxError } from './utils';

export interface LuxAuthUser {
	id: string;
	email: string;
	phone?: string;
	email_confirmed_at?: number | null;
	phone_confirmed_at?: number | null;
	last_sign_in_at?: number | null;
	created_at?: number | null;
	updated_at?: number | null;
	user_metadata?: Record<string, unknown>;
	app_metadata?: Record<string, unknown>;
}

export type LuxUser = LuxAuthUser;

export interface LuxAuthUserRow {
	id: string;
	email?: string;
	phone?: string;
	encrypted_password?: string;
	email_confirmed_at?: number | null;
	phone_confirmed_at?: number | null;
	raw_user_meta_data?: string;
	raw_app_meta_data?: string;
	created_at?: number | null;
	updated_at?: number | null;
	last_sign_in_at?: number | null;
	banned_until?: number | null;
	deleted_at?: number | null;
}

export interface LuxAuthIdentityRow {
	id: string;
	user_id: string;
	provider: string;
	provider_id: string;
	identity_data?: string;
	created_at?: number | null;
	updated_at?: number | null;
}

export interface LuxAuthSessionRow {
	id: string;
	user_id: string;
	refresh_token_hash: string;
	refresh_token_family?: string;
	user_agent?: string;
	ip?: string;
	expires_at?: number | null;
	revoked_at?: number | null;
	created_at?: number | null;
	updated_at?: number | null;
}

export interface LuxAuthKeyRow {
	id: string;
	name?: string;
	kind: 'publishable' | 'secret' | string;
	prefix: string;
	key_hash: string;
	scopes?: string;
	created_at?: number | null;
	revoked_at?: number | null;
	last_used_at?: number | null;
}

export interface LuxAuthSigningKeyRow {
	id: string;
	kid: string;
	algorithm: string;
	public_jwk?: string;
	private_key_encrypted?: string;
	active: boolean;
	created_at?: number | null;
	rotated_at?: number | null;
}

export interface LuxAuthGrantRow {
	id: string;
	user_id: string;
	capability: string;
	created_at?: number | null;
	revoked_at?: number | null;
}

export interface LuxAuthProviderRow {
	provider: LuxOAuthProvider | string;
	enabled: boolean;
	client_id?: string;
	client_secret?: string;
	redirect_uri?: string;
	scopes?: string;
	created_at?: number | null;
	updated_at?: number | null;
}

export interface LuxAuthTables {
	'auth.users': LuxAuthUserRow;
	'auth.identities': LuxAuthIdentityRow;
	'auth.sessions': LuxAuthSessionRow;
	'auth.keys': LuxAuthKeyRow;
	'auth.signing_keys': LuxAuthSigningKeyRow;
	'auth.grants': LuxAuthGrantRow;
	'auth.providers': LuxAuthProviderRow;
}

export interface LuxAuthSession {
	access_token: string;
	token_type: 'bearer';
	expires_in: number;
	refresh_token: string;
	user: LuxAuthUser;
	expires_at?: number;
}

export interface LuxAuthSessionResult {
	session: LuxAuthSession;
	user: LuxAuthUser;
}

export interface LuxAuthKey {
	id: string;
	name: string;
	kind: 'publishable' | 'secret';
	prefix: string;
	scopes: string[];
	created_at?: number | null;
	revoked_at?: number | null;
	last_used_at?: number | null;
}

export interface LuxAuthOptions {
	httpUrl?: string;
	apiKey?: string;
	authToken?: string;
	fetch?: typeof fetch;
	persistSession?: boolean;
	autoRefreshToken?: boolean;
	storage?: LuxAuthStorage | null;
	storageKey?: string;
	refreshMarginSeconds?: number;
}

export interface LuxSignUpOptions {
	email: string;
	password: string;
	data?: Record<string, unknown>;
}

export interface LuxSignInOptions {
	email: string;
	password: string;
}

export type LuxOAuthProvider = 'google' | 'github';

export interface LuxSignInWithOAuthOptions {
	provider: LuxOAuthProvider;
	redirectTo?: string;
	skipRedirect?: boolean;
}

export interface LuxOAuthUrl {
	url: string;
}

export interface LuxCreateApiKeyOptions {
	kind: 'publishable' | 'secret';
	name?: string;
}

export interface LuxAuthProvider {
	provider: LuxOAuthProvider;
	enabled: boolean;
	client_id: string;
	redirect_uri: string;
	scopes: string;
	has_client_secret: boolean;
	created_at?: number | null;
	updated_at?: number | null;
}

export interface LuxUpsertProviderOptions {
	provider: LuxOAuthProvider;
	client_id: string;
	client_secret?: string;
	redirect_uri: string;
	scopes?: string;
	enabled?: boolean;
}

export type LuxAuthChangeEvent = 'INITIAL_SESSION' | 'SIGNED_IN' | 'TOKEN_REFRESHED' | 'SIGNED_OUT' | 'SESSION_UPDATED';

export interface LuxAuthStorage {
	getItem(key: string): string | null | Promise<string | null>;
	setItem(key: string, value: string): void | Promise<void>;
	removeItem(key: string): void | Promise<void>;
}

export type LuxAuthStateChangeCallback = (event: LuxAuthChangeEvent, session: LuxAuthSession | null) => void;

export interface LuxAuthSubscription {
	unsubscribe(): void;
}

export class LuxAuthClient {
	private httpUrl?: string;
	private apiKey?: string;
	private authToken?: string;
	private fetchImpl: typeof fetch;
	private persistSession: boolean;
	private autoRefreshToken: boolean;
	private storage: LuxAuthStorage | null;
	private storageKey: string;
	private refreshMarginSeconds: number;
	private currentSession: LuxAuthSession | null = null;
	private loadedSession = false;
	private storedSessionRaw: string | null = null;
	private refreshTimer: ReturnType<typeof setTimeout> | null = null;
	private listeners = new Set<LuxAuthStateChangeCallback>();
	private broadcastChannel?: {
		postMessage(message: unknown): void;
		addEventListener(type: string, listener: (event: { data?: unknown }) => void): void;
	};

	constructor(options: LuxAuthOptions = {}) {
		this.httpUrl = options.httpUrl?.replace(/\/+$/, '');
		this.apiKey = options.apiKey;
		this.authToken = options.authToken;
		this.fetchImpl = resolveFetch(options.fetch);
		this.persistSession = options.persistSession ?? false;
		this.autoRefreshToken = options.autoRefreshToken ?? this.persistSession;
		this.storage = options.storage === undefined ? defaultBrowserStorage() : options.storage;
		this.storageKey = options.storageKey ?? 'lux.auth.session';
		this.refreshMarginSeconds = options.refreshMarginSeconds ?? 60;
		if (this.authToken) {
			this.currentSession = null;
		}
		this.initializeBrowserLifecycle();
	}

	async getSession(): Promise<LuxResult<{ session: LuxAuthSession | null }>> {
		try {
			return ok({ session: await this.getSessionValue() });
		} catch (error) {
			return err('LUX_AUTH_SESSION_ERROR', 'Failed to get auth session', toLuxError(error));
		}
	}

	private async getSessionValue(): Promise<LuxAuthSession | null> {
		if (this.loadedSession) {
			// Reconcile storage before auth operations, but do not emit a
			// synthetic event. For example, signOut after an SSR redirect must
			// emit only SIGNED_OUT; emitting SIGNED_IN first can start a
			// competing SvelteKit invalidation while the cookie still exists.
			await this.recoverStoredSession(false);
		} else {
			await this.loadStoredSession();
		}
		if (this.currentSession && isExpired(this.currentSession, this.refreshMarginSeconds)) {
			if (this.autoRefreshToken && this.currentSession.refresh_token) {
				const refreshed = await this.refreshSession(this.currentSession.refresh_token);
				return refreshed.error ? null : refreshed.data.session;
			}
			await this.clearSessionValue();
			return null;
		}
		return this.currentSession;
	}

	async getAccessToken(): Promise<string | undefined> {
		const session = await this.getSessionValue();
		return session?.access_token ?? this.authToken;
	}

	async setSession(session: LuxAuthSession | string | null): Promise<LuxResult<{ session: LuxAuthSession | null }>> {
		try {
			return ok({ session: await this.setSessionValue(session) });
		} catch (error) {
			return err('LUX_AUTH_SESSION_ERROR', 'Failed to set auth session', toLuxError(error));
		}
	}

	private async setSessionValue(session: LuxAuthSession | string | null): Promise<LuxAuthSession | null> {
		if (typeof session === 'string') {
			this.authToken = session;
			this.currentSession = null;
			return null;
		}
		if (!session) {
			await this.clearSessionValue();
			return null;
		}
		await this.saveSession(normalizeSession(session), 'SESSION_UPDATED');
		return this.currentSession;
	}

	async clearSession(): Promise<LuxResult<true>> {
		try {
			await this.clearSessionValue();
			return ok(true);
		} catch (error) {
			return err('LUX_AUTH_SESSION_ERROR', 'Failed to clear auth session', toLuxError(error));
		}
	}

	private async clearSessionValue(): Promise<void> {
		this.authToken = undefined;
		this.currentSession = null;
		this.loadedSession = true;
		this.storedSessionRaw = null;
		this.clearRefreshTimer();
		if (this.persistSession && this.storage) {
			await this.storage.removeItem(this.storageKey);
		}
		this.emit('SIGNED_OUT', null);
		this.broadcast('SIGNED_OUT', null);
	}

	onAuthStateChange(callback: LuxAuthStateChangeCallback): LuxAuthSubscription {
		this.listeners.add(callback);
		void this.getSessionValue().then((session) => callback('INITIAL_SESSION', session));
		return {
			unsubscribe: () => {
				this.listeners.delete(callback);
			},
		};
	}

	async signUp(options: LuxSignUpOptions): Promise<LuxResult<LuxAuthSessionResult>> {
		try {
			const session = await this.requestRaw<LuxAuthSession>('/auth/v1/signup', {
				method: 'POST',
				body: JSON.stringify({
					email: options.email,
					password: options.password,
					data: options.data,
				}),
				apiKey: true,
			});
			await this.saveSession(normalizeSession(session), 'SIGNED_IN');
			return ok({ session: this.currentSession!, user: this.currentSession!.user });
		} catch (error) {
			return err('LUX_AUTH_SIGNUP_ERROR', 'Failed to sign up', toLuxError(error));
		}
	}

	async signInWithPassword(options: LuxSignInOptions): Promise<LuxResult<LuxAuthSessionResult>> {
		try {
			const session = await this.requestRaw<LuxAuthSession>('/auth/v1/token', {
				method: 'POST',
				body: JSON.stringify({
					grant_type: 'password',
					email: options.email,
					password: options.password,
				}),
				apiKey: true,
			});
			await this.saveSession(normalizeSession(session), 'SIGNED_IN');
			return ok({ session: this.currentSession!, user: this.currentSession!.user });
		} catch (error) {
			return err('LUX_AUTH_SIGNIN_ERROR', 'Failed to sign in', toLuxError(error));
		}
	}

	async signInWithOAuth(options: LuxSignInWithOAuthOptions): Promise<LuxResult<LuxOAuthUrl>> {
		try {
			if (!this.httpUrl) {
				throw new Error('Lux auth requires httpUrl');
			}
			const redirectTo = options.redirectTo ?? browserLocation();
			const url = new URL(`${this.httpUrl}/auth/v1/authorize`);
			url.searchParams.set('provider', options.provider);
			if (redirectTo) url.searchParams.set('redirect_to', redirectTo);
			const target = url.toString();
			if (!options.skipRedirect && typeof globalThis !== 'undefined') {
				const location = (globalThis as any).location;
				if (location?.assign) location.assign(target);
			}
			return ok({ url: target });
		} catch (error) {
			return err('LUX_AUTH_OAUTH_ERROR', 'Failed to start OAuth sign in', toLuxError(error));
		}
	}

	async consumeOAuthRedirect(url = browserLocation()): Promise<LuxResult<LuxAuthSessionResult>> {
		try {
			if (!url) {
				return err('LUX_AUTH_OAUTH_ERROR', 'OAuth redirect URL is missing');
			}
			const parsed = new URL(url);
			const params = new URLSearchParams(parsed.hash.replace(/^#/, ''));
			const accessToken = params.get('access_token');
			const refreshToken = params.get('refresh_token');
			if (!accessToken || !refreshToken) {
				return err('LUX_AUTH_OAUTH_ERROR', 'OAuth redirect is missing session tokens');
			}
			const session = normalizeSession({
				access_token: accessToken,
				refresh_token: refreshToken,
				expires_in: Number(params.get('expires_in') || 0),
				token_type: 'bearer',
				user: { id: '', email: '' },
			});
			if (this.httpUrl) {
				const user = await this.getUser(accessToken);
				if (user.error) return user as LuxResult<LuxAuthSessionResult>;
				session.user = user.data.user;
			}
			await this.saveSession(session, 'SIGNED_IN');
			return ok({ session, user: session.user });
		} catch (error) {
			return err('LUX_AUTH_OAUTH_ERROR', 'Failed to consume OAuth redirect', toLuxError(error));
		}
	}

	async refreshSession(refreshToken: string): Promise<LuxResult<LuxAuthSessionResult>> {
		try {
			const session = await this.requestRaw<LuxAuthSession>('/auth/v1/token', {
				method: 'POST',
				body: JSON.stringify({
					grant_type: 'refresh_token',
					refresh_token: refreshToken,
				}),
				apiKey: true,
			});
			await this.saveSession(normalizeSession(session), 'TOKEN_REFRESHED');
			return ok({ session: this.currentSession!, user: this.currentSession!.user });
		} catch (error) {
			return err('LUX_AUTH_REFRESH_ERROR', 'Failed to refresh auth session', toLuxError(error));
		}
	}

	async getUser(session?: Pick<LuxAuthSession, 'access_token'> | string): Promise<LuxResult<{ user: LuxAuthUser }>> {
		if (!session) {
			await this.getSessionValue();
		}
		try {
			return ok(await this.requestRaw<{ user: LuxAuthUser }>('/auth/v1/user', {
				method: 'GET',
				token: this.tokenFrom(session),
			}));
		} catch (error) {
			return err('LUX_AUTH_USER_ERROR', 'Failed to get auth user', toLuxError(error));
		}
	}

	async logout(sessionOrRefreshToken?: Pick<LuxAuthSession, 'access_token' | 'refresh_token'> | string): Promise<LuxResult<true>> {
		if (!sessionOrRefreshToken) {
			sessionOrRefreshToken = await this.getSessionValue() ?? undefined;
		}
		const token = typeof sessionOrRefreshToken === 'string'
			? sessionOrRefreshToken
			: sessionOrRefreshToken?.access_token;
		const refreshToken = typeof sessionOrRefreshToken === 'string'
			? undefined
			: sessionOrRefreshToken?.refresh_token;
		let logoutError: unknown;
		try {
			await this.requestRaw('/auth/v1/logout', {
				method: 'POST',
				token,
				body: JSON.stringify(refreshToken ? { refresh_token: refreshToken } : {}),
			});
		} catch (error) {
			logoutError = error;
		}

		try {
			// Local sign-out must not depend on the remote session still being
			// valid. The server may already have revoked or expired it.
			await this.clearSessionValue();
		} catch (error) {
			return err('LUX_AUTH_LOGOUT_ERROR', 'Failed to clear the local auth session', {
				logout: logoutError ? toLuxError(logoutError) : null,
				storage: toLuxError(error),
			});
		}

		if (logoutError) {
			return err('LUX_AUTH_LOGOUT_ERROR', 'Remote logout failed; local session was cleared', toLuxError(logoutError));
		}
		return ok(true);
	}

	async signOut(): Promise<LuxResult<true>> {
		return this.logout();
	}

	async listUsers(): Promise<LuxResult<LuxAuthUser[]>> {
		try {
			const result = await this.requestRaw<{ users: LuxAuthUser[] }>('/auth/v1/admin/users', {
				method: 'GET',
				secret: true,
			});
			return ok(result.users);
		} catch (error) {
			return err('LUX_AUTH_ADMIN_ERROR', 'Failed to list auth users', toLuxError(error));
		}
	}

	async grantCapability(userId: string, capability: string): Promise<LuxResult<{ id: string; user_id: string; capability: string; created_at: string }>> {
		try {
			const result = await this.requestRaw<{ grant: { id: string; user_id: string; capability: string; created_at: string } }>('/auth/v1/admin/grants', {
				method: 'POST',
				secret: true,
				body: JSON.stringify({ user_id: userId, capability }),
			});
			return ok(result.grant);
		} catch (error) {
			return err('LUX_AUTH_ADMIN_ERROR', 'Failed to grant capability', toLuxError(error));
		}
	}

	async listUserGrants(userId: string): Promise<LuxResult<string[]>> {
		try {
			const result = await this.requestRaw<{ grants: string[] }>(`/auth/v1/admin/users/${encodeURIComponent(userId)}/grants`, {
				method: 'GET',
				secret: true,
			});
			return ok(result.grants);
		} catch (error) {
			return err('LUX_AUTH_ADMIN_ERROR', 'Failed to list user grants', toLuxError(error));
		}
	}

	async revokeGrant(grantId: string): Promise<LuxResult<true>> {
		try {
			await this.requestRaw(`/auth/v1/admin/grants/${encodeURIComponent(grantId)}`, {
				method: 'DELETE',
				secret: true,
			});
			return ok(true);
		} catch (error) {
			return err('LUX_AUTH_ADMIN_ERROR', 'Failed to revoke grant', toLuxError(error));
		}
	}

	async listApiKeys(): Promise<LuxResult<LuxAuthKey[]>> {
		try {
			const result = await this.requestRaw<{ keys: LuxAuthKey[] }>('/auth/v1/admin/keys', {
				method: 'GET',
				secret: true,
			});
			return ok(result.keys);
		} catch (error) {
			return err('LUX_AUTH_ADMIN_ERROR', 'Failed to list API keys', toLuxError(error));
		}
	}

	async listProviders(): Promise<LuxResult<LuxAuthProvider[]>> {
		try {
			const result = await this.requestRaw<{ providers: LuxAuthProvider[] }>('/auth/v1/admin/providers', {
				method: 'GET',
				secret: true,
			});
			return ok(result.providers);
		} catch (error) {
			return err('LUX_AUTH_ADMIN_ERROR', 'Failed to list auth providers', toLuxError(error));
		}
	}

	async upsertProvider(options: LuxUpsertProviderOptions): Promise<LuxResult<LuxAuthProvider>> {
		try {
			const result = await this.requestRaw<{ provider: LuxAuthProvider }>(
				`/auth/v1/admin/providers/${encodeURIComponent(options.provider)}`,
				{
					method: 'PUT',
					secret: true,
					body: JSON.stringify(options),
				},
			);
			return ok(result.provider);
		} catch (error) {
			return err('LUX_AUTH_ADMIN_ERROR', 'Failed to update auth provider', toLuxError(error));
		}
	}

	async createApiKey(options: LuxCreateApiKeyOptions): Promise<LuxResult<{ key: LuxAuthKey; plain_key: string }>> {
		try {
			return ok(await this.requestRaw<{ key: LuxAuthKey; plain_key: string }>('/auth/v1/admin/keys', {
				method: 'POST',
				secret: true,
				body: JSON.stringify(options),
			}));
		} catch (error) {
			return err('LUX_AUTH_ADMIN_ERROR', 'Failed to create API key', toLuxError(error));
		}
	}

	async revokeApiKey(keyId: string): Promise<LuxResult<true>> {
		try {
			await this.requestRaw(`/auth/v1/admin/keys/${encodeURIComponent(keyId)}`, {
				method: 'DELETE',
				secret: true,
			});
			return ok(true);
		} catch (error) {
			return err('LUX_AUTH_ADMIN_ERROR', 'Failed to revoke API key', toLuxError(error));
		}
	}

	async get<T = unknown>(path: string, session?: Pick<LuxAuthSession, 'access_token'> | string): Promise<LuxResult<T>> {
		return this.requestResult<T>(path, { method: 'GET', token: this.tokenFrom(session) });
	}

	async post<T = unknown>(path: string, body?: unknown, session?: Pick<LuxAuthSession, 'access_token'> | string): Promise<LuxResult<T>> {
		return this.requestResult<T>(path, {
			method: 'POST',
			token: this.tokenFrom(session),
			body: body == null ? undefined : JSON.stringify(body),
		});
	}

	async put<T = unknown>(path: string, body?: unknown, session?: Pick<LuxAuthSession, 'access_token'> | string): Promise<LuxResult<T>> {
		return this.requestResult<T>(path, {
			method: 'PUT',
			token: this.tokenFrom(session),
			body: body == null ? undefined : JSON.stringify(body),
		});
	}

	async delete<T = unknown>(path: string, session?: Pick<LuxAuthSession, 'access_token'> | string): Promise<LuxResult<T>> {
		return this.requestResult<T>(path, { method: 'DELETE', token: this.tokenFrom(session) });
	}

	private tokenFrom(session?: Pick<LuxAuthSession, 'access_token'> | string): string | undefined {
		return typeof session === 'string' ? session : session?.access_token ?? this.authToken;
	}

	private async loadStoredSession(): Promise<void> {
		if (this.loadedSession) return;
		this.loadedSession = true;
		if (!this.persistSession || !this.storage) return;
		const raw = await this.storage.getItem(this.storageKey);
		this.storedSessionRaw = raw;
		if (!raw) return;
		try {
			const session = normalizeSession(JSON.parse(raw));
			this.currentSession = session;
			this.authToken = session.access_token;
			this.scheduleRefresh(session);
		} catch {
			await this.storage.removeItem(this.storageKey);
		}
	}

	private async saveSession(session: LuxAuthSession, event: LuxAuthChangeEvent): Promise<void> {
		this.currentSession = session;
		this.authToken = session.access_token;
		this.loadedSession = true;
		const raw = JSON.stringify(session);
		this.storedSessionRaw = raw;
		if (this.persistSession && this.storage) {
			await this.storage.setItem(this.storageKey, raw);
		}
		this.scheduleRefresh(session);
		this.emit(event, session);
		this.broadcast(event, raw);
	}

	private scheduleRefresh(session: LuxAuthSession): void {
		this.clearRefreshTimer();
		if (!this.autoRefreshToken || !session.refresh_token || !session.expires_at) return;
		const delayMs = Math.max(0, (session.expires_at - this.refreshMarginSeconds) * 1000 - Date.now());
		this.refreshTimer = setTimeout(() => {
			void this.refreshSession(session.refresh_token).catch(() => {
				void this.clearSessionValue();
			});
		}, delayMs);
	}

	private clearRefreshTimer(): void {
		if (this.refreshTimer) {
			clearTimeout(this.refreshTimer);
			this.refreshTimer = null;
		}
	}

	private initializeBrowserLifecycle(): void {
		if (!this.persistSession || typeof globalThis === 'undefined') return;
		const document = (globalThis as any).document;
		if (!document) return;

		const BroadcastChannelImpl = (globalThis as any).BroadcastChannel;
		if (BroadcastChannelImpl) {
			this.broadcastChannel = new BroadcastChannelImpl(this.storageKey);
			this.broadcastChannel?.addEventListener('message', (event) => {
				const message = event.data as {
					event?: LuxAuthChangeEvent;
					raw?: string | null;
				} | undefined;
				if (!message || !('raw' in message)) return;
				void this.applyExternalSession(message.raw ?? null, message.event);
			});
		}

		if (document?.addEventListener) {
			document.addEventListener('visibilitychange', () => {
				if (document.visibilityState === 'visible') {
					void this.recoverStoredSession(true);
				}
			});
		}
	}

	private async recoverStoredSession(notify: boolean): Promise<void> {
		if (!this.persistSession || !this.storage) return;
		const raw = await this.storage.getItem(this.storageKey);
		await this.applyExternalSession(
			raw,
			undefined,
			notify,
		);
	}

	private async applyExternalSession(
		raw: string | null,
		event?: LuxAuthChangeEvent,
		notify = true,
	): Promise<void> {
		if (raw === this.storedSessionRaw) return;

		const previousSession = this.currentSession;
		this.storedSessionRaw = raw;
		this.loadedSession = true;

		if (!raw) {
			this.currentSession = null;
			this.authToken = undefined;
			this.clearRefreshTimer();
			if (notify && previousSession) this.emit('SIGNED_OUT', null);
			return;
		}

		try {
			const session = normalizeSession(JSON.parse(raw));
			this.currentSession = session;
			this.authToken = session.access_token;
			this.scheduleRefresh(session);
			if (notify) {
				this.emit(event ?? (previousSession ? 'SESSION_UPDATED' : 'SIGNED_IN'), session);
			}
		} catch {
			this.currentSession = null;
			this.authToken = undefined;
			this.clearRefreshTimer();
			this.storedSessionRaw = null;
			await this.storage?.removeItem(this.storageKey);
			if (notify && previousSession) this.emit('SIGNED_OUT', null);
		}
	}

	private broadcast(event: LuxAuthChangeEvent, raw: string | null): void {
		this.broadcastChannel?.postMessage({ event, raw });
	}

	private emit(event: LuxAuthChangeEvent, session: LuxAuthSession | null): void {
		for (const listener of this.listeners) {
			listener(event, session);
		}
	}

	private async requestResult<T = unknown>(path: string, init: {
		method: string;
		body?: string;
		apiKey?: boolean;
		secret?: boolean;
		token?: string;
	}): Promise<LuxResult<T>> {
		try {
			return ok(await this.requestRaw<T>(path, init));
		} catch (error) {
			return err('LUX_AUTH_REQUEST_ERROR', 'Lux auth request failed', toLuxError(error));
		}
	}

	private async requestRaw<T = unknown>(path: string, init: {
		method: string;
		body?: string;
		apiKey?: boolean;
		secret?: boolean;
		token?: string;
	}): Promise<T> {
		if (!this.httpUrl) {
			throw new Error('Lux auth requires httpUrl');
		}
		const headers: Record<string, string> = {
			Accept: 'application/json',
		};
		if (init.body != null) {
			headers['Content-Type'] = 'application/json';
		}
		const token = init.token ?? this.authToken;
		if (token) {
			headers.Authorization = `Bearer ${token}`;
		}
		if ((init.apiKey || init.secret) && this.apiKey) {
			headers.apikey = this.apiKey;
		}
		const response = await this.fetchImpl(`${this.httpUrl}${path}`, {
			method: init.method,
			headers,
			body: init.body,
		});
		const text = await response.text();
		const payload = text ? JSON.parse(text) : {};
		if (!response.ok) {
			const message = payload?.error || `Lux auth request failed with HTTP ${response.status}`;
			throw new Error(message);
		}
		return payload as T;
	}
}

function normalizeSession(session: LuxAuthSession): LuxAuthSession {
	return {
		...session,
		expires_at: session.expires_at ?? Math.floor(Date.now() / 1000) + Number(session.expires_in || 0),
	};
}

function isExpired(session: LuxAuthSession, marginSeconds = 0): boolean {
	return Boolean(session.expires_at && session.expires_at <= Math.floor(Date.now() / 1000) + marginSeconds);
}

function defaultBrowserStorage(): LuxAuthStorage | null {
	if (typeof globalThis === 'undefined') return null;
	const storage = (globalThis as any).localStorage;
	if (!storage) return null;
	return {
		getItem: (key) => storage.getItem(key),
		setItem: (key, value) => storage.setItem(key, value),
		removeItem: (key) => storage.removeItem(key),
	};
}

function resolveFetch(fetchImpl?: typeof fetch): typeof fetch {
	const candidate = fetchImpl ?? globalThis.fetch;
	if (!candidate) {
		throw new Error('Lux auth requires a fetch implementation');
	}
	if (typeof globalThis !== 'undefined' && candidate === globalThis.fetch) {
		return candidate.bind(globalThis) as typeof fetch;
	}
	return candidate;
}

function browserLocation(): string {
	if (typeof globalThis === 'undefined') return '';
	return String((globalThis as any).location?.href || '');
}
