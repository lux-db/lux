import type { LuxProjectClient } from './project';
import type { LuxResult } from './types';
import { err, toLuxError } from './utils';

export interface LuxPushDevice {
	id: string;
	subject_id?: string;
	platform: string;
	app_id: string;
	created_at: string;
	last_seen_at: string;
}

export interface LuxPushRegisterOptions {
	/** The platform push token (APNs hex device token, Web Push subscription, etc.). */
	token: string;
	/** Defaults to `'ios'`. */
	platform?: string;
	/** App/credential set to route through. Defaults to `'default'`. */
	app_id?: string;
}

/** A notification. `title`/`body` render the alert; the rest map to APNs `aps`
 *  fields (and their platform equivalents). `data` arrives in the client. */
export interface LuxPushNotification {
	title?: string;
	body?: string;
	subtitle?: string;
	/** Lock-screen grouping key (APNs `thread-id`). */
	thread_id?: string;
	/** Notification category (action buttons). */
	category?: string;
	sound?: string;
	badge?: number;
	/** Image URL; flips `mutable-content` so a notification-service-extension
	 *  can attach a thumbnail. */
	image?: string;
	mutable_content?: boolean;
	/** Silent/background delivery (APNs `content-available`). */
	content_available?: boolean;
	/** Arbitrary string key/values delivered to the client. */
	data?: Record<string, string>;
}

/**
 * `db.push` — device registration + delivery, keyed by an opaque **subject id**.
 * A subject id MAY be a Lux auth user id but doesn't have to be, so push works
 * with or without Lux auth. Registering with a user session self-registers
 * (subject = `auth.uid()`); a trusted **secret-key** caller registers and sends
 * on any subject's behalf.
 */
export class LuxPushNamespace {
	constructor(private client: LuxProjectClient<any>) {}

	/** Register the CURRENT user's device (subject = `auth.uid()`). Needs a session. */
	async register(options: LuxPushRegisterOptions): Promise<LuxResult<{ id: string }>> {
		return this.client.request('POST', '/push/devices', {
			token: options.token,
			platform: options.platform ?? 'ios',
			app_id: options.app_id ?? 'default',
		});
	}

	/** Register a device for an explicit subject id. Requires a secret key. */
	async registerFor(
		subjectId: string,
		options: LuxPushRegisterOptions,
	): Promise<LuxResult<{ id: string }>> {
		return this.client.request('POST', '/push/devices', {
			subject_id: subjectId,
			token: options.token,
			platform: options.platform ?? 'ios',
			app_id: options.app_id ?? 'default',
		});
	}

	/** Remove a device by id. */
	async unregister(id: string): Promise<LuxResult<{ deleted: boolean }>> {
		return this.client.request('DELETE', `/push/devices/${encodeURIComponent(id)}`);
	}

	/** List a subject's active devices. With a user session, omit `subjectId` to
	 *  list your own; with a secret key, pass the subject. */
	async devices(subjectId?: string): Promise<LuxResult<LuxPushDevice[]>> {
		const path = subjectId
			? `/push/devices?subject_id=${encodeURIComponent(subjectId)}`
			: '/push/devices';
		const res = await this.client.request<{ devices: LuxPushDevice[] }>('GET', path);
		if (res.error) return { data: null, error: res.error };
		return { data: res.data?.devices ?? [], error: null };
	}

	/** Send a notification to one subject or many at once. Requires a secret key. */
	async send(
		subjects: string | string[],
		notification: LuxPushNotification,
	): Promise<LuxResult<{ enqueued: number }>> {
		const body = Array.isArray(subjects)
			? { subject_ids: subjects, notification }
			: { subject_id: subjects, notification };
		return this.client.request('POST', '/push/send', body);
	}

	// ── Web Push (VAPID) ──

	/** The project's VAPID public key (the browser `applicationServerKey`). */
	async getVapidPublicKey(): Promise<LuxResult<string>> {
		const res = await this.client.request<{ public_key: string }>('GET', '/push/vapid');
		if (res.error) return { data: null, error: res.error };
		return { data: res.data?.public_key ?? '', error: null };
	}

	/**
	 * Browser helper: prompt for notification permission, subscribe via the
	 * service worker's PushManager using the project VAPID key, and register the
	 * subscription. Requires an active service worker. Pass `vapidPublicKey` to
	 * skip the network fetch, or `serviceWorker` to use a specific registration.
	 */
	async subscribeWebPush(
		options: { vapidPublicKey?: string; serviceWorker?: ServiceWorkerRegistration } = {},
	): Promise<LuxResult<{ id: string }>> {
		try {
			const key = options.vapidPublicKey ?? (await this.getVapidPublicKey()).data ?? '';
			if (!key) return err('LUX_PUSH_NO_VAPID', 'No VAPID public key is configured');
			if (typeof Notification === 'undefined' || !navigator?.serviceWorker) {
				return err('LUX_PUSH_UNSUPPORTED', 'Web Push is not available in this environment');
			}
			const permission = await Notification.requestPermission();
			if (permission !== 'granted') {
				return err('LUX_PUSH_PERMISSION_DENIED', 'Notification permission was not granted');
			}
			const registration = options.serviceWorker ?? (await navigator.serviceWorker.ready);
			const subscription = await registration.pushManager.subscribe({
				userVisibleOnly: true,
				applicationServerKey: urlBase64ToUint8Array(key),
			});
			return this.register({ token: JSON.stringify(subscription), platform: 'web' });
		} catch (e) {
			return err('LUX_PUSH_SUBSCRIBE_ERROR', 'Web push subscribe failed', toLuxError(e));
		}
	}
}

/** Decode a base64url VAPID key into the byte array PushManager expects. */
function urlBase64ToUint8Array(base64: string): Uint8Array<ArrayBuffer> {
	const padding = '='.repeat((4 - (base64.length % 4)) % 4);
	const normalized = (base64 + padding).replace(/-/g, '+').replace(/_/g, '/');
	const raw = atob(normalized);
	const out = new Uint8Array(new ArrayBuffer(raw.length));
	for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
	return out;
}
