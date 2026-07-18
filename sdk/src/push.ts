import type { LuxProjectClient } from './project';
import type { LuxResult } from './types';

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
}
