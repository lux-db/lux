import { expect, test } from 'bun:test';
import { createClient } from '../src/project';

test('simultaneous subscriptions open one socket after asynchronous auth loading', async () => {
	let count = 0;
	class Socket {
		static CONNECTING = 0; static OPEN = 1;
		readyState = 0;
		constructor() { count++; }
		close() { this.readyState = 3; }
	}
	const client = createClient('http://localhost', 'public', {
		websocket: Socket as unknown as typeof WebSocket,
		auth: {persistSession:true, autoRefreshToken:false, storage:{
			getItem:async () => {await Bun.sleep(5); return null;},
			setItem:() => {}, removeItem:() => {},
		}},
	});
	const subscriptions = await Promise.all(Array.from({length:12}, () => client._subscribeLive({}, () => {}, () => {})));
	try { expect(count).toBe(1); } finally { for (const unsubscribe of subscriptions) unsubscribe(); }
});

test('socket construction failures return an error envelope and remove the subscription', async () => {
	class Socket {
		static CONNECTING = 0; static OPEN = 1;
		constructor() { throw new Error('unavailable socket'); }
	}
	const client = createClient('http://localhost', 'public', {websocket:Socket as unknown as typeof WebSocket});
	const result = await client.table('notes').live();
	expect(result.live).toBeNull();
	expect(result.error?.message).toBe('unavailable socket');
	expect((client as any).liveSubscriptions.size).toBe(0);
});
