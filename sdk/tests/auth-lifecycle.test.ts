import { describe, expect, test } from 'bun:test';
import { LuxAuthClient, type LuxAuthSession } from '../src/auth';

function deferred<T>() {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>(done => {resolve = done;});
	return {promise, resolve};
}

const session = (id: string): LuxAuthSession => ({
	access_token: `access-${id}`, refresh_token:`refresh-${id}`, expires_in:3600,
	token_type:'bearer', user:{id,email:`${id}@example.test`},
});

describe('auth operation ordering', () => {
	test('initial persisted-session loading does not invalidate its pending refresh', async () => {
		const response = deferred<Response>();
		let stored: string | null = JSON.stringify(session('old'));
		const auth = new LuxAuthClient({httpUrl:'http://localhost',autoRefreshToken:false,persistSession:true,
			storage:{getItem:async () => stored,setItem:(_key,value) => {stored=value;},removeItem:() => {stored=null;}},
			fetch:(() => response.promise) as typeof fetch});
		const loading = auth.getSession();
		const refresh = auth.refreshSession('refresh-old');
		await loading;
		response.resolve(Response.json(session('rotated')));
		expect((await refresh).error).toBeNull();
		expect((await auth.getSession()).data?.session?.user.id).toBe('rotated');
	});

	test('a delayed initial read cannot restore a cleared session', async () => {
		const read = deferred<string | null>(); const started = deferred<void>();
		let first = true;
		const auth = new LuxAuthClient({autoRefreshToken:false,persistSession:true,storage:{
			getItem:() => {if (first) {first=false; started.resolve(); return read.promise;} return null;},
			setItem:() => {}, removeItem:() => {},
		}});
		const loading = auth.getSession(); await started.promise;
		await auth.clearSession(); read.resolve(JSON.stringify(session('old')));
		await loading;
		expect((await auth.getSession()).data?.session).toBeNull();
	});

	test.each(['clear', 'replace', 'logout'] as const)('late refresh cannot reverse %s', async action => {
		const response = deferred<Response>();
		const started = deferred<void>();
		const auth = new LuxAuthClient({httpUrl:'http://localhost', autoRefreshToken:false,
			fetch:(async (url) => {
				if (String(url).endsWith('/logout')) return new Response('{}');
				started.resolve(); return response.promise;
			}) as typeof fetch,
		});
		await auth.setSession(session('old'));
		const pending = auth.refreshSession('refresh-old'); await started.promise;
		if (action === 'clear') await auth.clearSession();
		if (action === 'replace') await auth.setSession(session('new'));
		if (action === 'logout') await auth.signOut();
		response.resolve(Response.json(session('rotated-old')));
		expect((await pending).error).not.toBeNull();
		expect((await auth.getSession()).data?.session?.user.id ?? null).toBe(action === 'replace' ? 'new' : null);
	});

	test('late sign-in cannot undo local session clear', async () => {
		const response = deferred<Response>();
		const auth = new LuxAuthClient({httpUrl:'http://localhost',autoRefreshToken:false,
			fetch:(() => response.promise) as typeof fetch});
		const signin = auth.signInAnonymously();
		await auth.clearSession();
		response.resolve(Response.json(session('late')));
		expect((await signin).error).not.toBeNull();
		expect((await auth.getSession()).data?.session).toBeNull();
	});

	test('late logout does not clear a new session', async () => {
		const response = deferred<Response>(); const started = deferred<void>();
		const auth = new LuxAuthClient({httpUrl:'http://localhost',autoRefreshToken:false,
			fetch:(() => {started.resolve(); return response.promise;}) as typeof fetch});
		await auth.setSession(session('old'));
		const logout = auth.signOut(); await started.promise;
		await auth.setSession(session('new'));
		response.resolve(Response.json({})); await logout;
		expect((await auth.getSession()).data?.session?.user.id).toBe('new');
	});

	test('a delayed storage write cannot survive a later clear', async () => {
		const write = deferred<void>(); const started = deferred<void>();
		let stored: string | null = null;
		const auth = new LuxAuthClient({autoRefreshToken:false,persistSession:true,storage:{
			getItem:() => stored,
			setItem:async (_key, value) => {started.resolve(); await write.promise; stored=value;},
			removeItem:() => {stored=null;},
		}});
		const saving = auth.setSession(session('old')); await started.promise;
		const clearing = auth.clearSession(); write.resolve();
		await Promise.all([saving,clearing]);
		expect(stored).toBeNull();
		expect((await auth.getSession()).data?.session).toBeNull();
	});
});
