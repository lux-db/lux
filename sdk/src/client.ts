import { Socket } from "net";
import type { LuxConfig, RespValue } from "./types";
import { LuxConnectionError, LuxError } from "./errors";
import { LuxSubscriber } from "./subscriber";

export class Lux {
  private socket: Socket | null = null;
  private host: string;
  private port: number;
  private password?: string;
  private connected = false;
  private chunks: Buffer[] = [];
  private buf: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  private waiting: ((chunk: Buffer<ArrayBufferLike>) => void) | null = null;
  private queue: Promise<any> = Promise.resolve();

  constructor(config: LuxConfig) {
    this.host = config.host;
    this.port = config.port || 6379;
    this.password = config.password;
  }

  async connect(): Promise<void> {
    if (this.connected) return;

    await new Promise<void>((resolve, reject) => {
      this.socket = new Socket();

      this.socket.on("connect", () => {
        this.connected = true;
        resolve();
      });

      this.socket.on("data", (data: Buffer) => {
        if (this.waiting) {
          const cb = this.waiting;
          this.waiting = null;
          cb(data);
        } else {
          this.chunks.push(data);
        }
      });

      this.socket.on("error", (err) => {
        if (!this.connected) reject(new LuxConnectionError(err.message));
      });

      this.socket.on("close", () => {
        this.connected = false;
      });

      this.socket.setNoDelay(true);
      this.socket.connect(this.port, this.host);
    });

    if (this.password) {
      await this.command("AUTH", this.password);
    }
  }

  createSubscriber(): LuxSubscriber {
    return new LuxSubscriber({ host: this.host, port: this.port, password: this.password });
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
      this.connected = false;
    }
  }

  private async fillBuffer(): Promise<void> {
    if (this.chunks.length > 0) {
      const pending = Buffer.concat(this.chunks);
      this.chunks.length = 0;
      this.buf = this.buf.length > 0 ? Buffer.concat([this.buf, pending]) : pending;
      return;
    }

    const chunk = await new Promise<Buffer>((resolve) => {
      this.waiting = resolve;
    });
    this.buf = this.buf.length > 0 ? Buffer.concat([this.buf, chunk]) : chunk;
  }

  private consume(n: number): void {
    this.buf = this.buf.subarray(n);
  }

  private async readLine(): Promise<string> {
    while (true) {
      const idx = this.buf.indexOf("\r\n");
      if (idx !== -1) {
        const line = this.buf.subarray(0, idx).toString();
        this.consume(idx + 2);
        return line;
      }
      await this.fillBuffer();
    }
  }

  private async readExact(n: number): Promise<Buffer> {
    while (this.buf.length < n) {
      await this.fillBuffer();
    }
    const result = this.buf.subarray(0, n);
    this.consume(n);
    return result;
  }

  private async readReply(): Promise<RespValue> {
    const line = await this.readLine();
    const type = line[0];
    const payload = line.slice(1);

    switch (type) {
      case "+":
        return payload;
      case "-":
        throw new LuxError(payload);
      case ":":
        return parseInt(payload, 10);
      case "$": {
        const len = parseInt(payload, 10);
        if (len === -1) return null;
        const data = await this.readExact(len + 2);
        return data.subarray(0, len).toString();
      }
      case "*": {
        const count = parseInt(payload, 10);
        if (count === -1) return null;
        if (count === 0) return [];
        const arr: RespValue[] = [];
        for (let i = 0; i < count; i++) {
          arr.push(await this.readReply());
        }
        return arr;
      }
      default:
        throw new LuxError(`unknown RESP type: ${type}`);
    }
  }

  private encode(args: (string | number)[]): string {
    let out = `*${args.length}\r\n`;
    for (const arg of args) {
      const s = String(arg);
      out += `$${Buffer.byteLength(s)}\r\n${s}\r\n`;
    }
    return out;
  }

  async command(...args: (string | number)[]): Promise<RespValue> {
    return this.enqueue(() => {
      if (!this.socket || !this.connected) {
        throw new LuxConnectionError("not connected");
      }
      this.socket.write(this.encode(args));
      return this.readReply();
    });
  }

  async pipeline(commands: (string | number)[][]): Promise<RespValue[]> {
    return this.enqueue(async () => {
      if (!this.socket || !this.connected) {
        throw new LuxConnectionError("not connected");
      }

      let encoded = "";
      for (const args of commands) {
        encoded += this.encode(args);
      }
      this.socket.write(encoded);

      const results: RespValue[] = [];
      for (let i = 0; i < commands.length; i++) {
        try {
          results.push(await this.readReply());
        } catch (e) {
          results.push(null);
        }
      }
      return results;
    });
  }

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.queue.then(fn, fn);
    this.queue = p.catch(() => {});
    return p;
  }

  async set(key: string, value: string, ttl?: number): Promise<string> {
    const args: (string | number)[] = ["SET", key, value];
    if (ttl !== undefined) args.push("EX", ttl);
    return (await this.command(...args)) as string;
  }

  async get(key: string): Promise<string | null> {
    return (await this.command("GET", key)) as string | null;
  }

  async del(...keys: string[]): Promise<number> {
    return (await this.command("DEL", ...keys)) as number;
  }

  async exists(...keys: string[]): Promise<number> {
    return (await this.command("EXISTS", ...keys)) as number;
  }

  async incr(key: string): Promise<number> {
    return (await this.command("INCR", key)) as number;
  }

  async decr(key: string): Promise<number> {
    return (await this.command("DECR", key)) as number;
  }

  async incrby(key: string, delta: number): Promise<number> {
    return (await this.command("INCRBY", key, delta)) as number;
  }

  async expire(key: string, seconds: number): Promise<number> {
    return (await this.command("EXPIRE", key, seconds)) as number;
  }

  async ttl(key: string): Promise<number> {
    return (await this.command("TTL", key)) as number;
  }

  async keys(pattern: string): Promise<string[]> {
    return (await this.command("KEYS", pattern)) as string[];
  }

  async mset(...pairs: string[]): Promise<string> {
    return (await this.command("MSET", ...pairs)) as string;
  }

  async mget(...keys: string[]): Promise<(string | null)[]> {
    return (await this.command("MGET", ...keys)) as (string | null)[];
  }

  async lpush(key: string, ...values: string[]): Promise<number> {
    return (await this.command("LPUSH", key, ...values)) as number;
  }

  async rpush(key: string, ...values: string[]): Promise<number> {
    return (await this.command("RPUSH", key, ...values)) as number;
  }

  async lpop(key: string): Promise<string | null> {
    return (await this.command("LPOP", key)) as string | null;
  }

  async rpop(key: string): Promise<string | null> {
    return (await this.command("RPOP", key)) as string | null;
  }

  async llen(key: string): Promise<number> {
    return (await this.command("LLEN", key)) as number;
  }

  async lrange(key: string, start: number, stop: number): Promise<string[]> {
    return (await this.command("LRANGE", key, start, stop)) as string[];
  }

  async hset(key: string, ...fieldValues: string[]): Promise<number> {
    return (await this.command("HSET", key, ...fieldValues)) as number;
  }

  async hget(key: string, field: string): Promise<string | null> {
    return (await this.command("HGET", key, field)) as string | null;
  }

  async hdel(key: string, ...fields: string[]): Promise<number> {
    return (await this.command("HDEL", key, ...fields)) as number;
  }

  async hgetall(key: string): Promise<Record<string, string>> {
    const arr = (await this.command("HGETALL", key)) as string[];
    const result: Record<string, string> = {};
    for (let i = 0; i < arr.length; i += 2) {
      result[arr[i]] = arr[i + 1];
    }
    return result;
  }

  async sadd(key: string, ...members: string[]): Promise<number> {
    return (await this.command("SADD", key, ...members)) as number;
  }

  async srem(key: string, ...members: string[]): Promise<number> {
    return (await this.command("SREM", key, ...members)) as number;
  }

  async smembers(key: string): Promise<string[]> {
    return (await this.command("SMEMBERS", key)) as string[];
  }

  async sismember(key: string, member: string): Promise<number> {
    return (await this.command("SISMEMBER", key, member)) as number;
  }

  async publish(channel: string, message: string): Promise<number> {
    return (await this.command("PUBLISH", channel, message)) as number;
  }

  async dbsize(): Promise<number> {
    return (await this.command("DBSIZE")) as number;
  }

  async flushdb(): Promise<string> {
    return (await this.command("FLUSHDB")) as string;
  }

  async ping(): Promise<string> {
    return (await this.command("PING")) as string;
  }
}
