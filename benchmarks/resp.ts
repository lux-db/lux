import { createConnection, type Socket } from "node:net";

type Parsed = { value: unknown; end: number };

function lineEnd(buffer: Buffer, offset: number): number {
  return buffer.indexOf("\r\n", offset);
}

export function parseResp(buffer: Buffer, offset = 0): Parsed | null {
  if (offset >= buffer.length) return null;
  const end = lineEnd(buffer, offset);
  if (end < 0) return null;
  const type = String.fromCharCode(buffer[offset]);
  const header = buffer.subarray(offset + 1, end).toString();
  if (type === "+") return { value: header, end: end + 2 };
  if (type === "-") return { value: new Error(header), end: end + 2 };
  if (type === ":") return { value: Number(header), end: end + 2 };
  const length = Number(header);
  if (!Number.isSafeInteger(length) || length < -1)
    throw new Error(`invalid RESP length: ${header}`);
  if (length === -1) return { value: null, end: end + 2 };
  if (type === "$") {
    const finish = end + 2 + length + 2;
    if (buffer.length < finish) return null;
    return {
      value: buffer.subarray(end + 2, finish - 2).toString(),
      end: finish,
    };
  }
  if (type !== "*") throw new Error(`unsupported RESP type: ${type}`);
  const values: unknown[] = [];
  let cursor = end + 2;
  for (let index = 0; index < length; index++) {
    const item = parseResp(buffer, cursor);
    if (!item) return null;
    values.push(item.value);
    cursor = item.end;
  }
  return { value: values, end: cursor };
}

export function encodeResp(args: string[]): Buffer {
  return Buffer.from(
    `*${args.length}\r\n` +
      args
        .map((arg) => `$${Buffer.byteLength(arg)}\r\n${arg}\r\n`)
        .join(""),
  );
}

export class RespConnection {
  private buffer = Buffer.alloc(0);
  private queued: unknown[] = [];
  private waiting: Array<{
    resolve: (value: unknown) => void;
    reject: (error: Error) => void;
  }> = [];

  private constructor(private readonly socket: Socket) {
    socket.on("data", (chunk) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      while (true) {
        const parsed = parseResp(this.buffer);
        if (!parsed) break;
        this.buffer = this.buffer.subarray(parsed.end);
        const waiter = this.waiting.shift();
        if (waiter) {
          if (parsed.value instanceof Error) waiter.reject(parsed.value);
          else waiter.resolve(parsed.value);
        } else this.queued.push(parsed.value);
      }
    });
    socket.on("error", (error) => this.rejectAll(error));
    socket.on("close", () => this.rejectAll(new Error("RESP connection closed")));
  }

  static async connect(port: number, password?: string): Promise<RespConnection> {
    const socket = createConnection({ host: "127.0.0.1", port });
    await new Promise<void>((resolve, reject) => {
      socket.once("connect", resolve);
      socket.once("error", reject);
    });
    socket.setNoDelay(true);
    const connection = new RespConnection(socket);
    if (password) await connection.request(["AUTH", password]);
    return connection;
  }

  private rejectAll(error: Error): void {
    for (const waiter of this.waiting.splice(0)) waiter.reject(error);
  }

  write(args: string[]): void {
    this.socket.write(encodeResp(args));
  }

  read(timeoutMs = 30_000): Promise<unknown> {
    if (this.queued.length) {
      const queued = this.queued.shift();
      if (queued instanceof Error) return Promise.reject(queued);
      return Promise.resolve(queued);
    }
    return new Promise((resolve, reject) => {
      const entry = {
        resolve: (value: unknown) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error: Error) => {
          clearTimeout(timer);
          reject(error);
        },
      };
      const timer = setTimeout(() => {
        const index = this.waiting.indexOf(entry);
        if (index >= 0) this.waiting.splice(index, 1);
        reject(new Error("RESP response deadline exceeded"));
      }, timeoutMs);
      this.waiting.push(entry);
    });
  }

  async request(args: string[]): Promise<unknown> {
    const response = this.read();
    this.write(args);
    return response;
  }

  async pipeline(commands: string[][]): Promise<unknown[]> {
    const responses = commands.map(() => this.read());
    for (const command of commands) this.write(command);
    return Promise.all(responses);
  }

  close(): void {
    this.socket.destroy();
  }
}

export async function loadCommands(
  port: number,
  password: string,
  commands: Iterable<string[]>,
  batchSize = 512,
): Promise<number> {
  const connection = await RespConnection.connect(port, password);
  let batch: string[][] = [];
  let completed = 0;
  try {
    for (const command of commands) {
      batch.push(command);
      if (batch.length < batchSize) continue;
      await connection.pipeline(batch);
      completed += batch.length;
      batch = [];
    }
    if (batch.length) {
      await connection.pipeline(batch);
      completed += batch.length;
    }
    return completed;
  } finally {
    connection.close();
  }
}
