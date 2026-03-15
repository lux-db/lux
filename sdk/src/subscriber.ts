import { Socket } from "net";
import type { LuxConfig } from "./types";
import { LuxConnectionError } from "./errors";

export class LuxSubscriber {
  private socket: Socket | null = null;
  private host: string;
  private port: number;
  private password?: string;
  private connected = false;
  private buffer = "";
  private listeners = new Map<string, Set<(channel: string, message: string) => void>>();

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

      this.socket.on("data", (data) => {
        this.buffer += data.toString();
        this.processBuffer();
      });

      this.socket.on("error", (err) => {
        if (!this.connected) {
          reject(new LuxConnectionError(err.message));
        }
      });

      this.socket.on("close", () => {
        this.connected = false;
      });

      this.socket.setNoDelay(true);
      this.socket.connect(this.port, this.host);
    });

    if (this.password && this.socket) {
      const cmd = `*2\r\n$4\r\nAUTH\r\n$${Buffer.byteLength(this.password)}\r\n${this.password}\r\n`;
      this.socket.write(cmd);
      await new Promise<void>((resolve) => {
        const handler = (data: Buffer) => {
          const resp = data.toString();
          if (resp.startsWith("+OK") || resp.startsWith("-")) {
            this.socket?.removeListener("data", handler);
            if (resp.startsWith("-")) throw new LuxConnectionError("AUTH failed");
            resolve();
          }
        };
        this.socket!.on("data", handler);
      });
    }
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
      this.connected = false;
    }
  }

  async subscribe(channel: string, callback: (channel: string, message: string) => void): Promise<void> {
    if (!this.socket || !this.connected) {
      throw new LuxConnectionError("not connected");
    }

    if (!this.listeners.has(channel)) {
      this.listeners.set(channel, new Set());
      const cmd = `*2\r\n$9\r\nSUBSCRIBE\r\n$${Buffer.byteLength(channel)}\r\n${channel}\r\n`;
      this.socket.write(cmd);
    }

    this.listeners.get(channel)!.add(callback);
  }

  async unsubscribe(channel: string, callback?: (channel: string, message: string) => void): Promise<void> {
    if (!this.listeners.has(channel)) return;

    if (callback) {
      this.listeners.get(channel)!.delete(callback);
      if (this.listeners.get(channel)!.size === 0) {
        this.listeners.delete(channel);
      }
    } else {
      this.listeners.delete(channel);
    }

    if (!this.listeners.has(channel) && this.socket && this.connected) {
      const cmd = `*2\r\n$11\r\nUNSUBSCRIBE\r\n$${Buffer.byteLength(channel)}\r\n${channel}\r\n`;
      this.socket.write(cmd);
    }
  }

  private processBuffer(): void {
    while (this.buffer.length > 0) {
      const result = this.parseArray(0);
      if (result === null) break;

      const [arr, consumed] = result;
      this.buffer = this.buffer.slice(consumed);

      if (Array.isArray(arr) && arr.length >= 3 && arr[0] === "message") {
        const channel = arr[1] as string;
        const message = arr[2] as string;
        const callbacks = this.listeners.get(channel);
        if (callbacks) {
          for (const cb of callbacks) {
            cb(channel, message);
          }
        }
      }
    }
  }

  private parseArray(pos: number): [unknown[], number] | null {
    if (pos >= this.buffer.length || this.buffer[pos] !== "*") return null;

    const nl = this.buffer.indexOf("\r\n", pos);
    if (nl === -1) return null;

    const count = parseInt(this.buffer.slice(pos + 1, nl), 10);
    if (count <= 0) return [[], nl + 2];

    const arr: unknown[] = [];
    let cursor = nl + 2;

    for (let i = 0; i < count; i++) {
      if (cursor >= this.buffer.length) return null;
      const type = this.buffer[cursor];

      if (type === "$") {
        const bnl = this.buffer.indexOf("\r\n", cursor);
        if (bnl === -1) return null;
        const len = parseInt(this.buffer.slice(cursor + 1, bnl), 10);
        if (len === -1) {
          arr.push(null);
          cursor = bnl + 2;
        } else {
          const end = bnl + 2 + len + 2;
          if (end > this.buffer.length) return null;
          arr.push(this.buffer.slice(bnl + 2, bnl + 2 + len));
          cursor = end;
        }
      } else if (type === ":") {
        const inl = this.buffer.indexOf("\r\n", cursor);
        if (inl === -1) return null;
        arr.push(parseInt(this.buffer.slice(cursor + 1, inl), 10));
        cursor = inl + 2;
      } else if (type === "+") {
        const snl = this.buffer.indexOf("\r\n", cursor);
        if (snl === -1) return null;
        arr.push(this.buffer.slice(cursor + 1, snl));
        cursor = snl + 2;
      } else {
        return null;
      }
    }

    return [arr, cursor];
  }
}
