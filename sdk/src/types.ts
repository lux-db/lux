export interface LuxConfig {
  host: string;
  port?: number;
  password?: string;
  maxRetries?: number;
  retryDelay?: number;
}

export type RespValue = string | number | null | RespValue[];
