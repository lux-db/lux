export class LuxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LuxError";
  }
}

export class LuxConnectionError extends LuxError {
  constructor(message: string) {
    super(message);
    this.name = "LuxConnectionError";
  }
}
