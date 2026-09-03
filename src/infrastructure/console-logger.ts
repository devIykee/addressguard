import type { Logger } from '../domain/interfaces/logger.ts';

/**
 * JSON-lines structured logger.
 *
 * One line per event, machine-parseable, written to stderr so it never mixes
 * with an HTTP response body on stdout. No log levels config, no transports —
 * a miner needs its warnings visible in a platform log drain, and nothing more.
 */
export class ConsoleLogger implements Logger {
  private readonly service: string;

  constructor(service = 'addressguard') {
    this.service = service;
  }

  debug(message: string, fields?: Readonly<Record<string, unknown>>): void {
    this.write('debug', message, fields);
  }

  info(message: string, fields?: Readonly<Record<string, unknown>>): void {
    this.write('info', message, fields);
  }

  warn(message: string, fields?: Readonly<Record<string, unknown>>): void {
    this.write('warn', message, fields);
  }

  error(message: string, fields?: Readonly<Record<string, unknown>>): void {
    this.write('error', message, fields);
  }

  private write(
    level: string,
    message: string,
    fields?: Readonly<Record<string, unknown>>,
  ): void {
    const entry = {
      ts: new Date().toISOString(),
      level,
      service: this.service,
      message,
      ...fields,
    };

    // A logger that throws would take down the request it was reporting on, so
    // serialization failure degrades to a plain message.
    let line: string;
    try {
      line = JSON.stringify(entry);
    } catch {
      line = JSON.stringify({ ts: entry.ts, level, service: this.service, message });
    }

    process.stderr.write(`${line}\n`);
  }
}

/** Discards everything. For tests and for the demo CLI, where logs are noise. */
export class NullLogger implements Logger {
  debug(): void {}
  info(): void {}
  warn(): void {}
  error(): void {}
}
