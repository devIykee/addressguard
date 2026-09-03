/**
 * Structured logging. One interface, injected everywhere — no module reaches
 * for a global logger, so tests can assert on warnings (the
 * `SimilarityStrategy` contract requires malformed input to be logged rather
 * than thrown) without capturing stdout.
 */
export interface Logger {
  debug(message: string, fields?: Readonly<Record<string, unknown>>): void;
  info(message: string, fields?: Readonly<Record<string, unknown>>): void;
  warn(message: string, fields?: Readonly<Record<string, unknown>>): void;
  error(message: string, fields?: Readonly<Record<string, unknown>>): void;
}
