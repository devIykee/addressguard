import { describe, it, expect } from 'vitest';
import type { SimilarityStrategy } from '../../src/domain/interfaces/similarity-strategy.ts';
import type { Logger } from '../../src/domain/interfaces/logger.ts';
import { INCIDENTS, MALFORMED_INPUTS, UNRELATED_PAIRS } from '../fixtures/incidents.ts';

/**
 * A logger that records instead of printing, so tests can assert that
 * malformed input was *warned about* rather than silently swallowed.
 */
export class RecordingLogger implements Logger {
  readonly entries: { level: string; message: string }[] = [];
  debug(message: string): void {
    this.entries.push({ level: 'debug', message });
  }
  info(message: string): void {
    this.entries.push({ level: 'info', message });
  }
  warn(message: string): void {
    this.entries.push({ level: 'warn', message });
  }
  error(message: string): void {
    this.entries.push({ level: 'error', message });
  }
  get warnings(): string[] {
    return this.entries.filter((e) => e.level === 'warn').map((e) => e.message);
  }
}

/**
 * The shared `SimilarityStrategy` contract.
 *
 * This is the Liskov guarantee made executable: every implementation must be
 * substitutable for any other inside `PoisoningDetectionService`, which
 * iterates them blindly. Each implementation calls this suite, so a new
 * strategy cannot quietly break an invariant the aggregator relies on — in
 * particular "never throws", which is the one that would otherwise turn a
 * single malformed history entry into a failed request.
 *
 * @param makeStrategy fresh instance per case, given a logger to record into.
 */
export function describeStrategyContract(
  name: string,
  makeStrategy: (logger: RecordingLogger) => SimilarityStrategy,
): void {
  describe(`${name} — SimilarityStrategy contract`, () => {
    it('returns a finite score within [0, 1] for well-formed input', () => {
      const strategy = makeStrategy(new RecordingLogger());
      for (const incident of INCIDENTS) {
        for (const [a, b] of [
          [incident.trusted, incident.lookalike],
          [incident.victim, incident.trusted],
          [incident.lookalike, incident.lookalike],
        ] as const) {
          const score = strategy.score(a, b);
          expect(Number.isFinite(score), `score(${a}, ${b}) must be finite`).toBe(true);
          expect(score).toBeGreaterThanOrEqual(0);
          expect(score).toBeLessThanOrEqual(1);
        }
      }
    });

    it('never throws on malformed input, and scores it 0', () => {
      const logger = new RecordingLogger();
      const strategy = makeStrategy(logger);
      const wellFormed = INCIDENTS[0].trusted;

      for (const bad of MALFORMED_INPUTS) {
        // Both argument positions, since either can carry a bad value: the
        // candidate comes from the request body, the trusted value from a
        // client-supplied array or a chain derivation.
        expect(() => strategy.score(bad, wellFormed), `score(${bad}, ok)`).not.toThrow();
        expect(() => strategy.score(wellFormed, bad), `score(ok, ${bad})`).not.toThrow();
        expect(strategy.score(bad, wellFormed)).toBe(0);
        expect(strategy.score(wellFormed, bad)).toBe(0);
      }

      expect(logger.warnings.length).toBeGreaterThan(0);
    });

    it('never throws when both inputs are malformed', () => {
      const strategy = makeStrategy(new RecordingLogger());
      for (const bad of MALFORMED_INPUTS) {
        expect(() => strategy.score(bad, bad)).not.toThrow();
        expect(strategy.score(bad, bad)).toBe(0);
      }
    });

    it('is symmetric', () => {
      const strategy = makeStrategy(new RecordingLogger());
      for (const incident of INCIDENTS) {
        expect(strategy.score(incident.trusted, incident.lookalike)).toBe(
          strategy.score(incident.lookalike, incident.trusted),
        );
      }
      for (const pair of UNRELATED_PAIRS) {
        expect(strategy.score(pair.a, pair.b)).toBe(strategy.score(pair.b, pair.a));
      }
    });

    it('is deterministic across repeated calls and fresh instances', () => {
      const first = makeStrategy(new RecordingLogger());
      const second = makeStrategy(new RecordingLogger());
      const { trusted, lookalike } = INCIDENTS[0];

      const baseline = first.score(trusted, lookalike);
      expect(first.score(trusted, lookalike)).toBe(baseline);
      expect(second.score(trusted, lookalike)).toBe(baseline);
    });

    it('is case-insensitive: EIP-55 checksum casing is not a difference', () => {
      const strategy = makeStrategy(new RecordingLogger());
      const { trusted, lookalike } = INCIDENTS[0];

      expect(strategy.score(trusted.toUpperCase().replace('0X', '0x'), lookalike)).toBe(
        strategy.score(trusted, lookalike),
      );
    });

    it('scores real incident pairs strictly above unrelated pairs', () => {
      const strategy = makeStrategy(new RecordingLogger());

      const worstIncident = Math.min(
        ...INCIDENTS.map((i) => strategy.score(i.trusted, i.lookalike)),
      );
      const bestUnrelated = Math.max(
        ...UNRELATED_PAIRS.map((p) => strategy.score(p.a, p.b)),
      );

      expect(worstIncident).toBeGreaterThan(bestUnrelated);
    });

    it('declares a stable matchType, name, and authority', () => {
      const strategy = makeStrategy(new RecordingLogger());
      expect(strategy.matchType).toBeTruthy();
      expect(strategy.name).toBeTruthy();
      expect(['primary', 'corroborating']).toContain(strategy.authority);
    });
  });
}
