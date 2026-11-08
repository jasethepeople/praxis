export interface BetaStats {
  alpha: number;
  beta: number;
  uses: number;
  blocked: number;
  unverified: number;
  last_used_at?: string | null;
}

function gammaSample(shape: number): number {
  if (shape < 1) return gammaSample(shape + 1) * Math.pow(Math.random(), 1 / shape);
  const d = shape - 1 / 3;
  const c = 1 / Math.sqrt(9 * d);
  for (let attempt = 0; attempt < 10_000; attempt++) {
    let x = 0;
    let v = 0;
    do {
      const u1 = Math.random();
      const u2 = Math.random();
      x = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
      v = 1 + c * x;
    } while (v <= 0);
    v = v * v * v;
    const u = Math.random();
    if (u < 1 - 0.0331 * x ** 4 || Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v;
  }
  return shape;
}

export function decayedStats(stats: BetaStats, halfLifeDays: number, now = Date.now()): BetaStats {
  if (!stats.last_used_at) return { ...stats };
  const last = Date.parse(stats.last_used_at);
  if (!Number.isFinite(last) || last > now) return { ...stats };
  const ageDays = (now - last) / 86_400_000;
  const factor = Math.pow(0.5, ageDays / halfLifeDays);
  return {
    ...stats,
    alpha: 1 + Math.max(0, stats.alpha - 1) * factor,
    beta: 1 + Math.max(0, stats.beta - 1) * factor,
  };
}

export function sampleSuccess(stats: BetaStats, deterministic: boolean): number {
  const alpha = Math.min(1_000_000, Math.max(1, stats.alpha));
  const beta = Math.min(1_000_000, Math.max(1, stats.beta));
  if (deterministic) return alpha / (alpha + beta);
  const a = gammaSample(alpha);
  const b = gammaSample(beta);
  const total = a + b;
  return total > 0 && Number.isFinite(total) ? a / total : alpha / (alpha + beta);
}

export function reciprocalRankFusion(rankings: Array<{ ids: string[]; weight?: number }>, k = 60): Map<string, number> {
  const scores = new Map<string, number>();
  for (const source of rankings) {
    const weight = source.weight ?? 1;
    source.ids.forEach((id, index) => scores.set(id, (scores.get(id) ?? 0) + weight / (k + index + 1)));
  }
  return scores;
}
