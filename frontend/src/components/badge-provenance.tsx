import { provenanceColors } from '@/lib/design/tokens';

type Provenance = 'Measured' | 'Simulated' | 'Generated' | 'Validated' | 'Unavailable';

export function BadgeProvenance({ state }: { state: Provenance }) {
  const color = provenanceColors[state];
  return (
    <span
      className="inline-flex items-center gap-2 rounded-full border px-3 py-1 text-[0.7rem] font-mono font-bold uppercase tracking-wide"
      style={{ borderColor: color, color }}
      aria-label={`Provenance: ${state}`}
    >
      <span className="size-1.5 rounded-full" style={{ backgroundColor: color }} />
      {state}
    </span>
  );
}
