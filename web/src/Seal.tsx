import { useEffect, useState, type CSSProperties } from "react";
import { Phase, type PhaseValue } from "./phase";

const SIZE = 320;
const C = SIZE / 2;
const RING_R = 146;
const WAX_R = 100;
const PRESS_R = 72;
const CIRC = 2 * Math.PI * RING_R;

/** A wax blob: a circle with soft irregular lobes. Deterministic. */
function blob(r: number, seed: number): string {
  const pts: string[] = [];
  const steps = 200;
  for (let i = 0; i < steps; i++) {
    const t = (i / steps) * Math.PI * 2;
    const rr = r + 4.6 * Math.sin(t * 9 + seed) + 2.6 * Math.sin(t * 4 + 1.3 + seed * 2) + 1.3 * Math.sin(t * 21 + seed);
    pts.push(`${(C + rr * Math.cos(t)).toFixed(2)},${(C + rr * Math.sin(t)).toFixed(2)}`);
  }
  return `M${pts.join("L")}Z`;
}

const WAX = blob(WAX_R, 0);
const POOL = blob(WAX_R + 8, 2.1);
const CRACK = [
  [C + 6, 0], [C - 9, 62], [C + 11, 104], [C - 5, 140], [C + 13, 176],
  [C - 11, 214], [C + 5, 256], [C - 7, SIZE],
];
const crackPts = CRACK.map(([x, y]) => `${x},${y}`).join(" ");
const LEFT = `0,0 ${crackPts} 0,${SIZE}`;
const RIGHT = `${SIZE},0 ${crackPts} ${SIZE},${SIZE}`;
const KEYHOLE = "M160 127 a15 15 0 0 1 8.6 27.3 L174 188 H146 L151.4 154.3 A15 15 0 0 1 160 127 Z";
const BEADS = Array.from({ length: 30 }, (_, i) => {
  const a = (i / 30) * Math.PI * 2;
  return [C + 86 * Math.cos(a), C + 86 * Math.sin(a)] as const;
});
const BITS = [
  { d: "M156 118 l9 -3 l2 8 l-9 2 Z", x: -64, y: -48, r: -50 },
  { d: "M164 150 l8 2 l-2 9 l-8 -3 Z", x: 74, y: -20, r: 40 },
  { d: "M154 196 l7 -2 l3 7 l-8 3 Z", x: -56, y: 60, r: 70 },
  { d: "M166 226 l8 1 l-1 8 l-8 -2 Z", x: 52, y: 66, r: -35 },
];

/**
 * The vault as a wax seal. The ring of ticks is a dial: it fills with money
 * while open, drains through the claim window while locked, and the seal
 * cracks open when the key is released.
 */
export function Seal({ phase, fill, still = false }: { phase: PhaseValue; fill: number; still?: boolean }) {
  const clamped = Math.max(0, Math.min(1, fill));
  // Normally the dial sweeps up to `fill`; `still` draws it there from the start (for the static README image).
  const [f, setF] = useState(still ? clamped : 0);
  useEffect(() => {
    const id = requestAnimationFrame(() => setF(clamped));
    return () => cancelAnimationFrame(id);
  }, [clamped]);

  const cls = [
    "seal",
    phase === Phase.Claimed && "is-broken",
    phase === Phase.Expired && "is-lapsed",
    phase === Phase.Locked && "is-locked",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <figure className={cls} aria-hidden="true">
      <svg viewBox={`0 0 ${SIZE} ${SIZE}`}>
        <defs>
          <clipPath id="seal-left">
            <polygon points={LEFT} />
          </clipPath>
          <clipPath id="seal-right">
            <polygon points={RIGHT} />
          </clipPath>
          <radialGradient id="seal-body" cx="36%" cy="30%" r="78%">
            <stop offset="0" style={{ stopColor: "var(--wax-hi)" }} />
            <stop offset="0.5" style={{ stopColor: "var(--wax)" }} />
            <stop offset="1" style={{ stopColor: "var(--wax-lo)" }} />
          </radialGradient>
          <radialGradient id="seal-press" cx="50%" cy="44%" r="64%">
            <stop offset="0" style={{ stopColor: "var(--wax)" }} />
            <stop offset="1" style={{ stopColor: "var(--wax-lo)" }} />
          </radialGradient>
          <linearGradient id="seal-rim" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" style={{ stopColor: "var(--wax-lo)" }} />
            <stop offset="1" style={{ stopColor: "var(--wax-hi)" }} />
          </linearGradient>
          <radialGradient id="seal-spill">
            <stop offset="0" style={{ stopColor: "var(--brass-hi)", stopOpacity: 0.95 }} />
            <stop offset="0.45" style={{ stopColor: "var(--brass)", stopOpacity: 0.35 }} />
            <stop offset="1" style={{ stopColor: "var(--brass)", stopOpacity: 0 }} />
          </radialGradient>
          <filter id="seal-soft">
            <feGaussianBlur stdDeviation="7" />
          </filter>
          <filter id="seal-shadow" x="-30%" y="-30%" width="160%" height="170%">
            <feDropShadow dx="0" dy="12" stdDeviation="12" floodColor="#1b1630" floodOpacity="0.32" />
          </filter>
          <mask id="seal-ring-mask">
            <circle
              className="ring-mask"
              cx={C}
              cy={C}
              r={RING_R}
              style={{ strokeDasharray: `${CIRC * f} ${CIRC}` }}
              transform={`rotate(-90 ${C} ${C})`}
            />
          </mask>
          <g id="seal-art">
            <path d={POOL} style={{ fill: "var(--wax-lo)" }} />
            <path d={WAX} fill="url(#seal-body)" />
            {BEADS.map(([x, y], i) => (
              <g key={i}>
                <circle cx={x + 0.7} cy={y + 0.9} r={2.1} style={{ fill: "var(--wax-hi)" }} opacity={0.45} />
                <circle cx={x} cy={y} r={2.1} style={{ fill: "var(--wax-lo)" }} opacity={0.7} />
              </g>
            ))}
            <circle cx={C} cy={C} r={PRESS_R} fill="url(#seal-press)" />
            <circle cx={C} cy={C} r={PRESS_R} fill="none" stroke="url(#seal-rim)" strokeWidth={5} />
            <path d={KEYHOLE} style={{ fill: "var(--wax-hi)" }} opacity={0.5} transform="translate(1.3 1.7)" />
            <path d={KEYHOLE} style={{ fill: "var(--wax-lo)" }} />
            <ellipse cx={120} cy={102} rx={34} ry={15} transform="rotate(-38 120 102)" fill="#fff" opacity={0.2} filter="url(#seal-soft)" />
          </g>
        </defs>

        <circle className="ring-ticks" cx={C} cy={C} r={RING_R} />
        <circle className="ring-lit" cx={C} cy={C} r={RING_R} mask="url(#seal-ring-mask)" />
        <g className="ring-head" style={{ transform: `rotate(${f * 360}deg)`, opacity: f > 0.005 && f < 0.995 ? 1 : 0 }}>
          <circle cx={C} cy={C - RING_R} r={4.5} />
        </g>

        <circle className="spill" cx={C} cy={C} r={WAX_R + 34} fill="url(#seal-spill)" />
        <g className="wax" filter="url(#seal-shadow)">
          <g className="wax-tone">
            <use href="#seal-art" clipPath="url(#seal-left)" className="half half-left" />
            <use href="#seal-art" clipPath="url(#seal-right)" className="half half-right" />
            {/* The uncut disc hides the seam between the halves until it breaks. */}
            <use href="#seal-art" className="whole" />
          </g>
        </g>
        {BITS.map((b, i) => (
          <path
            key={i}
            d={b.d}
            className="bit"
            style={{ "--x": `${b.x}px`, "--y": `${b.y}px`, "--r": `${b.r}deg` } as CSSProperties}
          />
        ))}
      </svg>
    </figure>
  );
}
