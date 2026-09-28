import { useEffect, useRef } from "react";

/** sealed: live ciphertext. unsealed: dissolves outward once. dormant: still and faint. */
export type CipherMode = "sealed" | "unsealed" | "dormant";

const GLYPHS = "0123456789abcdef";
const CW = 12.5;
const CH = 17;
const DISSOLVE_MS = 1900;

const rnd = () => GLYPHS[(Math.random() * 16) | 0];
const smooth = (a: number, b: number, x: number) => {
  const t = Math.max(0, Math.min(1, (x - a) / (b - a)));
  return t * t * (3 - 2 * t);
};

export function Cipherfield({ mode }: { mode: CipherMode }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    let w = 0;
    let h = 0;
    let cols = 0;
    let rows = 0;
    let chars: string[] = [];
    let raf = 0;
    let lastMutate = 0;
    const start = performance.now();

    const resize = () => {
      const r = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = r.width;
      h = r.height;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cols = Math.ceil(w / CW) + 1;
      rows = Math.ceil(h / CH) + 1;
      chars = Array.from({ length: cols * rows }, rnd);
    };

    // Returns how far the dissolve front has travelled (0 to 1.2).
    const draw = (now: number) => {
      const color = getComputedStyle(canvas).getPropertyValue("--glyph").trim() || "#bbb";
      ctx.clearRect(0, 0, w, h);
      ctx.font = '500 10.5px "Martian Mono", ui-monospace, monospace';
      ctx.textBaseline = "top";
      ctx.fillStyle = color;
      const cx = w / 2;
      const cy = h / 2;
      const max = Math.hypot(cx, cy);
      const front = mode === "unsealed" ? (reduce ? 1.2 : Math.min(1.2, ((now - start) / DISSOLVE_MS) * 1.2)) : 0;
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const x = c * CW;
          const y = r * CH;
          const d = Math.hypot(x + CW / 2 - cx, y + CH / 2 - cy) / max;
          // Clear the seal and its dial, fade out at the edges.
          let a = 0.85 * smooth(0.5, 0.74, d) * (1 - smooth(0.9, 1.05, d));
          if (mode === "dormant") a *= 0.5;
          if (front > 0) a *= smooth(front - 0.1, front + 0.04, d);
          if (a < 0.02) continue;
          ctx.globalAlpha = a;
          ctx.fillText(chars[r * cols + c], x, y);
        }
      }
      ctx.globalAlpha = 1;
      return front;
    };

    const loop = (now: number) => {
      let dirty = mode === "unsealed";
      if (mode === "sealed" && now - lastMutate > 120) {
        const n = Math.max(1, (chars.length * 0.02) | 0);
        for (let i = 0; i < n; i++) chars[(Math.random() * chars.length) | 0] = rnd();
        lastMutate = now;
        dirty = true;
      }
      if (dirty && draw(now) >= 1.2) return;
      raf = requestAnimationFrame(loop);
    };

    resize();
    draw(performance.now());
    if (!reduce && mode !== "dormant") raf = requestAnimationFrame(loop);
    const ro = new ResizeObserver(() => {
      resize();
      draw(performance.now());
    });
    ro.observe(canvas);
    document.fonts?.ready.then(() => draw(performance.now()));
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
    };
  }, [mode]);

  return <canvas ref={ref} className="cipherfield" aria-hidden="true" />;
}
