// Colours and type for the whole site.
//
// The palette follows Claude Code's own documentation site: a warm paper
// background rather than pure white, near-black text with a warm cast,
// orange as the only saturated accent, and quiet grey borders. Numbers here
// are the single source of truth; the Ant Design theme and the stylesheet
// both read from them so a change lands everywhere.

export const palette = {
  paper: "#faf9f5",
  paperRaised: "#f2f0e8",
  ink: "#191917",
  inkSoft: "#3d3b36",
  inkMuted: "#6b6862",
  line: "#e2ded2",
  accent: "#d97757",
  accentSoft: "#f3e4dc",
  accentInk: "#8f4a30",
  code: "#1d1c1a",
  codeInk: "#ece8dd",
  ok: "#3f7d5a",
} as const;

export const fonts = {
  display: '"Tiempos Headline", "Iowan Old Style", "Palatino Linotype", Georgia, serif',
  body: '-apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif',
  mono: '"JetBrains Mono", "SFMono-Regular", Menlo, Consolas, monospace',
} as const;

export const layout = {
  maxWidth: 1120,
  radius: 12,
  radiusSmall: 8,
} as const;
