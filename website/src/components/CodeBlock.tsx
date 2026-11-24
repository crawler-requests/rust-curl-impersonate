import type { ReactNode } from "react";

// A dark code panel. The tokens inside are plain spans, because the snippet
// is authored here rather than parsed; keeping it simple avoids a highlighter
// that would have to ship to the browser.

export function CodeBlock({ children }: { children: ReactNode }) {
  return <pre className="code">{children}</pre>;
}

export function Comment({ children }: { children: ReactNode }) {
  return <span className="code__comment">{children}</span>;
}

export function Str({ children }: { children: ReactNode }) {
  return <span className="code__string">{children}</span>;
}
