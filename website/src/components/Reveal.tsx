import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

// Fades a block in once, when it first enters the viewport. One short
// transition, nothing repeating: motion is here to say "this is arriving",
// not to animate while the reader is trying to read.
//
// With `prefers-reduced-motion` the block is visible from the start.

export function Reveal({
  children,
  delay = 0,
}: {
  children: ReactNode;
  delay?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [seen, setSeen] = useState(false);
  const [reduced, setReduced] = useState(false);

  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setReduced(true);
      setSeen(true);
      return;
    }
    const node = ref.current;
    if (!node) return;
    if (typeof IntersectionObserver === "undefined") {
      setSeen(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setSeen(true);
            observer.disconnect();
          }
        }
      },
      { rootMargin: "0px 0px -12% 0px" },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  return (
    <div
      ref={ref}
      className={`reveal${seen ? " reveal--in" : ""}`}
      style={seen && !reduced ? { transitionDelay: `${delay}ms` } : undefined}
    >
      {children}
    </div>
  );
}
