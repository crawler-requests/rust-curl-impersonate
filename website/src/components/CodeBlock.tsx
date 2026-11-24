import { useRef, useState } from "react";
import type { ReactNode } from "react";
import { CheckOutlined, CopyOutlined } from "@ant-design/icons";

// A dark code panel. The tokens inside are plain spans, because the snippet
// is authored here rather than parsed; keeping it simple avoids a highlighter
// that would have to ship to the browser.
//
// The copy button reads the rendered text rather than a second copy of the
// snippet, so what is copied is always what is on screen.

export function CodeBlock({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLPreElement>(null);
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    const text = ref.current?.textContent ?? "";
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      // A blocked clipboard leaves the snippet selectable by hand.
    }
  };

  return (
    <div className="code-wrap">
      <pre className="code" ref={ref}>
        {children}
      </pre>
      <button type="button" className="code__copy" onClick={copy} aria-label="复制这段代码">
        {copied ? <CheckOutlined /> : <CopyOutlined />}
        <span>{copied ? "已复制" : "复制"}</span>
      </button>
    </div>
  );
}

export function Comment({ children }: { children: ReactNode }) {
  return <span className="code__comment">{children}</span>;
}

export function Str({ children }: { children: ReactNode }) {
  return <span className="code__string">{children}</span>;
}
