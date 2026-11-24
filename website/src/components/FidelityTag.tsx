import { Tag } from "antd";
import type { Fidelity } from "../data/library";

// Fidelity says how closely the record reproduces its capture: exact means
// every cipher, extension, signature algorithm and the HTTP/2 or quic
// parameters match; close means something a build cannot send was dropped and
// the record names what.

const LABELS: Record<string, { text: string; hint: string }> = {
  exact: { text: "exact", hint: "与抓包逐字节一致" },
  close: {
    text: "close",
    hint: "少数参数无法发出，记录中已注明",
  },
  partial: { text: "partial", hint: "只保留了部分参数" },
};

export function FidelityTag({ value }: { value: Fidelity }) {
  const entry = LABELS[value] ?? {
    text: value || "—",
    hint: "未标注",
  };
  return (
    <Tag
      bordered={false}
      title={entry.hint}
      style={
        value === "exact"
          ? { background: "#e8efe9", color: "#3f7d5a" }
          : value === "close"
            ? { background: "#f3e4dc", color: "#8f4a30" }
            : undefined
      }
    >
      {entry.text}
    </Tag>
  );
}
