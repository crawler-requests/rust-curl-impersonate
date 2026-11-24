import type { ReactNode } from "react";
import {
  AndroidOutlined,
  BookOutlined,
  ClusterOutlined,
  FileSearchOutlined,
  FireOutlined,
  ForkOutlined,
  LockOutlined,
  NodeExpandOutlined,
  PartitionOutlined,
  SwapOutlined,
  SyncOutlined,
  UnorderedListOutlined,
  ApiOutlined,
  AppleOutlined,
  ChromeOutlined,
  CodeOutlined,
  CompassOutlined,
  DatabaseOutlined,
  ExperimentOutlined,
  GlobalOutlined,
  NodeIndexOutlined,
  RocketOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
  ToolOutlined,
  WindowsOutlined,
} from "@ant-design/icons";

// One mark per client family, so a reader can tell families apart at a glance
// instead of reading a list of names. The icons come from Ant Design's set:
// line drawings, one colour, sized to the label rather than to the tile.

const BY_FAMILY: Record<string, ReactNode> = {
  chrome: <ChromeOutlined />,
  firefox: <GlobalOutlined />,
  safari: <CompassOutlined />,
  ios: <AppleOutlined />,
  android: <AndroidOutlined />,
  okhttp: <ApiOutlined />,
  python: <CodeOutlined />,
  go: <RocketOutlined />,
  curl: <NodeIndexOutlined />,
  java: <DatabaseOutlined />,
  node: <NodeIndexOutlined />,
  php: <CodeOutlined />,
  openssl: <SafetyCertificateOutlined />,
  opera: <GlobalOutlined />,
  wget: <NodeIndexOutlined />,
  edge: <GlobalOutlined />,
  "360": <GlobalOutlined />,
  dotnet: <WindowsOutlined />,
  bun: <RocketOutlined />,
  perl: <CodeOutlined />,
  ruby: <CodeOutlined />,
  rust: <CodeOutlined />,
  brave: <GlobalOutlined />,
  deno: <RocketOutlined />,
  dart: <CodeOutlined />,
  erlang: <ToolOutlined />,
  cloudflare: <ThunderboltOutlined />,
  qq: <GlobalOutlined />,
};

export function familyIcon(family: string): ReactNode {
  return BY_FAMILY[family] ?? <ExperimentOutlined />;
}

/** Marks for the subject areas the site explains. */
export const AREA_ICONS = {
  why: <FireOutlined />,
  presets: <UnorderedListOutlined />,
  http3: <ThunderboltOutlined />,
  proxy: <SwapOutlined />,
  websocket: <NodeExpandOutlined />,
  override: <PartitionOutlined />,
  abi: <ClusterOutlined />,
  audit: <FileSearchOutlined />,
  limits: <LockOutlined />,
  evidence: <BookOutlined />,
  sync: <SyncOutlined />,
  fork: <ForkOutlined />,
} as const;

export type AreaIcon = keyof typeof AREA_ICONS;

/** A tinted mark above a heading, for pages built as lists of topics. */
export function AreaMark({ icon }: { icon: AreaIcon }) {
  return <span className="area-mark">{AREA_ICONS[icon]}</span>;
}

/** The icon for one of the Android stacks. */
const BY_STACK: Record<string, ReactNode> = {
  okhttp: <ApiOutlined />,
  conscrypt: <SafetyCertificateOutlined />,
  cronet: <ThunderboltOutlined />,
  webview: <GlobalOutlined />,
};

export function stackIcon(key: string): ReactNode {
  return BY_STACK[key] ?? <ExperimentOutlined />;
}
