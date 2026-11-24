// What each extension id in a captured ClientHello is for. The ids are the
// ones that actually appear in the library's records, and the notes come from
// goal-evidence/extension-registry.md, which the crate's tooling generates from
// the captures and the vendored BoringSSL.

export interface ExtensionInfo {
  /** Short name, as tls.peet.ws and the registry write it. */
  name: string;
  /** One sentence: what the server learns from it. */
  what: string;
}

export const EXTENSIONS: Record<string, ExtensionInfo> = {
  "0": { name: "server_name", what: "SNI：客户端要找哪个主机名。" },
  "5": {
    name: "status_request",
    what: "请求 OCSP stapling，让服务端把证书状态一起发来。",
  },
  "10": {
    name: "supported_groups",
    what: "支持的命名组（曲线）及其偏好顺序，决定后面 key_share 谈哪一个。",
  },
  "11": {
    name: "ec_point_formats",
    what: "老接口留下的「只用非压缩点」标记，实际内容恒为一个 0。",
  },
  "13": {
    name: "signature_algorithms",
    what: "能接受哪些签名算法；Chrome 156 起以 GREASE 与 ML-DSA 打头。",
  },
  "16": {
    name: "alpn",
    what: "应用层协议协商：h2、http/1.1，个别记录还带 h3。",
  },
  "18": {
    name: "signed_certificate_timestamp",
    what: "请求 SCT，用于证书透明日志的校验。",
  },
  "23": {
    name: "extended_master_secret",
    what: "TLS 1.2 主密钥派生方式的标记，BoringSSL 默认就发。",
  },
  "27": {
    name: "compress_certificate",
    what: "证书压缩算法（brotli / zstd / zlib），服务端按此压缩证书链。",
  },
  "28": {
    name: "record_size_limit",
    what: "单条记录的明文上限，服务端按此切分记录。",
  },
  "34": {
    name: "delegated_credentials",
    what: "RFC 9345：允许服务端出示由证书密钥签发的短时凭证。",
  },
  "35": {
    name: "session_ticket",
    what: "支持 ticket 续连的标记；真正的 pre_shared_key 只在续连时出现。",
  },
  "41": {
    name: "pre_shared_key",
    what: "TLS 1.3 续连标识；只有带着缓存的 ticket 才会发，首次连接没有。",
  },
  "43": {
    name: "supported_versions",
    what: "支持的 TLS 版本列表，TLS 1.3 协商靠它。",
  },
  "45": {
    name: "psk_key_exchange_modes",
    what: "PSK 与密钥交换的组合方式；psk_dhe_ke 表示先走一次 DHE。",
  },
  "51": {
    name: "key_share",
    what: "预先算好的临时公钥；Chrome 131 起第一个是 X25519MLKEM768。",
  },
  "4832": {
    name: "server_padding_request",
    what: "Chromium 私有扩展：请服务端把响应补齐，抵御长度侧信道。",
  },
  "13172": {
    name: "next_proto_neg",
    what: "已废弃的 NPN 协商，只有 uTLS 的 iOS 抓包还带着。",
  },
  "17513": {
    name: "application_settings_old",
    what: "ALPS 的旧码点（Chrome 124 之前），携带 HTTP/2 设置的预协商。",
  },
  "17613": {
    name: "application_settings",
    what: "ALPS 现用码点：把 HTTP/2 SETTINGS 挪进握手里预协商。",
  },
  "30032": {
    name: "channel_id",
    what: "已废弃的 ChannelID，Chrome 58–70 发的是空内容。",
  },
  "51764": {
    name: "trust_anchors",
    what: "draft-ietf-tls-trust-anchors：告诉服务端自己信任哪些根，Chrome 156 起带。",
  },
  "65037": {
    name: "encrypted_client_hello",
    what: "ECH；找不到 ECHConfig 时发的是随机长度的 GREASE 占位。",
  },
  "65281": {
    name: "renegotiation_info",
    what: "旧版重协商的兼容标记，内容为空。",
  },
};

/** A captured extension order rendered for display: id plus its name. */
export function extensionLabel(id: string): ExtensionInfo {
  return EXTENSIONS[id] ?? { name: `extension ${id}`, what: "抓包里出现、没有收录的扩展。" };
}
