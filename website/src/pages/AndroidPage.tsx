import { CodeBlock, Comment, Str } from "../components/CodeBlock";
import { AndroidLibraries } from "../components/AndroidLibraries";
import { HelloExplorer } from "../components/HelloExplorer";
import { androidFidelity, androidRecordCount } from "../data/library";

// The Android page: what makes the platform's TLS stacks hard to pin down, how
// each record was checked, and every built-in Android record.

const ISSUES = [
  {
    title: "同一库版本，不同 Android 版本发出不同握手",
    body: "OkHttp 用平台 Conscrypt 时，cipher 与扩展由系统版本决定；Android 8.1 与 9 在 TLS 1.2 下只差一个 status_request，Android 10 起才进入 TLS 1.3。",
  },
  {
    title: "应用可以自带 TLS 栈",
    body: "OkHttp 自带 BoringSSL，Conscrypt 可以被应用装成 JCA provider。同一个 Android 版本上，两个应用可能发出完全不同的 ClientHello。",
  },
  {
    title: "padding 由传输层按报文大小决定",
    body: "BoringSSL 会把 256–511 字节的 hello 补到 508 字节。padding 的长度不是客户端属性，而是当前报文长度的结果；记录若写死长度，换一个 SNI 就错了。",
  },
  {
    title: "GREASE 与后量子组会改哈希",
    body: "WebView 的 ECH GREASE 长度随机，Conscrypt 2.9 起带 1216 字节的 X25519MLKEM768 key share，两者都会改变报文大小，进而改变 padding 与 JA4。",
  },
];

const METHODS = [
  {
    title: "一条 APK 只链接一个库版本",
    body: "每个版本单独构建 APK（build.sh --variant），静态链接该版本的 jar 与 .so。抓到的握手一定来自那个构建，没有反射、没有类加载器可以替换。",
  },
  {
    title: "真实运行时不只一种",
    body: "redroid 容器（Android 8.1、9、10、12、13、14）、KVM 上的官方模拟器（Android 7.0、10）、以及一台带公网出口的云手机。",
  },
  {
    title: "逐字节比对，而不是比对参数",
    body: "每次抓包都用同一个函数算 JA4 的三段，与记录里的值直接比较；单数字格式缺陷（如 t12d129 应为 t12d1209）也在 raw 里注明并修正。",
  },
  {
    title: "发不出来的东西写进 deviations",
    body: "BoringSSL 不支持某个 cipher、组或签名算法时，记录标为 close 并在 deviations 里写明是哪一项。exact 的 22 条没有这一项。",
  },
];

export function AndroidPage() {
  return (
    <>
      <section className="hero hero--compact">
        <div className="hero__eyebrow">Android</div>
        <h1 className="hero__title">
          Android 的握手不是一个东西，
          <br />
          是<b>每个库、每个版本各一个</b>。
        </h1>
        <p className="hero__lede">
          {androidRecordCount} 条内置记录，覆盖 OkHttp、Conscrypt 平台栈、Cronet 与 WebView。
          每条都在真实 Android 运行时上抓包复现过：{androidFidelity.exact} 条逐字节一致，
          {androidFidelity.close} 条有一两项 BoringSSL 发不出来，已在记录里注明。
        </p>
      </section>

      <section className="section">
        <span className="section__kicker">难在哪</span>
        <h2 className="section__title">四个会让指纹漂移的因素</h2>
        <div className="issue-grid">
          {ISSUES.map((issue) => (
            <div className="issue-card" key={issue.title}>
              <div className="issue-card__title">{issue.title}</div>
              <div className="issue-card__body">{issue.body}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="section">
        <span className="section__kicker">怎么验证的</span>
        <h2 className="section__title">抓包，而不是复述参数</h2>
        <div className="issue-grid">
          {METHODS.map((method) => (
            <div className="issue-card" key={method.title}>
              <div className="issue-card__title">{method.title}</div>
              <div className="issue-card__body">{method.body}</div>
            </div>
          ))}
        </div>
      </section>

      <HelloExplorer />

      <AndroidLibraries />

      <section className="section">
        <span className="section__kicker">选哪个名字</span>
        <h2 className="section__title">按运行环境挑记录</h2>
        <CodeBlock>
          <Comment>{"// 平台栈：HttpsURLConnection 的默认形态\n"}</Comment>
          {"let client = Client::new(Profile::find("}
          <Str>"android_conscrypt13"</Str>
          {")?)?;\n\n"}
          <Comment>{"// OkHttp：按 Android 版本\n"}</Comment>
          {"let client = Client::new(Profile::find("}
          <Str>"android_okhttp8"</Str>
          {")?)?;\nlet client = Client::new(Profile::find("}
          <Str>"android_okhttp13"</Str>
          {")?)?;\n\n"}
          <Comment>{"// 系统 WebView 与 Cronet\n"}</Comment>
          {"let client = Client::new(Profile::find("}
          <Str>"android_webview125"</Str>
          {")?)?;\nlet client = Client::new(Profile::find("}
          <Str>"android_cronet119"</Str>
          {")?)?;\n\n"}
          <Comment>{"// 别名按 Android 版本选 OkHttp\n"}</Comment>
          {"let client = Client::new(Profile::find("}
          <Str>"android10"</Str>
          {")?)?;   "}
          <Comment>{"// 即 android_okhttp10\n"}</Comment>
        </CodeBlock>
      </section>
    </>
  );
}
