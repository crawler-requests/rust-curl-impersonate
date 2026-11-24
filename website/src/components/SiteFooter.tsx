import { Link } from "react-router-dom";

// The page frame ends in a footer: where the code is, where the evidence is,
// and the licence. Three columns rather than one line, because the repository
// and the docs are separate destinations rather than navigation links.

const REPO = "https://github.com/crawler-requests/rust-curl-impersonate";

export function SiteFooter() {
  return (
    <footer className="site-footer">
      <div className="site-footer__inner">
        <div className="site-footer__col">
          <span className="site-footer__title">rust-curl-impersonate</span>
          <span className="site-footer__text">
            curl-impersonate 的 Rust 实现。MIT 许可证。
          </span>
          <a className="site-footer__link" href={REPO} target="_blank" rel="noreferrer noopener">
            源码在 GitHub
          </a>
        </div>
        <div className="site-footer__col">
          <span className="site-footer__title">站内</span>
          <Link className="site-footer__link" to="/clients">
            客户端总览
          </Link>
          <Link className="site-footer__link" to="/library">
            指纹库
          </Link>
          <Link className="site-footer__link" to="/evidence">
            审计与可信度
          </Link>
          <Link className="site-footer__link" to="/limits">
            边界
          </Link>
        </div>
        <div className="site-footer__col">
          <span className="site-footer__title">证据</span>
          <a
            className="site-footer__link"
            href={`${REPO}/tree/main/tools/capture/raw`}
            target="_blank"
            rel="noreferrer noopener"
          >
            抓包原始文件
          </a>
          <a
            className="site-footer__link"
            href={`${REPO}/blob/main/src/fingerprint/builtin.json`}
            target="_blank"
            rel="noreferrer noopener"
          >
            builtin.json
          </a>
          <a
            className="site-footer__link"
            href={`${REPO}/blob/main/docs/reference-coverage.md`}
            target="_blank"
            rel="noreferrer noopener"
          >
            与 curl-impersonate 的覆盖对比
          </a>
        </div>
      </div>
    </footer>
  );
}
