import { Link } from "react-router-dom";

export function NotFoundPage() {
  return (
    <section className="hero hero--compact">
      <div className="hero__eyebrow">404</div>
      <h1 className="hero__title">这一页不存在。</h1>
      <p className="hero__lede">
        <Link to="/">回到首页</Link>，或者从顶部导航挑一个主题。
      </p>
    </section>
  );
}
