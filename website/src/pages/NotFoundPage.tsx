import { Link } from "react-router-dom";
import { FAMILY_PAGES } from "../data/families";
import { familyIcon } from "../components/icons";

// A route nobody wrote. Rather than an apology, it offers the two things a
// visitor is most likely looking for: the client families and the library.

export function NotFoundPage() {
  return (
    <>
      <section className="hero hero--compact">
        <div className="hero__eyebrow">404</div>
        <h1 className="hero__title">
          这一页
          <br />
          还没有<b>抓到</b>。
        </h1>
        <p className="hero__lede">
          地址里的路径不存在。可能链接写错了，也可能是站点换过结构。
          下面这些入口都还在。
        </p>
        <div className="hero__actions">
          <Link className="cta" to="/">
            回到首页
          </Link>
          <Link className="cta cta--ghost" to="/library">
            指纹库
          </Link>
        </div>
      </section>

      <section className="section">
        <span className="section__kicker">按客户端找</span>
        <h2 className="section__title">六类客户端，各有各的页</h2>
        <div className="client-menu__grid notfound__families">
          {FAMILY_PAGES.map((page) => (
            <Link key={page.key} to={page.path} className="client-menu__item">
              <span className="client-menu__icon">{familyIcon(page.members[0])}</span>
              <span className="client-menu__text">
                <span className="client-menu__label">{page.nav}</span>
                <span className="client-menu__count">{page.title}</span>
              </span>
            </Link>
          ))}
        </div>
      </section>
    </>
  );
}
