import type { ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { GitHubBadge } from "./GitHubBadge";

// Shared page frame: the header, the page body, the footer. Each page supplies
// its own sections.

const NAV = [
  { to: "/problem", label: "解决什么问题" },
  { to: "/android", label: "Android" },
  { to: "/library", label: "指纹库" },
  { to: "/usage", label: "用法" },
  { to: "/evidence", label: "可信度" },
];

export function Layout({ children }: { children: ReactNode }) {
  const location = useLocation();

  return (
    <>
      <header className="site-header">
        <div className="site-header__inner">
          <Link to="/" className="wordmark" style={{ textDecoration: "none" }}>
            <span className="wordmark__dot" />
            rust-curl-impersonate
          </Link>
          <nav className="site-header__links">
            {NAV.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                className={location.pathname === item.to ? "is-active" : undefined}
              >
                {item.label}
              </Link>
            ))}
            <GitHubBadge />
          </nav>
        </div>
      </header>
      <div className="page">{children}</div>
    </>
  );
}
