import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { MenuOutlined } from "@ant-design/icons";
import { GitHubBadge } from "./GitHubBadge";
import { ClientMenu, FamilyNavList } from "./ClientMenu";

// Shared page frame: the header, the page body. Each page supplies its own
// sections.

const NAV = [
  { to: "/problem", label: "解决什么问题" },
  { to: "/library", label: "指纹库" },
  { to: "/usage", label: "用法" },
  { to: "/evidence", label: "可信度" },
];

// Under 920px the wordmark, the links and the badge no longer fit on one line
// (the badge alone is ~270px), so the header keeps the wordmark, the badge and
// one button: a sheet listing the same links, one line each.

function MobileSheet() {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const location = useLocation();

  // A navigation is also a dismissal.
  useEffect(() => {
    setOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    if (!open) return;

    function onPointerDown(event: PointerEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }

    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  return (
    <div className="mobile-nav" ref={rootRef}>
      <button
        type="button"
        className="mobile-nav__trigger"
        aria-expanded={open}
        aria-controls="mobile-nav-sheet"
        aria-label="打开导航"
        onClick={() => setOpen((value) => !value)}
      >
        <MenuOutlined />
      </button>
      {open ? (
        <div className="mobile-nav__sheet" id="mobile-nav-sheet">
          <span className="mobile-nav__group">客户端</span>
          <FamilyNavList />
          <span className="mobile-nav__group">页面</span>
          {NAV.map((item) => (
            <Link
              key={item.to}
              to={item.to}
              className={`mobile-nav__link${location.pathname === item.to ? " is-current" : ""}`}
            >
              {item.label}
            </Link>
          ))}
          <Link
            to="/clients"
            className={`mobile-nav__link${location.pathname === "/clients" ? " is-current" : ""}`}
          >
            全部客户端与覆盖范围
          </Link>
        </div>
      ) : null}
    </div>
  );
}

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
            <ClientMenu />
            {NAV.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                className={location.pathname === item.to ? "is-active" : undefined}
              >
                {item.label}
              </Link>
            ))}
          </nav>
          <GitHubBadge />
          <MobileSheet />
        </div>
      </header>
      <div className="page">{children}</div>
    </>
  );
}
