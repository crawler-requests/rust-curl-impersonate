import { useEffect, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { DownOutlined } from "@ant-design/icons";
import { FAMILY_PAGES, recordsOf } from "../data/families";
import { familyIcon } from "./icons";

// The header's family menu. Android used to be the only client named up top,
// which made the other families look optional; this gives every family the
// same entry, built from FAMILY_PAGES so the menu and the routes cannot drift
// apart.
//
// It opens on click rather than on hover: a hover menu needs a bridge across
// the gap to the panel, and that is the part touch and keyboard users cannot
// cross.

/** The six family entries, shared by the desktop panel and the mobile sheet. */
export function FamilyNavList() {
  const location = useLocation();

  return (
    <div className="client-menu__grid">
      {FAMILY_PAGES.map((page) => (
        <Link
          key={page.key}
          to={page.path}
          className={`client-menu__item${location.pathname === page.path ? " is-current" : ""}`}
        >
          <span className="client-menu__icon">{familyIcon(page.members[0])}</span>
          <span className="client-menu__text">
            <span className="client-menu__label">{page.nav}</span>
            <span className="client-menu__count">{recordsOf(page).length} 条记录</span>
          </span>
        </Link>
      ))}
    </div>
  );
}

export function ClientMenu() {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const location = useLocation();
  const onFamilyPage =
    location.pathname === "/clients" ||
    FAMILY_PAGES.some((page) => page.path === location.pathname);

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
    <div className="client-menu" ref={rootRef}>
      <button
        type="button"
        className={`client-menu__trigger${onFamilyPage ? " is-current" : ""}`}
        aria-expanded={open}
        aria-controls="client-menu-panel"
        onClick={() => setOpen((value) => !value)}
      >
        客户端
        <DownOutlined className="client-menu__caret" />
      </button>
      {open ? (
        <div className="client-menu__panel" id="client-menu-panel">
          <FamilyNavList />
          <Link to="/clients" className="client-menu__all">
            全部客户端与覆盖范围
          </Link>
        </div>
      ) : null}
    </div>
  );
}
