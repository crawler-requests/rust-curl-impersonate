import { useEffect, useState } from "react";
import { GithubOutlined, StarFilled } from "@ant-design/icons";

// A GitHub repository badge in the header: the mark, the repository name and
// its star count, fetched from the GitHub API.
//
// The API allows 60 anonymous requests an hour per address, so the answer is
// cached for half an hour in localStorage rather than fetched on every visit.
// A failed fetch (offline, rate limited, blocked) leaves the badge without a
// star count instead of hiding it.

const REPO = "crawler-requests/rust-curl-impersonate";
const URL = `https://github.com/${REPO}`;
const CACHE_KEY = "github-stars:" + REPO;
const TTL_MS = 30 * 60 * 1000;

interface Cached {
  stars: number;
  at: number;
}

function readCache(): number | null {
  try {
    const raw = localStorage.getItem(CACHE_KEY);
    if (!raw) return null;
    const cached = JSON.parse(raw) as Cached;
    if (!Number.isFinite(cached.stars) || Date.now() - cached.at > TTL_MS) {
      return null;
    }
    return cached.stars;
  } catch {
    // A blocked or corrupt storage behaves like no cache.
    return null;
  }
}

function writeCache(stars: number) {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify({ stars, at: Date.now() }));
  } catch {
    // Private mode can refuse the write; the count still shows this visit.
  }
}

function formatStars(count: number): string {
  return count >= 1000 ? `${(count / 1000).toFixed(1)}k` : String(count);
}

export function GitHubBadge() {
  // `null` means "not known yet"; the badge renders without a count until it
  // is, so the header never reserves space it then throws away.
  const [stars, setStars] = useState<number | null>(null);

  useEffect(() => {
    const cached = readCache();
    if (cached !== null) {
      setStars(cached);
      return;
    }

    let cancelled = false;
    fetch(`https://api.github.com/repos/${REPO}`, {
      headers: { Accept: "application/vnd.github+json" },
    })
      .then((response) => (response.ok ? response.json() : null))
      .then((data: { stargazers_count?: number } | null) => {
        if (cancelled || !data || typeof data.stargazers_count !== "number") {
          return;
        }
        writeCache(data.stargazers_count);
        setStars(data.stargazers_count);
      })
      .catch(() => {
        // Offline or blocked: leave the count unknown.
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <a
      className="github-badge"
      href={URL}
      target="_blank"
      rel="noreferrer noopener"
      title={`${REPO} · ${stars === null ? "星标数未知" : `${stars} 个 star`}`}
    >
      <GithubOutlined className="github-badge__mark" />
      <span className="github-badge__name">{REPO.split("/")[1]}</span>
      {stars !== null && (
        <span className="github-badge__stars">
          <StarFilled />
          {formatStars(stars)}
        </span>
      )}
    </a>
  );
}
