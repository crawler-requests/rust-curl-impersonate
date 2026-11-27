import { useEffect, useState } from "react";
import { GithubOutlined, StarFilled } from "@ant-design/icons";
import { isFresh, readStarRecord, writeStarRecord } from "../data/starCache";

// A GitHub repository badge in the header: the mark, the repository name and
// its star count, fetched from the GitHub API.
//
// The API allows 60 anonymous requests an hour per address, so the count is
// kept in IndexedDB for half an hour (src/data/starCache.ts). A cached count
// paints as soon as the read completes; when it is older than the TTL it still
// paints, and a fresh fetch replaces it in place. Only a visit with no record
// at all starts without a number.
//
// A failed fetch (offline, rate limited, blocked) leaves the last known count
// in place, or no count at all if there never was one; the badge stays.

const REPO = "crawler-requests/rust-curl-impersonate";
const URL = `https://github.com/${REPO}`;

// One decimal below ten thousand reads precisely ("4.3k"); above that the
// decimal is noise ("12k"), and a million - unreachable for this repo but
// cheap to handle - becomes "1.2M" rather than "1000k".
function formatStars(count: number): string {
  if (count < 1000) return String(count);
  if (count < 10000) return `${(count / 1000).toFixed(1)}k`;
  if (count < 999500) return `${Math.round(count / 1000)}k`;
  return `${(count / 1000000).toFixed(1)}M`;
}

// Shared across mounts so a remount while the request is in flight (React
// Strict Mode's double effect, a route change) does not spend the quota twice.
// It is released when the request settles, so a later stale cache can fetch
// again rather than replaying the first answer.
let inflight: Promise<number | null> | null = null;

function fetchStars(): Promise<number | null> {
  if (inflight) return inflight;

  inflight = fetch(`https://api.github.com/repos/${REPO}`, {
    headers: { Accept: "application/vnd.github+json" },
  })
    .then((response) => (response.ok ? response.json() : null))
    .then((data: { stargazers_count?: number } | null) => {
      if (!data || typeof data.stargazers_count !== "number") return null;
      void writeStarRecord(REPO, { stars: data.stargazers_count, at: Date.now() });
      return data.stargazers_count;
    })
    .catch(() => null)
    .finally(() => {
      inflight = null;
    });

  return inflight;
}

export function GitHubBadge() {
  // `null` means "not known yet"; the badge renders without a count until it
  // is, so the header never reserves space it then throws away.
  const [stars, setStars] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const paint = (count: number) => {
      if (!cancelled) setStars(count);
    };

    void readStarRecord(REPO).then((record) => {
      if (cancelled) return;
      if (record) {
        paint(record.stars);
        if (isFresh(record)) return;
      }
      void fetchStars().then((count) => {
        if (count !== null) paint(count);
      });
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
