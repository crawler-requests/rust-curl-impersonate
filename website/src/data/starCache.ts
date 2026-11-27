// The star count the header badge keeps between visits, in IndexedDB.
//
// The GitHub API allows 60 anonymous requests an hour per address, so the
// badge must not fetch on every visit; a count older than half an hour is
// treated as stale and refetched. IndexedDB rather than localStorage because
// the read is asynchronous: the header paints immediately and the number fills
// in when the transaction completes, instead of the first paint waiting on a
// synchronous storage call.
//
// Every failure — no IndexedDB in a private window, a blocked upgrade, a
// corrupt record — degrades to "no cache". A missing count is better than a
// broken header.

const DB_NAME = "rust-curl-impersonate";
const DB_VERSION = 1;
const STORE = "github-stars";

export const CACHE_TTL_MS = 30 * 60 * 1000;

export interface StarRecord {
  stars: number;
  at: number;
}

// One connection per operation, closed as soon as the transaction settles: the
// badge does one read and at most one write per page load, so a pool would buy
// nothing but a version-change edge to handle.
function withStore<T>(
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest,
  fallback: T,
): Promise<T> {
  return new Promise((resolve) => {
    let request: IDBOpenDBRequest;
    try {
      if (typeof indexedDB === "undefined") {
        resolve(fallback);
        return;
      }
      request = indexedDB.open(DB_NAME, DB_VERSION);
    } catch {
      // Some browsers throw on open itself when storage is blocked.
      resolve(fallback);
      return;
    }

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE);
      }
    };
    request.onerror = () => resolve(fallback);
    request.onblocked = () => resolve(fallback);
    request.onsuccess = () => {
      const db = request.result;
      let transaction: IDBTransaction;
      try {
        transaction = db.transaction(STORE, mode);
      } catch {
        db.close();
        resolve(fallback);
        return;
      }

      let settled = false;
      const settle = (value: T) => {
        if (settled) return;
        settled = true;
        db.close();
        resolve(value);
      };

      try {
        const pending = run(transaction.objectStore(STORE));
        pending.onsuccess = () => settle(pending.result as T);
        pending.onerror = () => settle(fallback);
      } catch {
        settle(fallback);
      }
      transaction.onabort = () => settle(fallback);
    };
  });
}

export function readStarRecord(repo: string): Promise<StarRecord | null> {
  return withStore<unknown>("readonly", (store) => store.get(repo), null).then(
    (record) => {
      if (
        !record ||
        typeof record !== "object" ||
        !Number.isFinite((record as StarRecord).stars) ||
        !Number.isFinite((record as StarRecord).at)
      ) {
        return null;
      }
      const { stars, at } = record as StarRecord;
      return { stars, at };
    },
  );
}

export function writeStarRecord(repo: string, record: StarRecord): Promise<void> {
  return withStore("readwrite", (store) => store.put(record, repo), undefined);
}

// `at` is when the count was read from the API; a record is fresh while it is
// no older than the TTL, so a revisit inside the window costs no request.
export function isFresh(record: StarRecord, now = Date.now()): boolean {
  return now - record.at <= CACHE_TTL_MS;
}
