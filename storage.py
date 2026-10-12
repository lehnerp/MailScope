"""SQLite persistence: analyses + an IOC index used for pivoting and correlation."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY, filename TEXT, sha256 TEXT, uploaded_at TEXT,
    subject TEXT, sender TEXT, origin_ip TEXT, score INTEGER, verdict TEXT, level TEXT,
    report TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS iocs (analysis_id TEXT, type TEXT, value TEXT, context TEXT);
CREATE INDEX IF NOT EXISTS idx_iocs_tv ON iocs(type, value);
CREATE INDEX IF NOT EXISTS idx_iocs_aid ON iocs(analysis_id);
CREATE INDEX IF NOT EXISTS idx_an_sha ON analyses(sha256);
"""

PIVOT_TYPES = ("ip", "domain", "email", "url", "sha256", "md5", "sha1", "filename")


class Store:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.path = path
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        return c

    # ------------------------------------------------------------------ #
    def save(self, report: dict, analysis_id: str | None = None) -> str:
        aid = analysis_id or uuid.uuid4().hex[:12]
        s, sc = report["summary"], report["scoring"]
        origin = (report["trace"].get("origin") or {}).get("ip", "")
        with self._conn() as c:
            c.execute("DELETE FROM iocs WHERE analysis_id=?", (aid,))
            c.execute(
                "INSERT OR REPLACE INTO analyses VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (aid, report["file"]["filename"], report["file"]["sha256"], report["analyzed_at"],
                 s.get("subject", ""), report["identity"].get("from_addr", ""), origin,
                 sc["score"], sc["verdict"], sc["level"], json.dumps(report)),
            )
            c.executemany("INSERT INTO iocs VALUES (?,?,?,?)",
                          [(aid, i["type"], i["value"].lower(), i["context"]) for i in report["iocs"]])
        return aid

    def get(self, aid: str):
        with self._conn() as c:
            row = c.execute("SELECT * FROM analyses WHERE id=?", (aid,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["report"] = json.loads(d["report"])
        return d

    def find_by_sha(self, sha256: str):
        with self._conn() as c:
            row = c.execute("SELECT id FROM analyses WHERE sha256=? LIMIT 1", (sha256,)).fetchone()
        return row["id"] if row else None

    def list(self, q: str = "", level: str = "", limit: int = 500):
        sql = ("SELECT id, filename, uploaded_at, subject, sender, origin_ip, score, verdict, level "
               "FROM analyses WHERE 1=1")
        args: list = []
        if q:
            like = f"%{q.lower()}%"
            sql += (" AND (lower(subject) LIKE ? OR lower(sender) LIKE ? OR lower(filename) LIKE ? "
                    "OR origin_ip LIKE ? OR id IN (SELECT analysis_id FROM iocs WHERE value LIKE ?))")
            args += [like] * 5
        if level:
            sql += " AND level=?"
            args.append(level)
        sql += " ORDER BY uploaded_at DESC LIMIT ?"
        args.append(limit)
        with self._conn() as c:
            return [dict(r) for r in c.execute(sql, args)]

    def stats(self, noisy: set[str] = frozenset()):
        with self._conn() as c:
            rows = c.execute("SELECT level, COUNT(*) n FROM analyses GROUP BY level").fetchall()
            total = c.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            top_ips = c.execute(
                "SELECT value, COUNT(DISTINCT analysis_id) n FROM iocs WHERE type='ip' AND context LIKE 'Origin%' "
                "GROUP BY value HAVING n > 1 ORDER BY n DESC LIMIT 5").fetchall()
            top_domains = c.execute(
                "SELECT i.value, COUNT(DISTINCT i.analysis_id) n FROM iocs i JOIN analyses a ON a.id=i.analysis_id "
                "WHERE i.type='domain' AND a.score >= 20 GROUP BY i.value HAVING n > 1 ORDER BY n DESC LIMIT 50"
            ).fetchall()
        top_domains = [r for r in top_domains
                       if r["value"] not in noisy and not any(r["value"].endswith("." + n) for n in noisy)][:6]
        return {"total": total, "by_level": {r["level"]: r["n"] for r in rows},
                "repeat_ips": [dict(r) for r in top_ips], "repeat_domains": [dict(r) for r in top_domains]}

    def delete(self, aid: str):
        with self._conn() as c:
            c.execute("DELETE FROM iocs WHERE analysis_id=?", (aid,))
            c.execute("DELETE FROM analyses WHERE id=?", (aid,))

    # ------------------------------------------------------------------ #
    def related(self, aid: str, noisy: set[str]) -> list[dict]:
        """Other analyses sharing at least one non-noisy IOC with this one."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT a.id, a.filename, a.subject, a.sender, a.score, a.level, a.uploaded_at, i2.type, i2.value "
                "FROM iocs i1 JOIN iocs i2 ON i1.type=i2.type AND i1.value=i2.value AND i2.analysis_id<>i1.analysis_id "
                "JOIN analyses a ON a.id=i2.analysis_id WHERE i1.analysis_id=? ORDER BY a.uploaded_at DESC", (aid,)
            ).fetchall()
        out: dict[str, dict] = {}
        for r in rows:
            v = r["value"]
            if r["type"] == "domain" and (v in noisy or any(v.endswith("." + n) for n in noisy)):
                continue
            rec = out.setdefault(r["id"], {k: r[k] for k in ("id", "filename", "subject", "sender", "score",
                                                             "level", "uploaded_at")} | {"shared": []})
            if (r["type"], v) not in rec["shared"]:
                rec["shared"].append((r["type"], v))
        return sorted(out.values(), key=lambda x: -len(x["shared"]))

    def search_iocs(self, q: str, limit: int = 300):
        like = f"%{q.lower().strip()}%"
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT i.type, i.value, i.context, a.id, a.filename, a.subject, a.score, a.level, a.uploaded_at "
                "FROM iocs i JOIN analyses a ON a.id=i.analysis_id WHERE i.value LIKE ? "
                "ORDER BY a.uploaded_at DESC LIMIT ?", (like, limit))]
