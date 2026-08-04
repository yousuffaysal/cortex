"""Reproducible index benchmark against PRD §10's targets.

Targets:
  - 200k files indexed in under 15 minutes
  - index under 500 MB
  - incremental updates under 200 ms

Run:  uv run python bench/benchmark.py --files 200000 --corpus /path/to/corpus

The corpus is synthetic on purpose. Measuring against the user's real home directory
would be slower to set up, unrepeatable, impossible to compare across runs, and would
mean reading personal files to produce a number. Generation time is excluded from the
index timing — it measures the filesystem, not the indexer.
"""

from __future__ import annotations

import argparse
import random
import shutil
import statistics
import time
from pathlib import Path

from cortex_index import HashingEmbedder, IndexStore, Indexer, IndexWatcher

WORDS = """
connection pool acquire release timeout retry backoff session transaction commit
rollback cursor schema migration index query planner cache invalidate evict shard
replica primary failover heartbeat quorum consensus leader election partition
serialize deserialize encode decode compress checksum validate authenticate token
handler request response middleware router endpoint payload header status latency
throughput buffer stream chunk offset watermark checkpoint snapshot restore
""".split()

EXTENSIONS = [".py"] * 40 + [".ts"] * 25 + [".md"] * 15 + [".go"] * 10 + [".rs"] * 10


def generate(root: Path, count: int, per_dir: int = 100, seed: int = 7) -> float:
    """Create `count` code-like text files. Returns seconds spent."""
    rng = random.Random(seed)
    started = time.perf_counter()
    root.mkdir(parents=True, exist_ok=True)

    made = 0
    directory_index = 0
    while made < count:
        directory = root / f"pkg{directory_index // 50:03d}" / f"mod{directory_index % 50:03d}"
        directory.mkdir(parents=True, exist_ok=True)
        if directory_index % 37 == 0:
            (directory / ".gitignore").write_text("*.generated\nbuild/\n")

        for file_index in range(min(per_dir, count - made)):
            lines = []
            symbol = f"{rng.choice(WORDS)}_{rng.choice(WORDS)}_{file_index}"
            lines.append(f"def {symbol}(context):")
            for _ in range(rng.randint(25, 55)):
                lines.append(
                    "    "
                    + " ".join(rng.choice(WORDS) for _ in range(rng.randint(4, 12)))
                )
            lines.append(f"    return {rng.choice(WORDS)}")
            extension = rng.choice(EXTENSIONS)
            (directory / f"file{file_index:03d}{extension}").write_text("\n".join(lines))
            made += 1
        directory_index += 1

    return time.perf_counter() - started


def human_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=int, default=200_000)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--keep-corpus", action="store_true")
    parser.add_argument("--dimensions", type=int, default=256)
    args = parser.parse_args()

    corpus: Path = args.corpus
    index_path: Path = args.index

    existing = sum(1 for _ in corpus.rglob("*.py")) if corpus.exists() else 0
    if existing < args.files // 2:
        print(f"generating {args.files:,} files under {corpus} …", flush=True)
        seconds = generate(corpus, args.files)
        print(f"  generated in {seconds:.1f}s", flush=True)
    else:
        print(f"reusing existing corpus at {corpus}", flush=True)

    on_disk = sum(p.stat().st_size for p in corpus.rglob("*") if p.is_file())
    total_files = sum(1 for p in corpus.rglob("*") if p.is_file())
    print(f"corpus: {total_files:,} files, {human_bytes(on_disk)}\n", flush=True)

    if index_path.exists():
        for stale in index_path.parent.glob(index_path.name + "*"):
            stale.unlink()

    store = IndexStore(index_path, dimensions=args.dimensions)
    indexer = Indexer(store, HashingEmbedder(dimensions=args.dimensions))

    print("=== COLD INDEX ===", flush=True)
    report = indexer.index_root(corpus)
    print(f"  files indexed     {report.files_indexed:,}")
    print(f"  chunks written    {report.chunks_written:,}")
    print(f"  wall clock        {report.seconds:.1f}s  ({report.seconds / 60:.2f} min)")
    print(f"  throughput        {report.files_per_second:,.0f} files/s")
    print(f"  index size        {human_bytes(store.size_bytes())}")
    print(f"  TARGET            <15 min, <500 MB")
    print(f"  walk stats        {report.walk_stats}", flush=True)

    print("\n=== WARM RE-SCAN (no changes) ===", flush=True)
    warm = indexer.index_root(corpus)
    print(f"  unchanged         {warm.files_unchanged:,}")
    print(f"  wall clock        {warm.seconds:.1f}s", flush=True)

    print("\n=== INCREMENTAL UPDATE (single file, 25 samples) ===", flush=True)
    watcher = IndexWatcher(indexer, [corpus])
    targets = sorted(corpus.rglob("*.py"))[:25]
    latencies: list[float] = []
    for i, target in enumerate(targets):
        target.write_text(f"def changed_symbol_{i}(x):\n    return x\n" * 12)
        watcher._changed.add(str(target))
        started = time.perf_counter()
        watcher.flush()
        latencies.append((time.perf_counter() - started) * 1000)
    if latencies:
        print(f"  median            {statistics.median(latencies):.1f} ms")
        print(f"  p95               {sorted(latencies)[int(len(latencies) * 0.95) - 1]:.1f} ms")
        print(f"  max               {max(latencies):.1f} ms")
        print(f"  TARGET            <200 ms", flush=True)

    print("\n=== SEARCH LATENCY (10 queries) ===", flush=True)
    queries = ["connection pool", "checkpoint watermark", "authenticate token",
               "shard replica failover", "serialize payload"]
    for use_exact in (True, False):
        samples: list[float] = []
        for query in queries * 2:
            started = time.perf_counter()
            indexer.search(query, roots=[corpus], limit=20, use_exact=use_exact)
            samples.append((time.perf_counter() - started) * 1000)
        label = "all three retrievers" if use_exact else "fts + vector only"
        print(f"  {label:<24} median {statistics.median(samples):7.1f} ms  "
              f"max {max(samples):7.1f} ms", flush=True)

    print(f"\nfinal index size: {human_bytes(store.size_bytes())}")
    print(f"counts: {store.counts()}")
    store.close()

    if not args.keep_corpus:
        shutil.rmtree(corpus, ignore_errors=True)


if __name__ == "__main__":
    main()
