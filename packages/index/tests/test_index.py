"""Index tests.

The security-relevant ones are in TestDenylist: an indexer is the component most likely
to read something it should not, because its whole job is reading everything.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from cortex_index import (
    ExactSearcher,
    HashingEmbedder,
    IndexStore,
    Indexer,
    IndexWatcher,
    Source,
    chunk_text,
    fuse,
    walk,
)
from cortex_index.store import ChunkHit
from cortex_index.walker import WalkStats

RG = shutil.which("rg") or "/opt/homebrew/bin/rg"
HAS_RG = (
    Path(RG).is_file()
    and subprocess.run([RG, "--version"], capture_output=True, text=True).stdout.startswith(
        "ripgrep "
    )
)
requires_rg = pytest.mark.skipif(not HAS_RG, reason="needs a real ripgrep binary")


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    (root / "src").mkdir(parents=True)
    (root / "src" / "db.py").write_text(
        "class ConnectionPool:\n    def acquire(self):\n        return self._pool.pop()\n" * 3
    )
    (root / "src" / "api.py").write_text(
        "def handler(request):\n    pool = get_connection_pool()\n    return pool\n" * 3
    )
    (root / "README.md").write_text("Connection pool tuning guide.\nMax connections.\n" * 4)
    return root


@pytest.fixture
def indexer(tmp_path: Path) -> Indexer:
    store = IndexStore(tmp_path / "index.sqlite", dimensions=128)
    return Indexer(store, HashingEmbedder(dimensions=128))


# --- invariant 10: what must never be indexed -----------------------------------------


class TestDenylist:
    @pytest.mark.parametrize(
        "relative",
        [".ssh/id_rsa", ".gnupg/secring.gpg", ".password-store/aws.gpg", "vault.kdbx"],
    )
    def test_credential_files_are_never_indexed(self, tmp_path: Path, relative: str) -> None:
        """Simulates a home directory being an approved root."""
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("ssh-rsa AAAAB3NzaC1yc2E super secret key material\n")
        (tmp_path / "ordinary.txt").write_text("perfectly normal content\n")

        indexed = {r.path.name for r in walk(tmp_path, stats=WalkStats())}
        assert "ordinary.txt" in indexed
        assert target.name not in indexed

    def test_ssh_directory_is_pruned_not_descended(self, tmp_path: Path) -> None:
        ssh = tmp_path / ".ssh"
        ssh.mkdir()
        for name in ("id_rsa", "config", "known_hosts"):
            (ssh / name).write_text("secret\n")
        stats = WalkStats()
        assert list(walk(tmp_path, stats=stats)) == []
        assert stats.dirs_pruned >= 1

    def test_env_files_need_approval_so_are_not_indexed(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("API_KEY=sk-ant-secret\n")
        (tmp_path / "app.py").write_text("import os\n" * 3)
        names = {r.path.name for r in walk(tmp_path, stats=WalkStats())}
        assert ".env" not in names
        assert "app.py" in names

    @requires_rg
    def test_ripgrep_results_are_filtered_too(self, tmp_path: Path) -> None:
        """ripgrep does not know about invariant 10; the driver must enforce it."""
        ssh = tmp_path / ".ssh"
        ssh.mkdir()
        (ssh / "id_rsa").write_text("NEEDLE_TOKEN in a private key\n")
        (tmp_path / "ok.txt").write_text("NEEDLE_TOKEN in an ordinary file\n")

        hits = ExactSearcher().search("NEEDLE_TOKEN", [tmp_path], limit=20)
        paths = {h.path for h in hits}
        assert any("ok.txt" in p for p in paths)
        assert not any("id_rsa" in p for p in paths)


class TestGitignore:
    def test_ignored_files_are_skipped(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("*.log\nbuild/\n")
        (tmp_path / "keep.py").write_text("x = 1\n")
        (tmp_path / "drop.log").write_text("noise\n")
        (tmp_path / "build").mkdir()
        (tmp_path / "build" / "out.py").write_text("generated\n")

        names = {r.path.name for r in walk(tmp_path, stats=WalkStats())}
        # .gitignore itself is an ordinary tracked text file and is worth indexing.
        assert names == {"keep.py", ".gitignore"}

    def test_nested_gitignore_applies_below_itself(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / ".gitignore").write_text("*.tmp\n")
        (tmp_path / "a" / "x.tmp").write_text("nested ignore\n")
        (tmp_path / "b").mkdir()
        (tmp_path / "b" / "y.tmp").write_text("not ignored, different dir\n")

        names = {r.path.name for r in walk(tmp_path, stats=WalkStats())}
        assert "x.tmp" not in names
        assert "y.tmp" in names

    def test_gitignore_can_be_disabled(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("*.log\n")
        (tmp_path / "a.log").write_text("content\n")
        names = {r.path.name for r in walk(tmp_path, respect_gitignore=False, stats=WalkStats())}
        assert "a.log" in names


class TestWalkerFilters:
    def test_binary_files_are_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "bin.dat").write_bytes(b"text\x00\x01binary")
        (tmp_path / "text.txt").write_text("plain\n")
        names = {r.path.name for r in walk(tmp_path, stats=WalkStats())}
        assert names == {"text.txt"}

    def test_oversize_files_are_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "big.txt").write_text("x" * 5000)
        (tmp_path / "small.txt").write_text("y" * 10)
        names = {r.path.name for r in walk(tmp_path, max_bytes=1000, stats=WalkStats())}
        assert names == {"small.txt"}

    def test_symlinks_are_not_followed(self, tmp_path: Path) -> None:
        """Otherwise a link into ~/.ssh inside an approved root would be indexed."""
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("should not be indexed\n")
        root = tmp_path / "root"
        root.mkdir()
        (root / "real.txt").write_text("fine\n")
        (root / "link").symlink_to(outside)

        names = {r.path.name for r in walk(root, stats=WalkStats())}
        assert names == {"real.txt"}


# --- chunking and embedding ------------------------------------------------------------


class TestChunking:
    def test_short_text_is_one_chunk(self) -> None:
        chunks = chunk_text("a\nb\nc\n")
        assert len(chunks) == 1
        assert chunks[0][0] == 1

    def test_chunks_overlap_so_matches_are_not_lost_at_boundaries(self) -> None:
        text = "\n".join(f"line{i}" for i in range(200))
        chunks = chunk_text(text, target_lines=40, overlap_lines=8)
        assert len(chunks) > 1
        assert chunks[1][0] < chunks[0][1], "consecutive chunks must overlap"

    def test_line_numbers_are_one_based_and_cover_the_file(self) -> None:
        text = "\n".join(f"line{i}" for i in range(100))
        chunks = chunk_text(text, target_lines=40, overlap_lines=8)
        assert chunks[0][0] == 1
        assert chunks[-1][1] == 100


class TestEmbedder:
    def test_is_deterministic(self) -> None:
        e = HashingEmbedder(64)
        assert e.embed(["connection pool"]) == e.embed(["connection pool"])

    def test_declares_itself_non_semantic(self) -> None:
        """Nothing downstream may present placeholder hits as semantic understanding."""
        assert HashingEmbedder().is_semantic is False

    def test_shared_vocabulary_is_closer_than_unrelated_text(self) -> None:
        e = HashingEmbedder(256)
        a, b, c = e.embed(
            ["connection pool acquire release",
             "connection pool acquire timeout",
             "render template html output"]
        )
        dot = lambda x, y: sum(i * j for i, j in zip(x, y, strict=True))  # noqa: E731
        assert dot(a, b) > dot(a, c)

    def test_dimension_mismatch_is_rejected_loudly(self, tmp_path: Path) -> None:
        store = IndexStore(tmp_path / "i.sqlite", dimensions=128)
        with pytest.raises(ValueError, match="dimensions"):
            Indexer(store, HashingEmbedder(dimensions=64))


# --- fusion ------------------------------------------------------------------------------


def _hits(*paths: str) -> list[ChunkHit]:
    return [ChunkHit(chunk_id=i, path=p, start_line=1, end_line=10, score=0.0)
            for i, p in enumerate(paths, 1)]


class TestFusion:
    def test_agreement_beats_a_single_strong_hit(self) -> None:
        """The core RRF property: two retrievers at rank 2 beat one at rank 1."""
        fused = fuse(
            {
                Source.FTS: _hits("solo.py", "both.py"),
                Source.VECTOR: _hits("other.py", "both.py"),
            },
            weights={Source.FTS: 1.0, Source.VECTOR: 1.0},
        )
        assert fused[0].path == "both.py"
        assert fused[0].agreement == 2

    def test_scores_on_incoming_hits_are_ignored(self) -> None:
        """Only rank matters — that is the whole point of RRF."""
        inflated = [ChunkHit(chunk_id=1, path="a.py", start_line=1, end_line=10, score=999.0)]
        normal = [ChunkHit(chunk_id=2, path="b.py", start_line=1, end_line=10, score=0.001)]
        a = fuse({Source.FTS: inflated}, weights={Source.FTS: 1.0})
        b = fuse({Source.FTS: normal}, weights={Source.FTS: 1.0})
        assert a[0].score == b[0].score

    def test_weights_are_applied(self) -> None:
        fused = fuse(
            {Source.EXACT: _hits("e.py"), Source.VECTOR: _hits("v.py")},
            weights={Source.EXACT: 1.0, Source.VECTOR: 0.4},
        )
        assert fused[0].path == "e.py"

    def test_zero_weight_source_is_excluded(self) -> None:
        fused = fuse(
            {Source.VECTOR: _hits("v.py")}, weights={Source.VECTOR: 0.0}
        )
        assert fused == []

    def test_empty_sources_contribute_nothing(self) -> None:
        fused = fuse({Source.FTS: [], Source.VECTOR: _hits("v.py")})
        assert len(fused) == 1

    def test_ordering_is_deterministic(self) -> None:
        """Evidence links (invariant 20) require a stable order run to run."""
        results = {Source.FTS: _hits("a.py", "b.py"), Source.VECTOR: _hits("b.py", "a.py")}
        first = [h.path for h in fuse(results)]
        for _ in range(5):
            assert [h.path for h in fuse(results)] == first

    def test_provenance_is_recorded(self) -> None:
        fused = fuse({Source.FTS: _hits("x.py"), Source.EXACT: _hits("x.py")})
        assert set(fused[0].ranks) == {Source.FTS, Source.EXACT}
        assert "fts#1" in fused[0].explain()


# --- indexing ------------------------------------------------------------------------


class TestIndexing:
    def test_index_then_search(self, indexer: Indexer, corpus: Path) -> None:
        report = indexer.index_root(corpus)
        assert report.files_indexed == 3
        hits = indexer.search("connection pool", roots=[corpus], limit=5)
        assert hits
        assert any("db.py" in h.path or "README" in h.path for h in hits)

    def test_second_pass_does_no_work(self, indexer: Indexer, corpus: Path) -> None:
        indexer.index_root(corpus)
        second = indexer.index_root(corpus)
        assert second.files_indexed == 0
        assert second.files_unchanged == 3

    def test_modified_file_is_reindexed(self, indexer: Indexer, corpus: Path) -> None:
        indexer.index_root(corpus)
        target = corpus / "src" / "db.py"
        target.write_text("class Rewritten:\n    pass\n" * 4)
        report = indexer.index_root(corpus)
        assert report.files_indexed == 1
        hits = indexer.search("Rewritten", roots=[corpus])
        assert any("db.py" in h.path for h in hits)

    def test_deleted_file_is_pruned(self, indexer: Indexer, corpus: Path) -> None:
        indexer.index_root(corpus)
        (corpus / "src" / "api.py").unlink()
        report = indexer.index_root(corpus)
        assert report.files_removed == 1
        assert indexer.store.counts()["files"] == 2

    def test_deleting_a_file_removes_its_vectors_and_fts_rows(
        self, indexer: Indexer, corpus: Path
    ) -> None:
        """A stale posting is worse than a missing one: it cites a file that is gone."""
        indexer.index_root(corpus)
        before = indexer.store.counts()
        indexer.store.delete_file(str(corpus / "src" / "db.py"))
        indexer.store.commit()
        after = indexer.store.counts()
        assert after["chunks"] < before["chunks"]
        assert after["vectors"] == after["chunks"]

    def test_malformed_query_returns_nothing_rather_than_raising(
        self, indexer: Indexer, corpus: Path
    ) -> None:
        indexer.index_root(corpus)
        for query in ['unbalanced "quote', "AND", "*", "((", ""]:
            indexer.search(query, roots=[corpus])

    def test_undecodable_file_does_not_abort_the_index(
        self, indexer: Indexer, tmp_path: Path
    ) -> None:
        root = tmp_path / "r"
        root.mkdir()
        (root / "good.txt").write_text("readable content here\n" * 3)
        (root / "bad.txt").write_bytes(b"\xff\xfe invalid utf-8 \xc3\x28 more\n" * 3)
        report = indexer.index_root(root)
        assert report.files_indexed >= 1


@requires_rg
class TestExactSearch:
    def test_finds_literal_text(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("def find_me():\n    pass\n")
        hits = ExactSearcher().search("find_me", [tmp_path])
        assert any("a.py" in h.path for h in hits)

    def test_pattern_is_not_shell_interpreted(self, tmp_path: Path) -> None:
        """A pattern is a pattern, even when it looks like a command."""
        (tmp_path / "a.py").write_text("value = 1\n")
        marker = tmp_path / "pwned.txt"
        ExactSearcher().search(f"x; touch {marker}", [tmp_path])
        assert not marker.exists()

    def test_paths_are_resolved_to_match_the_walker(self, tmp_path: Path) -> None:
        """On macOS /var vs /private/var would otherwise break fusion keying."""
        (tmp_path / "a.py").write_text("needle_here = 1\n")
        hits = ExactSearcher().search("needle_here", [tmp_path])
        assert hits
        assert hits[0].path == str(Path(hits[0].path).resolve())

    def test_exact_hits_align_onto_chunks(self, indexer: Indexer, corpus: Path) -> None:
        """Without alignment, exact hits can never agree with fts/vector hits."""
        indexer.index_root(corpus)
        hits = indexer.search("ConnectionPool", roots=[corpus], limit=10)
        assert any(h.agreement >= 2 for h in hits), "no hit was found by two retrievers"


# --- watching --------------------------------------------------------------------------


class TestWatcher:
    def test_new_file_is_picked_up_on_flush(self, indexer: Indexer, corpus: Path) -> None:
        indexer.index_root(corpus)
        watcher = IndexWatcher(indexer, [corpus], debounce_seconds=0.05)
        (corpus / "src" / "fresh.py").write_text("def brand_new_symbol():\n    pass\n" * 3)
        watcher._changed.add(str(corpus / "src" / "fresh.py"))  # deterministic, no sleeping
        watcher.flush()
        hits = indexer.search("brand_new_symbol", roots=[corpus])
        assert any("fresh.py" in h.path for h in hits)

    def test_deleted_file_is_removed_on_flush(self, indexer: Indexer, corpus: Path) -> None:
        indexer.index_root(corpus)
        target = corpus / "src" / "api.py"
        target.unlink()
        watcher = IndexWatcher(indexer, [corpus])
        watcher._removed.add(str(target))
        watcher.flush()
        assert indexer.store.counts()["files"] == 2

    def test_watcher_respects_the_denylist(self, indexer: Indexer, tmp_path: Path) -> None:
        """The watcher must not be a hole in invariant 10."""
        root = tmp_path / "r"
        (root / ".ssh").mkdir(parents=True)
        key = root / ".ssh" / "id_rsa"
        key.write_text("PRIVATE KEY MATERIAL\n")
        watcher = IndexWatcher(indexer, [root])
        watcher._changed.add(str(key))
        watcher.flush()
        assert indexer.store.counts()["files"] == 0

    def test_bursts_coalesce_to_one_update_per_file(
        self, indexer: Indexer, corpus: Path
    ) -> None:
        indexer.index_root(corpus)
        watcher = IndexWatcher(indexer, [corpus])
        target = corpus / "src" / "db.py"
        target.write_text("class Changed:\n    pass\n" * 3)
        for _ in range(50):  # editors emit many events per save
            watcher._changed.add(str(target))
        touched = watcher.flush()
        assert touched == 1
        assert watcher.stats.files_updated == 1
