"""Workspace containment, including a real symlink escape on disk."""

from __future__ import annotations

from pathlib import Path

import pytest

from cortex_policy import (
    AutonomyLevel,
    FileAction,
    FileOperation,
    PathSensitivity,
    PolicyContext,
    RiskClass,
    Verdict,
    contains,
    decide,
    sensitivity,
)


class TestSensitivity:
    @pytest.mark.parametrize(
        "path",
        [
            "~/.ssh/id_rsa",
            "~/.ssh/known_hosts",
            "~/.gnupg/pubring.kbx",
            "~/.password-store/x.gpg",
            "~/Library/Application Support/Google/Chrome/Default/Login Data",
            "~/Library/Application Support/Firefox/Profiles/abc/logins.json",
            "~/secrets.kdbx",
            "/etc/sudoers",
        ],
    )
    def test_credential_paths_are_protected(self, path: str) -> None:
        assert sensitivity(path) is PathSensitivity.PROTECTED

    @pytest.mark.parametrize("path", ["/ws/.env", "/ws/.env.local", "/ws/.env.production"])
    def test_env_files_need_per_file_approval(self, path: str) -> None:
        assert sensitivity(path) is PathSensitivity.PER_FILE_APPROVAL

    @pytest.mark.parametrize("path", ["/ws/src/main.py", "/ws/README.md", "/ws/.gitignore"])
    def test_ordinary_files_are_normal(self, path: str) -> None:
        assert sensitivity(path) is PathSensitivity.NORMAL


class TestContainment:
    def test_path_inside_workspace(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        result = contains((workspace,), workspace / "src" / "main.py")
        assert result.inside
        assert not result.symlink_escape

    def test_path_outside_workspace(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        result = contains((workspace,), tmp_path / "elsewhere" / "x.txt")
        assert not result.inside
        assert not result.symlink_escape

    def test_dotdot_traversal_does_not_escape_undetected(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        result = contains((workspace,), workspace / ".." / "outside.txt")
        assert not result.inside

    def test_symlink_pointing_out_of_the_workspace_is_flagged(self, tmp_path: Path) -> None:
        """The path *looks* contained and is not. This is the case that a lexical-only
        containment check gets wrong, and it is how a workspace sandbox gets escaped."""
        workspace = tmp_path / "ws"
        workspace.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("stolen")

        link = workspace / "innocuous"
        link.symlink_to(outside)

        target = link / "secret.txt"
        assert target.exists()  # it really does resolve to the file outside

        result = contains((workspace,), target)
        assert not result.inside
        assert result.symlink_escape

    def test_symlink_escape_escalates_the_risk_class(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        workspace.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.txt").write_text("stolen")
        (workspace / "innocuous").symlink_to(outside)

        decision = decide(
            FileOperation(action=FileAction.READ, path=workspace / "innocuous" / "secret.txt"),
            PolicyContext(autonomy=AutonomyLevel.L3_AUTONOMOUS, workspaces=(workspace,)),
        )
        assert decision.verdict is Verdict.APPROVE
        assert decision.risk is RiskClass.WRITE_BROAD
        assert any("symlink" in reason for reason in decision.reasons)

    def test_symlink_staying_inside_the_workspace_is_fine(self, tmp_path: Path) -> None:
        workspace = tmp_path / "ws"
        (workspace / "real").mkdir(parents=True)
        (workspace / "real" / "a.txt").write_text("ok")
        (workspace / "link").symlink_to(workspace / "real")

        result = contains((workspace,), workspace / "link" / "a.txt")
        assert result.inside
        assert not result.symlink_escape


class TestWorkspaceScopingInShellCommands:
    def test_write_inside_workspace_is_scoped(self, tmp_path: Path) -> None:
        decision = decide(
            FileOperation(action=FileAction.WRITE, path=tmp_path / "out.txt"),
            PolicyContext(autonomy=AutonomyLevel.L2_CONFIRM_RISKY, workspaces=(tmp_path,)),
        )
        assert decision.risk is RiskClass.WRITE_SCOPED
        assert decision.verdict is Verdict.ALLOW

    def test_write_outside_workspace_is_broad(self, tmp_path: Path) -> None:
        decision = decide(
            FileOperation(action=FileAction.WRITE, path="/somewhere/else/out.txt"),
            PolicyContext(autonomy=AutonomyLevel.L2_CONFIRM_RISKY, workspaces=(tmp_path,)),
        )
        assert decision.risk is RiskClass.WRITE_BROAD
        assert decision.verdict is Verdict.APPROVE

    def test_shell_write_outside_workspace_escalates(self, tmp_path: Path) -> None:
        from cortex_policy import ShellOperation

        decision = decide(
            ShellOperation(command="touch /etc/newfile", cwd=tmp_path),
            PolicyContext(autonomy=AutonomyLevel.L3_AUTONOMOUS, workspaces=(tmp_path,)),
        )
        assert decision.risk is RiskClass.WRITE_BROAD
        assert decision.verdict is Verdict.APPROVE
