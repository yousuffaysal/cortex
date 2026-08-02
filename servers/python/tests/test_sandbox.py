"""Sandbox tests.

Split deliberately: the security *posture* is asserted without a daemon by inspecting
the argv, so those tests run anywhere and fail loudly if someone weakens a flag. The
tests marked `docker` need a real daemon and prove the flags actually do what the argv
claims — an isolation flag that is present but ineffective is worse than one that is
missing, because it reads as covered.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from cortex_python_server.docker_runtime import TASK_LABEL, DockerRuntime, SandboxSpec
from cortex_python_server.errors import SandboxError, SandboxErrorCode
from cortex_python_server.policy_bridge import PolicyRefusal, check_host_execution, check_install
from cortex_python_server.session import SandboxSession
from cortex_python_server.settings import WorkspaceSettings, load_settings

DOCKER = shutil.which("docker") or "/usr/local/bin/docker"
HAS_DOCKER = Path(DOCKER).is_file() and (
    subprocess.run([DOCKER, "info"], capture_output=True).returncode == 0
)
requires_docker = pytest.mark.skipif(not HAS_DOCKER, reason="needs a running Docker daemon")


@pytest.fixture
def spec(tmp_path: Path) -> SandboxSpec:
    return SandboxSpec(
        task_id="t1",
        workspace=tmp_path / "ws",
        artifacts_dir=tmp_path / "art",
        memory="512m",
    )


# --- security posture, asserted from argv (no daemon needed) ------------------------


class TestIsolationFlags:
    def argv(self, spec: SandboxSpec, tmp_path: Path) -> list[str]:
        runtime = DockerRuntime(binary="/usr/bin/docker")
        return runtime.build_run_argv(spec, tmp_path / "kernel", "cortex-test")

    def test_network_is_disabled_by_default(self, spec: SandboxSpec, tmp_path: Path) -> None:
        argv = self.argv(spec, tmp_path)
        assert "--network" in argv
        assert argv[argv.index("--network") + 1] == "none"

    def test_network_only_appears_when_explicitly_allowed(
        self, tmp_path: Path
    ) -> None:
        allowed = SandboxSpec(
            task_id="t1", workspace=tmp_path, artifacts_dir=tmp_path, allow_network=True
        )
        assert "--network" not in self.argv(allowed, tmp_path)

    @pytest.mark.parametrize(
        "flag,value",
        [
            ("--memory", "512m"),
            ("--memory-swap", "512m"),  # equal to memory => swap disabled
            ("--cpus", "2"),
            ("--pids-limit", "256"),
            ("--cap-drop", "ALL"),
            ("--security-opt", "no-new-privileges"),
        ],
    )
    def test_hardening_flags_present(
        self, spec: SandboxSpec, tmp_path: Path, flag: str, value: str
    ) -> None:
        argv = self.argv(spec, tmp_path)
        assert flag in argv, f"{flag} missing from the sandbox argv"
        assert argv[argv.index(flag) + 1] == value

    def test_root_filesystem_is_read_only(self, spec: SandboxSpec, tmp_path: Path) -> None:
        assert "--read-only" in self.argv(spec, tmp_path)

    def test_kernel_is_mounted_readonly(self, spec: SandboxSpec, tmp_path: Path) -> None:
        argv = self.argv(spec, tmp_path)
        kernel_mounts = [a for a in argv if "target=/cortex" in a]
        assert kernel_mounts and kernel_mounts[0].endswith("readonly")

    def test_container_is_labelled_for_out_of_band_kill(
        self, spec: SandboxSpec, tmp_path: Path
    ) -> None:
        """The kill switch finds containers by label, never by in-memory state."""
        argv = self.argv(spec, tmp_path)
        assert f"{TASK_LABEL}={spec.task_id}" in argv

    def test_platform_is_pinned_to_arm64(self, spec: SandboxSpec, tmp_path: Path) -> None:
        argv = self.argv(spec, tmp_path)
        assert argv[argv.index("--platform") + 1] == "linux/arm64"


# --- settings: fail closed ----------------------------------------------------------


class TestWorkspaceSettings:
    def test_defaults_are_off(self) -> None:
        settings = WorkspaceSettings()
        assert not settings.host_execution_enabled
        assert not settings.network_enabled

    def test_missing_config_is_off(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CORTEX_CONFIG_DIR", str(tmp_path))
        assert not load_settings(tmp_path).host_execution_enabled

    def test_malformed_config_is_off_not_on(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CORTEX_CONFIG_DIR", str(tmp_path))
        (tmp_path / "workspaces.json").write_text("{ this is not json")
        assert not load_settings(tmp_path).host_execution_enabled

    def test_enabling_requires_literal_true(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Truthy-but-not-true values must not enable a dangerous mode."""
        monkeypatch.setenv("CORTEX_CONFIG_DIR", str(tmp_path))
        for value in ["yes", 1, "true", [1]]:
            (tmp_path / "workspaces.json").write_text(
                json.dumps({str(tmp_path.resolve()): {"host_execution_enabled": value}})
            )
            assert not load_settings(tmp_path).host_execution_enabled, value

        (tmp_path / "workspaces.json").write_text(
            json.dumps({str(tmp_path.resolve()): {"host_execution_enabled": True}})
        )
        assert load_settings(tmp_path).host_execution_enabled


# --- policy integration -------------------------------------------------------------


class TestPolicyGates:
    def test_install_refused_when_network_off(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyRefusal) as exc:
            check_install(["requests"], tmp_path, WorkspaceSettings())
        assert "network" in str(exc.value).lower()

    def test_host_execution_refused_by_default(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyRefusal) as exc:
            check_host_execution(tmp_path, WorkspaceSettings())
        assert "not enabled" in str(exc.value)

    def test_host_execution_cannot_be_enabled_by_an_argument(self) -> None:
        """There is no parameter that grants host execution — only stored settings."""
        import inspect

        params = set(inspect.signature(check_host_execution).parameters)
        assert params == {"workspace", "settings"}
        assert "approved" not in params
        assert "force" not in params


# --- guided errors ------------------------------------------------------------------


class TestGuidedErrors:
    def test_docker_missing_error_is_actionable(self) -> None:
        from cortex_python_server.errors import docker_not_installed

        error = docker_not_installed(["/usr/local/bin/docker"])
        text = str(error)
        assert "Traceback" not in text
        assert error.remediation, "an error with no remediation is a stack trace with prose"
        assert "OrbStack" in text or "Docker Desktop" in text

    def test_every_error_constructor_yields_remediation(self) -> None:
        from cortex_python_server import errors

        builders = [
            errors.docker_not_installed(["/x"]),
            errors.docker_not_running("cannot connect"),
            errors.docker_permission_denied("permission denied"),
            errors.image_missing("python:3.12-slim"),
            errors.host_mode_not_enabled("/ws"),
        ]
        for error in builders:
            assert error.remediation, f"{error.code} has no remediation steps"
            assert error.explanation, f"{error.code} has no explanation"


# --- live, against a real daemon ----------------------------------------------------


@requires_docker
class TestLiveSandbox:
    def test_state_persists_across_executions(self, tmp_path: Path) -> None:
        with SandboxSession("live-state", tmp_path / "ws", tmp_path / "art",
                            memory="512m") as session:
            session.execute("value = 123")
            result = session.execute("value * 2")
            assert result.ok
            assert result.result_repr == "246"

    def test_network_really_is_blocked(self, tmp_path: Path) -> None:
        """The flag being present is not proof. This proves it."""
        with SandboxSession("live-net", tmp_path / "ws", tmp_path / "art",
                            memory="512m") as session:
            result = session.execute(
                "import socket\n"
                "socket.setdefaulttimeout(3)\n"
                "try:\n"
                "    socket.create_connection(('1.1.1.1', 53))\n"
                "    print('REACHABLE')\n"
                "except Exception as e:\n"
                "    print('BLOCKED', type(e).__name__)"
            )
            assert "BLOCKED" in result.stdout
            assert "REACHABLE" not in result.stdout

    def test_exception_does_not_kill_the_session(self, tmp_path: Path) -> None:
        with SandboxSession("live-exc", tmp_path / "ws", tmp_path / "art",
                            memory="512m") as session:
            session.execute("keep = 'alive'")
            failed = session.execute("1/0")
            assert not failed.ok
            assert failed.error is not None
            assert failed.error["type"] == "ZeroDivisionError"
            assert session.execute("keep").result_repr == "'alive'"

    def test_timeout_destroys_the_container(self, tmp_path: Path) -> None:
        session = SandboxSession("live-timeout", tmp_path / "ws", tmp_path / "art",
                                 memory="512m")
        session.start()
        with pytest.raises(SandboxError) as exc:
            session.execute("while True: pass", timeout=5)
        assert exc.value.code is SandboxErrorCode.EXECUTION_TIMEOUT
        # Nothing may survive. Invariant 25's rule, applied per task.
        assert DockerRuntime().kill_task("live-timeout") == []

    def test_memory_ceiling_is_enforced(self, tmp_path: Path) -> None:
        session = SandboxSession("live-oom", tmp_path / "ws", tmp_path / "art",
                                 memory="256m")
        session.start()
        with pytest.raises(SandboxError) as exc:
            session.execute("b = bytearray(512*1024*1024)")
        assert exc.value.code is SandboxErrorCode.MEMORY_EXCEEDED
        session.close()

    def test_artifacts_are_reported_and_land_on_the_host(self, tmp_path: Path) -> None:
        artifacts = tmp_path / "art"
        with SandboxSession("live-art", tmp_path / "ws", artifacts,
                            memory="512m") as session:
            result = session.execute(
                "open(ARTIFACTS_DIR + '/report.txt', 'w').write('generated')"
            )
            assert [a["path"] for a in result.artifacts] == ["report.txt"]
        assert (artifacts / "report.txt").read_text() == "generated"

    def test_root_filesystem_is_actually_read_only(self, tmp_path: Path) -> None:
        with SandboxSession("live-ro", tmp_path / "ws", tmp_path / "art",
                            memory="512m") as session:
            result = session.execute(
                "try:\n"
                "    open('/usr/lib/evil.so', 'w').write('x')\n"
                "    print('WRITABLE')\n"
                "except OSError as e:\n"
                "    print('READONLY', e.errno)"
            )
            assert "READONLY" in result.stdout

    def test_no_container_survives_a_closed_session(self, tmp_path: Path) -> None:
        with SandboxSession("live-cleanup", tmp_path / "ws", tmp_path / "art",
                            memory="512m") as session:
            session.execute("1")
        assert DockerRuntime().kill_task("live-cleanup") == []


class TestMcpServerEntrypoint:
    """The MCP surface must actually import and expose its tools.

    This class exists because an earlier version of server.py imported a module that
    did not exist in the installed SDK, and every other test passed: nothing imported
    the entry point. A server that cannot start is not caught by testing its internals.
    """

    def test_module_imports(self) -> None:
        from cortex_python_server import server

        assert server.server.name == "cortex-python"

    @pytest.mark.anyio
    async def test_expected_tools_are_registered(self) -> None:
        from cortex_python_server import server

        names = {tool.name for tool in await server.server.list_tools()}
        assert {
            "python_execute",
            "python_session_state",
            "python_install_packages",
            "python_run_on_host",
            "python_end_session",
        } <= names

    @pytest.mark.anyio
    async def test_no_tool_exposes_an_approval_bypass_argument(self) -> None:
        """A model-settable 'approved' flag would be a bypass with a polite name."""
        from cortex_python_server import server

        for tool in await server.server.list_tools():
            properties = (tool.input_schema or {}).get("properties", {})
            forbidden = {"approved", "approve", "force", "skip_policy", "unsafe", "sandbox"}
            assert not (forbidden & set(properties)), (
                f"{tool.name} exposes {forbidden & set(properties)} to the model"
            )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
