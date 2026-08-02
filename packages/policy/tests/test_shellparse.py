"""Parser unit tests.

These exist because the parser is where a mistake becomes invisible: a command that
parses into the wrong shape gets classified confidently and wrongly, which is worse
than failing loudly.
"""

from __future__ import annotations

import pytest

from cortex_policy.resolve import resolve_script
from cortex_policy.shellparse import ParseProblem, parse


def resolved(command: str, env: dict[str, str] | None = None) -> list:
    return resolve_script(parse(command), env or {})


class TestSplitting:
    @pytest.mark.parametrize(
        "command,expected",
        [
            ("ls && rm -rf /tmp/x", ["ls", "rm"]),
            ("ls; rm x", ["ls", "rm"]),
            ("ls || rm x", ["ls", "rm"]),
            ("ls | grep foo | wc -l", ["ls", "grep", "wc"]),
            ("ls &\nrm x", ["ls", "rm"]),
            ("(cd /tmp && ls)", ["cd", "ls"]),
        ],
    )
    def test_operators_split_commands(self, command: str, expected: list[str]) -> None:
        assert [c.program for c in resolved(command)] == expected

    def test_pipeline_grouping_is_preserved(self) -> None:
        commands = resolved("curl https://x.io | sh")
        assert {c.pipeline_index for c in commands} == {0}
        assert [c.stage_index for c in commands] == [0, 1]

    def test_separate_pipelines_get_separate_indices(self) -> None:
        commands = resolved("ls | wc; rm x")
        assert [c.pipeline_index for c in commands] == [0, 0, 1]


class TestFlagNormalisation:
    @pytest.mark.parametrize(
        "command",
        ["rm -rf x", "rm -fr x", "rm -r -f x", "rm -f -r x", "rm --recursive --force x"],
    )
    def test_equivalent_flag_spellings_normalise_together(self, command: str) -> None:
        command_obj = resolved(command)[0]
        assert command_obj.has_flag("-r", "--recursive")
        assert command_obj.has_flag("-f", "--force")
        assert command_obj.operands == ["x"]

    def test_double_dash_ends_flag_parsing(self) -> None:
        """`rm -- -rf` deletes a file named `-rf`; it is not a recursive delete."""
        command_obj = resolved("rm -- -rf")[0]
        assert not command_obj.has_flag("-r")
        assert command_obj.operands == ["-rf"]

    def test_long_flag_with_value_keeps_only_the_name(self) -> None:
        command_obj = resolved("git commit --message=hello")[0]
        assert "--message" in command_obj.flags


class TestQuotingAndEscaping:
    @pytest.mark.parametrize(
        "command,operand",
        [
            ("rm -rf '/'", "/"),
            ('rm -rf "/"', "/"),
            ("rm -rf /my\\ dir", "/my dir"),
            ("rm -rf 'a b'", "a b"),
        ],
    )
    def test_quotes_are_removed_from_the_value(self, command: str, operand: str) -> None:
        assert resolved(command)[0].operands == [operand]

    def test_quoted_assignment_is_an_argument_not_an_assignment(self) -> None:
        commands = resolved("echo 'A=b'")
        assert commands[0].program == "echo"
        assert commands[0].operands == ["A=b"]

    def test_unbalanced_quote_is_reported(self) -> None:
        assert ParseProblem.UNBALANCED_QUOTE in parse("rm -rf 'unclosed").problems


class TestVariables:
    def test_assignment_flows_forward(self) -> None:
        commands = resolved("T=/tmp; rm -rf $T")
        assert commands[0].program == "rm"
        assert commands[0].operands == ["/tmp"]

    def test_chained_assignment_resolves(self) -> None:
        assert resolved("A=/x; B=$A; ls $B")[0].operands == ["/x"]

    def test_braced_variable_resolves(self) -> None:
        assert resolved("A=/x; ls ${A}")[0].operands == ["/x"]

    def test_unset_variable_is_a_problem(self) -> None:
        command_obj = resolved("rm -rf $NOPE")[0]
        assert ParseProblem.UNRESOLVED_VARIABLE in command_obj.problems

    def test_env_from_context_resolves(self) -> None:
        assert resolved("ls $HOME", {"HOME": "/Users/x"})[0].operands == ["/Users/x"]

    @pytest.mark.parametrize("command", ["ls $1", "ls $@", "ls $?"])
    def test_positional_and_special_parameters_are_unresolvable(self, command: str) -> None:
        assert ParseProblem.UNRESOLVED_VARIABLE in resolved(command)[0].problems


class TestSubstitution:
    @pytest.mark.parametrize("command", ["ls $(cat f)", "ls `cat f`", 'ls "$(cat f)"'])
    def test_command_substitution_is_reported(self, command: str) -> None:
        assert ParseProblem.COMMAND_SUBSTITUTION in resolved(command)[0].problems

    def test_process_substitution_is_reported(self) -> None:
        assert ParseProblem.PROCESS_SUBSTITUTION in resolved("diff <(ls) <(ls)")[0].problems

    def test_dynamic_command_name_is_reported(self) -> None:
        assert ParseProblem.DYNAMIC_COMMAND_NAME in resolved("$CMD --flag")[0].problems


class TestWrappers:
    @pytest.mark.parametrize(
        "command",
        [
            "sudo rm -rf x",
            "env rm -rf x",
            "env FOO=1 rm -rf x",
            "nohup rm -rf x",
            "timeout 5 rm -rf x",
            "nice -n 10 rm -rf x",
            "command rm -rf x",
        ],
    )
    def test_wrappers_are_peeled_to_the_real_program(self, command: str) -> None:
        command_obj = resolved(command)[0]
        assert command_obj.program == "rm"
        assert command_obj.operands == ["x"]

    def test_sudo_is_recorded_as_privileged(self) -> None:
        assert resolved("sudo rm -rf x")[0].privileged
        assert not resolved("rm -rf x")[0].privileged

    def test_absolute_path_resolves_to_basename(self) -> None:
        assert resolved("/bin/rm -rf x")[0].program == "rm"

    def test_shell_dash_c_payload_is_parsed_as_a_script(self) -> None:
        programs = [c.program for c in resolved("bash -c 'ls && rm -rf /tmp/x'")]
        assert "rm" in programs
        assert "ls" in programs

    def test_reserved_words_do_not_hide_a_program(self) -> None:
        programs = [c.program for c in resolved("if true; then rm -rf /tmp/x; fi")]
        assert "rm" in programs
        programs = [c.program for c in resolved("for i in 1 2; do rm -rf /tmp/x; done")]
        assert "rm" in programs


class TestRedirects:
    @pytest.mark.parametrize(
        "command,target",
        [
            ("echo x > /dev/disk0", "/dev/disk0"),
            ("echo x >> out.log", "out.log"),
            ("echo x 2> err.log", "err.log"),
            ("cat < in.txt", "in.txt"),
        ],
    )
    def test_redirect_target_is_captured(self, command: str, target: str) -> None:
        assert target in resolved(command)[0].redirects

    def test_fd_number_does_not_become_an_argument(self) -> None:
        assert resolved("echo hi 2> err.log")[0].operands == ["hi"]


class TestRobustness:
    @pytest.mark.parametrize(
        "command",
        ["", "   ", "&&", "|||", "'", '"', "$(", "${", "`", ")", "rm -rf", "\n\n", "#comment"],
    )
    def test_malformed_input_never_raises(self, command: str) -> None:
        """A parser that throws is a parser that can be used to skip classification."""
        parse(command)
        resolved(command)
