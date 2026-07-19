import sys

from huntkit.core.config import Config
from huntkit.core.runner import CommandRunner, ToolNotFound
from huntkit.utils import process


class TestProcess:
    def test_execute_captures_stdout(self):
        r = process.execute([sys.executable, "-c", "print('hello')"])
        assert r.ok
        assert r.lines == ["hello"]
        assert r.duration >= 0

    def test_nonzero_exit_not_raised(self):
        r = process.execute([sys.executable, "-c", "import sys; sys.exit(3)"])
        assert not r.ok
        assert r.code == 3

    def test_binary_not_found(self):
        r = process.execute(["definitely-not-a-real-binary-xyz"])
        assert r.code == process.NOT_FOUND
        assert "not found" in r.stderr

    def test_timeout(self):
        r = process.execute([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
        assert r.timed_out
        assert r.code == process.TIMEOUT

    def test_stdin_passthrough(self):
        r = process.execute([sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"],
                            stdin_data="abc")
        assert "ABC" in r.stdout


class TestCommandRunner:
    def _runner_with_python_as(self, tool_name):
        # pin the tool's binary to the python interpreter for a portable test
        cfg = Config.from_dict({"tools": {tool_name: {"path": sys.executable}}})
        return CommandRunner(cfg)

    def test_resolve_pinned_path(self):
        r = self._runner_with_python_as("faketool")
        assert r.resolve("faketool") == sys.executable
        assert r.available("faketool")

    def test_run_executes(self):
        r = self._runner_with_python_as("faketool")
        result = r.run("faketool", ["-c", "print('ok')"])
        assert result.ok
        assert result.lines == ["ok"]

    def test_missing_tool_raises(self):
        r = CommandRunner(Config())
        try:
            r.run("nonexistent-binary-xyz", ["--help"])
            assert False, "should have raised"
        except ToolNotFound:
            pass

    def test_extra_args_appended(self):
        cfg = Config.from_dict(
            {"tools": {"faketool": {"path": sys.executable, "extra_args": ["extra"]}}}
        )
        r = CommandRunner(cfg)
        # echo argv so we can see extra_args made it through
        result = r.run("faketool", ["-c", "import sys; print(sys.argv[1:])", "main"])
        assert "extra" in result.stdout
