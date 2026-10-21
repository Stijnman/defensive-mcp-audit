import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "action" / "action.yml"


def extract_run_scripts(action_text):
    """Return composite-action run blocks without needing a YAML dependency."""
    lines = action_text.splitlines()
    scripts = []
    index = 0
    while index < len(lines):
        if lines[index].strip() == "run: |":
            index += 1
            body = []
            while index < len(lines):
                line = lines[index]
                if line and not line.startswith("        "):
                    break
                body.append(line[8:] if line.startswith("        ") else "")
                index += 1
            scripts.append("\n".join(body).rstrip() + "\n")
        else:
            index += 1
    return scripts


class ActionInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scripts = extract_run_scripts(ACTION.read_text(encoding="utf-8"))

    def test_run_scripts_do_not_interpolate_github_inputs(self):
        self.assertEqual(len(self.scripts), 2)
        for script in self.scripts:
            self.assertNotIn("${{", script)
            self.assertNotIn("inputs.", script)

    def test_hostile_inputs_are_passed_as_arguments_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            stub_dir = temp / "bin"
            stub_dir.mkdir()
            python_log = temp / "python-args.jsonl"
            pip_log = temp / "pip-args.jsonl"
            marker = temp / "injected-command-ran"

            recorder = """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
log_path = Path(os.environ["LOG_DIR"]) / (Path(sys.argv[0]).name + "-args.jsonl")
with open(log_path, "a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\\n")
"""
            for command, log in (("python", python_log), ("pip", pip_log)):
                executable = stub_dir / command
                executable.write_text(recorder, encoding="utf-8")
                executable.chmod(0o755)

            env = os.environ.copy()
            env.update({"PATH": f"{stub_dir}{os.pathsep}{env['PATH']}", "LOG_DIR": str(temp)})
            hostile_version = f'v1"; touch {marker}; # $(touch {marker})'
            env["INPUT_VERSION"] = hostile_version
            subprocess.run(
                ["bash", "-c", self.scripts[0]],
                cwd=temp,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            hostile_format = f'sarif"; touch {marker}; # $(touch {marker})'
            hostile_output = f'{temp / "result"}.sarif"; touch {marker}; # $(touch {marker})'
            env["INPUT_FORMAT"] = hostile_format
            env["INPUT_OUTPUT"] = hostile_output
            subprocess.run(
                ["bash", "-c", self.scripts[1]],
                cwd=temp,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertFalse(marker.exists(), "input-triggered shell command was executed")
            pip_calls = [json.loads(line) for line in pip_log.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(pip_calls, [["install", f"git+https://github.com/Stijnman/defensive-mcp-audit@{hostile_version}#egg=defensive-mcp-audit[cli]"]])
            python_calls = [json.loads(line) for line in python_log.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(python_calls[0], ["-m", "pip", "install", "--upgrade", "pip"])
            self.assertEqual(
                python_calls[1],
                ["-m", "defensive_mcp_audit", "--format", hostile_format, "--output", hostile_output],
            )


if __name__ == "__main__":
    unittest.main()
