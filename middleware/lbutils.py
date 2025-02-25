# The MIT License (MIT)
#
# Copyright (c) 2021 RSK Labs Ltd
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import ast
import contextlib
import io
import sys


def post_process_list_apps(raw_output):
    app_list = []
    for line in raw_output.splitlines():
        line = line.strip()
        if line.startswith("[{") and line.endswith("}]"):
            data = ast.literal_eval(line)
            if isinstance(data, list) and all(
                    isinstance(app_dict, dict) for app_dict in data):
                for app_dict in data:
                    app_list.append(app_dict["name"])
                break
    if app_list:
        return "\n".join([f"Installed app: {app}" for app
                          in app_list])
    else:
        return "No apps installed"


def main():
    import runpy

    utilities = {
        "load": {"module": "loadApp", "post_process": None},
        "delete": {"module": "deleteApp", "post_process": None},
        "setupCA": {"module": "setupCustomCA", "post_process": None},
        "resetCA": {"module": "resetCustomCA", "post_process": None},
        "genCA": {"module": "genCAPair", "post_process": None},
        "listApps": {"module": "listApps", "post_process": post_process_list_apps},
    }

    if len(sys.argv) < 2 or sys.argv[1] not in utilities:
        commands = ", ".join(utilities.keys())
        print("Ledgerblue utilities")
        print(f"usage: {sys.argv[0]} {{{commands}}} [options]")
        sys.exit(99)

    try:
        command = sys.argv[1]
        sys.argv = [f"{sys.argv[0]} {command}"] + sys.argv[2:]
        module = f"ledgerblue.{utilities[command]["module"]}"
        post_process = utilities[command]["post_process"]

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            with contextlib.suppress(UnicodeDecodeError):
                runpy.run_module(module, run_name="__main__")
        output = buffer.getvalue()
        buffer.close()
        if post_process:
            output = post_process(output)
        if output:
            print(output)
        sys.exit(0)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
