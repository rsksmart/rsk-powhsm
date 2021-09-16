if __name__ == "__main__":
    import runpy
    import sys

    utilities = {
        "load": "loadApp",
        "delete": "deleteApp",
        "setupCA": "setupCustomCA",
        "resetCA": "resetCustomCA",
        "genCA": "genCAPair",
    }

    if len(sys.argv) < 2 or sys.argv[1] not in utilities:
        commands = ", ".join(utilities.keys())
        print("Ledgerblue utilities")
        print(f"usage: {sys.argv[0]} {{{commands}}} [options]")
        sys.exit(99)

    module = f"ledgerblue.{utilities[sys.argv[1]]}"
    sys.argv = [f"{sys.argv[0]} {sys.argv[1]}"] + sys.argv[2:]
    try:
        res = runpy.run_module(module, run_name="__main__")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
