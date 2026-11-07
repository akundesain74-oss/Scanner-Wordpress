
class Engine:
    def __init__(self, terminal):
        self.terminal = terminal
        self.modules = []
        self.findings = []

    def register(self, module):
        if not callable(getattr(module, "run", None)):
            raise TypeError("Module must implement run(context, emit)")

        self.modules.append(module)

    def emit(self, finding):
        finding.validate()
        self.findings.append(finding)
        self.terminal.emit(finding)

    def execute(self, context):
        self.terminal.banner()

        for module in self.modules:
            name = getattr(
                module,
                "name",
                module.__class__.__name__
            )

            print(f"\n[*] Starting module: {name}")

            try:
                module.run(context, self.emit)
            except Exception as exc:
                print(
                    f"[ERROR] {name}: "
                    f"{type(exc).__name__}: {exc}"
                )

        print("\n[*] Engine finished.")
        print(f"[*] Total findings: {len(self.findings)}")
