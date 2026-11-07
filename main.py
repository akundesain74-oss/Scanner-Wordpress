from pathlib import Path

from core.engine import Engine
from core.validation.target import TargetValidator
from output.terminal import Terminal
from output.json_report import write_json_report
from output.html_report import write_html_report

from modules.http.module import HTTPIntelligence
from modules.tls.module import TLSIntelligence
from modules.dns.module import DNSIntelligence
from modules.dns.resolver import DNSLiveResolver
from modules.vulnerability.module import VulnerabilityIntelligence


def main():
    terminal = Terminal()
    engine = Engine(terminal)

    engine.register(HTTPIntelligence())
    engine.register(TLSIntelligence())

    dns_module = DNSIntelligence()
    dns_module.resolver = DNSLiveResolver(
        timeout=2.0,
        lifetime=4.0
    )
    engine.register(dns_module)

    engine.register(VulnerabilityIntelligence())

    terminal.banner()

    print("[*] Registered modules:", len(engine.modules))
    print("[*] Mode: Passive Intelligence")
    print()

    target = input("Target URL: ").strip()

    validator = TargetValidator()
    valid, result = validator.validate(target)

    if not valid:
        print("[ERROR] Invalid target:", result)
        return

    hostname = result

    print()
    print("[*] Target:", target)
    print("[*] Hostname:", hostname)
    print("[*] Validation: PASS")

    context = {
        "target": target,
        "hostname": hostname,
        "vulnerability_observations": []
    }

    engine.execute(context)

    terminal.report_component_inventory(context)

    report_path = write_json_report(
        Path("output/report.json"),
        context,
        engine.findings
    )

    print()
    print("[*] JSON report saved:", report_path)

    html_path = write_html_report(
        Path("output/report.html"),
        context,
        engine.findings
    )
    print("[*] HTML report saved:", html_path)


if __name__ == "__main__":
    main()
