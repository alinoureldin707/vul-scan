try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.markdown import Markdown
    console = Console()
    RICH_AVAILABLE = True
except Exception:
    RICH_AVAILABLE = False


def _safe_get(v, key):
    if isinstance(v, dict):
        return v.get(key)
    return getattr(v, key, None)


def print_header(index: int, total: int, file_path: str):
    title = f"[{index}/{total}] Analyzing: {file_path}"
    if RICH_AVAILABLE:
        console.rule(title)
    else:
        print("=" * 80)
        print(title)
        print("=" * 80)


def print_vulnerability(vuln):
    owasp_id = _safe_get(vuln, "owasp_id") or _safe_get(vuln, "id") or ""
    name = _safe_get(vuln, "name") or ""
    description = _safe_get(vuln, "description") or ""
    evidence = _safe_get(vuln, "evidence") or ""
    steps = _safe_get(vuln, "exploitation_steps") or _safe_get(vuln, "exploitation") or []
    impact = _safe_get(vuln, "impact") or ""
    mitigation = _safe_get(vuln, "mitigation") or ""

    if RICH_AVAILABLE:
        header = f"{owasp_id} — {name}" if owasp_id else name
        console.print(Panel(header, style="bold red"))
        console.print("[bold]Description:[/bold] " + description)
        console.print("[bold]Evidence:[/bold] " + evidence)
        if steps:
            console.print("[bold]Exploitation Steps:[/bold]")
            for s in steps:
                console.print(f"  • {s}")
        console.print("[bold]Impact:[/bold] " + impact)
        console.print("[bold]Mitigation:[/bold] " + mitigation)
        console.print("")
    else:
        print(f"Vulnerability: {owasp_id} {name}")
        print(f"Description: {description}")
        print(f"Evidence: {evidence}")
        if steps:
            print("Exploitation Steps:")
            for s in steps:
                print(f"  - {s}")
        print(f"Impact: {impact}")
        print(f"Mitigation: {mitigation}")
        print()


def print_summary(summary: dict):
    # summary: { file_path: count }
    if RICH_AVAILABLE:
        table = Table(title="Vulnerability Summary per File")
        table.add_column("File", style="cyan", no_wrap=True)
        table.add_column("# Vulnerabilities", style="magenta")
        for fp, cnt in summary.items():
            table.add_row(fp, str(cnt))
        console.rule("Summary")
        console.print(table)
    else:
        print("\nSummary: Vulnerabilities per file")
        print("{:<60} {:>10}".format("File", "Count"))
        print("-" * 72)
        for fp, cnt in summary.items():
            print("{:<60} {:>10}".format(fp, cnt))
