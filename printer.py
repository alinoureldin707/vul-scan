try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.text import Text

    console = Console()
    RICH_AVAILABLE = True
except Exception:
    RICH_AVAILABLE = False


def _safe_get(v, key):
    if isinstance(v, dict):
        return v.get(key)
    return getattr(v, key, None)


def _fmt_line_range(start, end) -> str:
    if not start and not end:
        return ""
    if start == end or not end:
        return f"line {start}"
    return f"lines {start}–{end}"


# ── Generic message helpers ─────────────────────

def print_info(msg: str):
    if RICH_AVAILABLE:
        console.print(f"[cyan]ℹ[/cyan]  {msg}")
    else:
        print(f"  {msg}")


def print_success(msg: str):
    if RICH_AVAILABLE:
        console.print(f"[bold green]✔[/bold green]  {msg}")
    else:
        print(f"✔  {msg}")


def print_warning(msg: str):
    if RICH_AVAILABLE:
        console.print(f"[bold yellow]⚠[/bold yellow]  {msg}")
    else:
        print(f"⚠  {msg}")


def print_error(msg: str):
    if RICH_AVAILABLE:
        console.print(f"[bold red]✖[/bold red]  {msg}")
    else:
        print(f"✖  {msg}")


# ── Section headers ─────────────────────

def print_header(index: int, total: int, file_path: str):
    if RICH_AVAILABLE:
        console.print()
        console.rule(
            f"[bold white][{index}/{total}][/bold white] [cyan]{file_path}[/cyan]",
            style="dim",
        )
    else:
        print()
        print("=" * 80)
        print(f"[{index}/{total}] {file_path}")
        print("=" * 80)


# ── Vulnerability card ─────────────────────

def print_vulnerability(vuln):
    owasp_id       = _safe_get(vuln, "owasp_id") or ""
    name           = _safe_get(vuln, "name") or ""
    description    = _safe_get(vuln, "description") or ""
    evidence       = _safe_get(vuln, "evidence") or ""
    line_start     = _safe_get(vuln, "line_start") or 0
    line_end       = _safe_get(vuln, "line_end") or 0
    steps          = _safe_get(vuln, "exploitation_steps") or []
    impact         = _safe_get(vuln, "impact") or ""
    mitigation     = _safe_get(vuln, "mitigation") or ""
    fix_line_start = _safe_get(vuln, "fix_line_start") or 0
    fix_line_end   = _safe_get(vuln, "fix_line_end") or 0
    fixed_code     = _safe_get(vuln, "fixed_code") or ""

    vuln_range = _fmt_line_range(line_start, line_end)
    fix_range  = _fmt_line_range(fix_line_start, fix_line_end)

    if RICH_AVAILABLE:
        title = Text()
        title.append(owasp_id, style="bold white")
        title.append("  —  ", style="dim")
        title.append(name, style="bold red")
        if vuln_range:
            title.append(f"  [{vuln_range}]", style="dim yellow")
        console.print(Panel(title, border_style="red", padding=(0, 1)))
        console.print(f"  [bold]Description[/bold]  {description}")
        console.print(f"  [bold]Evidence[/bold]     {evidence}")
        if vuln_range:
            console.print(f"  [bold]Location[/bold]     [yellow]{vuln_range}[/yellow]")
        if steps:
            console.print("  [bold]Exploitation[/bold]")
            for s in steps:
                console.print(f"    [dim]•[/dim] {s}")
        console.print(f"  [bold]Impact[/bold]       {impact}")
        console.print(f"  [bold]Mitigation[/bold]   {mitigation}")
        if fixed_code:
            fix_title = "Fixed Code" + (f"  ({fix_range})" if fix_range else "")
            syntax = Syntax(
                fixed_code, "python",
                theme="monokai",
                line_numbers=bool(fix_line_start),
                start_line=fix_line_start or 1,
                background_color="default",
            )
            console.print(Panel(
                syntax,
                title=f"[bold green]{fix_title}[/bold green]",
                border_style="green",
                padding=(0, 1),
            ))
        console.print()
    else:
        range_tag = f" [{vuln_range}]" if vuln_range else ""
        print(f"\n{'='*72}")
        print(f"{owasp_id}  —  {name}{range_tag}")
        print(f"{'='*72}")
        print(f"Description : {description}")
        print(f"Evidence    : {evidence}")
        if vuln_range:
            print(f"Location    : {vuln_range}")
        if steps:
            print("Exploitation:")
            for s in steps:
                print(f"  - {s}")
        print(f"Impact      : {impact}")
        print(f"Mitigation  : {mitigation}")
        if fixed_code:
            fix_label = "Fixed Code" + (f" ({fix_range})" if fix_range else "")
            print(f"{fix_label}:")
            print(fixed_code)
        print()


# ── Summary table ─────────────────────

def print_summary(summary: dict):
    if RICH_AVAILABLE:
        console.print()
        console.rule("[bold]Scan Summary[/bold]", style="dim")
        table = Table(show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("File", style="cyan", no_wrap=True)
        table.add_column("Vulnerabilities", style="magenta", justify="right")
        total = 0
        for fp, cnt in summary.items():
            color = "green" if cnt == 0 else "red"
            table.add_row(fp, f"[{color}]{cnt}[/{color}]")
            total += cnt
        table.add_section()
        c = "red" if total else "green"
        table.add_row("[bold]TOTAL[/bold]", f"[bold {c}]{total}[/bold {c}]")
        console.print(table)
    else:
        print("\nScan Summary")
        print("{:<60} {:>15}".format("File", "Vulnerabilities"))
        print("-" * 77)
        for fp, cnt in summary.items():
            print("{:<60} {:>15}".format(fp, cnt))
        print("-" * 77)
        print("{:<60} {:>15}".format("TOTAL", sum(summary.values())))
