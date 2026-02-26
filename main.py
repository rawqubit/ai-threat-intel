#!/usr/bin/env python3
"""
ai-threat-intel: AI-powered threat intelligence summarizer.
Accepts threat reports, IOC lists, or raw intelligence text and produces
structured summaries with TTPs, IOCs, attribution, and defensive recommendations.
"""

import sys
import click
from openai import OpenAI
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

client = OpenAI()
console = Console()


def read_input(source: str) -> str:
    """Read intelligence from a file or stdin."""
    if source == "-":
        return sys.stdin.read()
    try:
        with open(source, "r") as f:
            return f.read()
    except FileNotFoundError:
        console.print(f"[bold red]File not found:[/bold red] {source}")
        sys.exit(1)


@click.command()
@click.argument("source", default="-", metavar="FILE_OR_STDIN")
@click.option("--format", "output_format", default="markdown",
              type=click.Choice(["markdown", "json"], case_sensitive=False),
              help="Output format.")
@click.option("--actor", default=None, help="Known threat actor name for context.")
def summarize(source: str, output_format: str, actor: str):
    """Summarize threat intelligence from a file or stdin.

    Pass '-' as SOURCE to read from stdin.

    Example:
        cat report.txt | python main.py -
        python main.py report.txt --actor APT29
    """
    intel_text = read_input(source)
    if not intel_text.strip():
        console.print("[bold red]No input provided.[/bold red]")
        sys.exit(1)

    actor_context = f"\nKnown threat actor context: {actor}" if actor else ""
    console.print(Panel("[bold cyan]Analyzing threat intelligence...[/bold cyan]", expand=False))

    prompt = f"""You are a senior threat intelligence analyst. Analyze the following intelligence report and produce a structured summary including:

1. **Executive Summary** – 2-3 sentence overview.
2. **Threat Actor Profile** – Attribution, motivation, and sophistication level.
3. **TTPs (Tactics, Techniques & Procedures)** – Map to MITRE ATT&CK where possible.
4. **Indicators of Compromise (IOCs)** – Extract all IPs, domains, hashes, URLs.
5. **Targeted Industries/Sectors** – Who is being targeted?
6. **Defensive Recommendations** – Concrete mitigations and detection rules.
7. **Confidence Level** – Your confidence in the attribution and analysis.
{actor_context}

Intelligence Report:
---
{intel_text[:8000]}
---

Format your response in {"JSON" if output_format == "json" else "Markdown"}."""

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "You are an expert threat intelligence analyst with deep knowledge of APT groups, malware families, and the MITRE ATT&CK framework."},
                {"role": "user", "content": prompt}
            ]
        )
        result = response.choices[0].message.content
        if output_format == "json":
            console.print(result)
        else:
            console.print(Markdown(result))
    except Exception as e:
        console.print(f"[bold red]AI analysis error:[/bold red] {e}")


if __name__ == "__main__":
    summarize()
