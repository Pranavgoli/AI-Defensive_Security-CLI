import click
import os
from rich.console import Console
from ds_cli.config import settings
from ds_cli.ingestion.parser import parse_log_file
from ds_cli.ingestion.normalizer import normalize_log
from ds_cli.detection.rules import DetectionEngine
from ds_cli.ai.analyzer import AIAnalyzer
from ds_cli.reporting.generator import save_report

MAX_FILE_SIZE_MB = 50

console = Console()

DS_BANNER = r"""
[bold cyan]
    ____  _____   ________    ____
   / __ \/ ___/  / ____/ /   /  _/
  / / / /\__ \  / /   / /    / /  
 / /_/ /___/ / / /___/ /____/ /   
/_____//____/  \____/_____/___/   
[/bold cyan]
[bold white]AI Defensive Security CLI[/bold white]
"""

def check_file_size(file_path: str):
    """Prevent OOM DoS by enforcing a maximum ingestion file size."""
    size_mb = os.path.getsize(file_path) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        console.print(f"[bold red]Error:[/bold red] File {file_path} ({size_mb:.2f}MB) exceeds maximum allowed size of {MAX_FILE_SIZE_MB}MB.")
        raise click.Abort()

@click.group()
def cli():
    """AI Powered Defensive Security CLI."""
    pass

@cli.command()
def info():
    """Display CLI information and banner"""
    console.print(DS_BANNER)
    console.print(f"[green]Initialized with configuration from: {settings.config_path}[/green]")
    console.print(f"[green]AI Model Base: {settings.ai_api_base} | Model: {settings.ai_model}[/green]")

@cli.command()
@click.argument('log_file', type=click.Path(exists=True))
def ingest(log_file):
    """Ingest and normalize a log file for analysis."""
    check_file_size(log_file)
    console.print(f"[yellow]Ingesting log file:[/yellow] {log_file}...")
    raw_logs = parse_log_file(log_file)
    normalized_logs = [normalize_log(log) for log in raw_logs]
    
    console.print(f"[green]Successfully parsed and normalized {len(normalized_logs)} logs.[/green]")
    if normalized_logs:
        console.print("[cyan]Sample normalized log:[/cyan]")
        console.print(normalized_logs[0].model_dump_json(indent=2))

@cli.command()
@click.argument('log_file', type=click.Path(exists=True))
def analyze(log_file):
    """Analyze ingested events and detect threats."""
    check_file_size(log_file)
    console.print(f"[yellow]Processing log file:[/yellow] {log_file}...")
    raw_logs = parse_log_file(log_file)
    normalized_logs = [normalize_log(log) for log in raw_logs]
    
    console.print("[yellow]Running threat detection engine...[/yellow]")
    engine = DetectionEngine()
    alerts = engine.process_logs(normalized_logs)
    
    console.print(f"[bold cyan]Detected {len(alerts)} alerts.[/bold cyan]")
    for alert in alerts:
        console.print(f"- {alert.alert_id} | {alert.severity} | {alert.title} | IP: {alert.source_ip}")

@cli.command()
@click.argument('log_file', type=click.Path(exists=True))
def report(log_file):
    """Generate AI-powered incident reports for a log file."""
    check_file_size(log_file)
    console.print(f"[yellow]Processing log file:[/yellow] {log_file}...")
    raw_logs = parse_log_file(log_file)
    normalized_logs = [normalize_log(log) for log in raw_logs]
    
    console.print("[yellow]Running threat detection engine...[/yellow]")
    engine = DetectionEngine()
    alerts = engine.process_logs(normalized_logs)
    
    if not alerts:
        console.print("[green]No alerts detected. No reports generated.[/green]")
        return
        
    console.print(f"[cyan]Initializing AI Analyzer ({settings.ai_model})...[/cyan]")
    analyzer = AIAnalyzer()
    
    for alert in alerts:
        console.print(f"[yellow]Analyzing Alert {alert.alert_id}...[/yellow]")
        analyzed_data = analyzer.analyze_alert(alert)
        
        console.print(f"[yellow]Generating report for {alert.alert_id}...[/yellow]")
        report_md = analyzer.generate_incident_report(analyzed_data)
        
        saved_path = save_report(alert.alert_id, report_md)
        if saved_path:
            console.print(f"[bold green]Report saved to:[/bold green] {saved_path}")
        else:
            console.print(f"[bold red]Failed to save report for {alert.alert_id}[/bold red]")

if __name__ == '__main__':
    import sys
    try:
        cli()
    except Exception as e:
        console.print(f"\n[bold red]Fatal Error:[/bold red] An unexpected system error occurred: {str(e)}")
        sys.exit(1)
