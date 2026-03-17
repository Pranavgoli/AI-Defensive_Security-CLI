from ds_cli.main import cli
from rich.console import Console
import sys

if __name__ == '__main__':
    try:
        cli()
    except Exception as e:
        console = Console()
        console.print(f"\n[bold red]Fatal Error:[/bold red] An unexpected system error occurred: {str(e)}")
        sys.exit(1)
