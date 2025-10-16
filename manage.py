#!/usr/bin/env python3
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'arpia_project.settings')
    try:
        from django.core.management import execute_from_command_line, call_command
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    should_skip_auto_migrate = "--skip-auto-migrate" in sys.argv
    if should_skip_auto_migrate:
        sys.argv = [arg for arg in sys.argv if arg != "--skip-auto-migrate"]

    if len(sys.argv) > 1 and sys.argv[1] == "runserver" and not should_skip_auto_migrate:
        noreload_requested = "--noreload" in sys.argv
        run_main_flag = os.environ.get("RUN_MAIN") == "true"

        if noreload_requested or run_main_flag:
            import django
            from django.core.management.base import CommandError

            django.setup()
            try:
                call_command("migrate", interactive=False)
            except CommandError as exc:
                from django.core.management.color import color_style

                style = color_style()
                print(style.WARNING(f"Aviso: falha ao aplicar migrações automaticamente: {exc}"))

    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
