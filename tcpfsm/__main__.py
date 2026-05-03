from .cli import main  # noqa: F401 — re-exported for entry_points
import sys

if __name__ == "__main__":
    sys.exit(main())
