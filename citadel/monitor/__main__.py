"""python -m citadel.monitor: the connection monitor for this OS."""
import sys

from . import common


def main():
    if sys.platform == "darwin":
        from . import darwin as backend
    else:
        from . import linux as backend
    common.use(backend)
    try:
        common.main()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
