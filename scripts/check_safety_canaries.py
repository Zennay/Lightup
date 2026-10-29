"""CI-compatible wrapper for the installed offline safety canary."""
from lightup.lab_canary import main
if __name__ == "__main__":
    raise SystemExit(main())
