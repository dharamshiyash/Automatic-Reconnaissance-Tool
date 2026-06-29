"""
Automatic Recon Tool — Entry Point.

This file serves as the backward-compatible launcher.
Running `python automatic_recon_gui.py` launches the full application
with splash screen and professional GUI.

For the original monolithic version, see git history.
"""

from recon.gui.app import main

if __name__ == "__main__":
    main()
