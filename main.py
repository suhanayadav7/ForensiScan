"""ForensiScan entry point."""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from gui.app import ForensiScanApp


def main():
    app = ForensiScanApp()
    app.run()


if __name__ == '__main__':
    main()
