#!/usr/bin/env python
import sys
import pytest


# sys.exit() is required otherwise the wrapper exits
# with exit code 0, regardless the pytest.main() execution
sys.exit(pytest.main())
