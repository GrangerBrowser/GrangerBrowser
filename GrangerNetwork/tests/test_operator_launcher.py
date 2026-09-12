from pathlib import Path
import os
import subprocess
import sys
import unittest


class OperatorLauncherTests(unittest.TestCase):
    def test_coordinator_imports_in_isolated_python_mode(self):
        tool = Path(__file__).resolve().parents[1] / 'tools/operator_renewal.py'
        environment = dict(os.environ, PYTHONPATH='nonexistent-poisoned-module-path')
        result = subprocess.run([sys.executable, '-I', '-B', str(tool), '--help'],
                                env=environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--config', result.stdout)


if __name__ == '__main__':
    unittest.main()
