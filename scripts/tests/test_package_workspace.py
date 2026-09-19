from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[2]
SHELL = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'


@unittest.skipUnless(os.name == 'nt', 'Windows packaging policy')
class PackageWorkspaceTests(unittest.TestCase):
    def run_script(self, command):
        return subprocess.run(
            [str(SHELL), '-NoProfile', '-NonInteractive', '-Command', command],
            cwd=PROJECT, capture_output=True, text=True, timeout=15,
        )

    def resolve(self, path):
        return self.run_script(
            ". ./scripts/PackageWorkspace.ps1; "
            f"Resolve-PackageCandidate -ProjectRoot (Get-Location).Path -Path '{path}'"
        )

    def test_only_candidate_in_dedicated_build_workspace_is_accepted(self):
        result = self.resolve('build/package-work/regression/candidate')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('build\\package-work\\regression\\candidate', result.stdout)

    def test_absolute_candidate_in_dedicated_build_workspace_is_accepted(self):
        candidate = PROJECT / 'build/package-work/regression-absolute/candidate'
        result = self.resolve(str(candidate))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(candidate), result.stdout)

    def test_release_validators_do_not_duplicate_absolute_package_path(self):
        candidate = PROJECT / 'build/package-work/regression-validator/candidate'
        candidate.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, candidate.parent, True)
        for script in ('test-windows-portability.ps1', 'test-release.ps1'):
            with self.subTest(script=script):
                result = self.run_script(
                    f"& ./scripts/{script} -PackageDirectory '{candidate}'"
                )
                self.assertNotEqual(result.returncode, 0)
                duplicated = str(PROJECT) + '\\' + str(candidate)
                self.assertNotIn(duplicated, result.stdout + result.stderr)

    def test_canonical_old_staging_and_arbitrary_build_paths_are_rejected(self):
        for path in ['release/Granger Browser', 'release/.local-staging',
                     'release/.previous', 'build/desktop',
                     'build/package-work/candidate',
                     'build/package-work/test/../../../release/candidate']:
            with self.subTest(path=path):
                result = self.resolve(path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('outside release', result.stderr)

    def test_missing_wan_bundle_fails_before_runtime_or_package_mutation(self):
        result = self.run_script(
            "& ./scripts/package-local-granger-runtime.ps1 "
            "-PackageDirectory build/package-work/regression/candidate -WanBundleDirectory ''"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('WAN_BUNDLE_REQUIRED', result.stderr)
        self.assertFalse((PROJECT / 'build/package-work/regression').exists())

    def test_local_build_rejects_missing_bundle_before_compilation(self):
        # The public wrapper checks source cleanliness before delegating to this preflight.
        result = self.run_script("& ./scripts/build-local-release.ps1 -WanBundleDirectory ''")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('WAN_BUNDLE_REQUIRED', result.stderr)

    def test_release_acceptance_paths_remain_in_child_scripts_workspace(self):
        result = self.run_script(
            "$projectRoot=(Get-Location).Path; "
            "$tokens=$null; $errors=$null; "
            "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
            "(Resolve-Path './scripts/test-release.ps1'), [ref]$tokens, [ref]$errors); "
            "$assignment=$ast.Find({param($node) "
            "$node -is [System.Management.Automation.Language.AssignmentStatementAst] "
            "-and $node.Left.Extent.Text -eq '$temporaryRoot'}, $true); "
            "Invoke-Expression $assignment.Extent.Text; "
            "$expected=[IO.Path]::GetFullPath((Join-Path $projectRoot 'build/package-work')); "
            "if ([IO.Path]::GetDirectoryName($temporaryRoot) -ne $expected) "
            "{ throw 'Acceptance root violates child script workspace validation' }; "
            "$copy=Join-Path $temporaryRoot 'path with spaces/copied release/Granger Browser'; "
            "$relative=$copy.Substring($projectRoot.Length+1); "
            "if ([IO.Path]::GetFullPath((Join-Path $projectRoot $relative)) -ne $copy) "
            "{ throw 'Relative acceptance path does not round trip' }"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_changed_powershell_scripts_parse(self):
        for name in ['PackageWorkspace.ps1', 'build-local-release.ps1', 'build-release.ps1',
                     'package-release.ps1', 'package-local-granger-runtime.ps1', 'test-release.ps1']:
            with self.subTest(name=name):
                result = self.run_script(
                    '$tokens=$null; $errors=$null; '
                    f"[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path './scripts/{name}'), "
                    '[ref]$tokens, [ref]$errors) | Out-Null; '
                    'if ($errors.Count) { $errors | ForEach-Object { $_.Message }; exit 1 }'
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
