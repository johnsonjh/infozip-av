# Xtro-ZIP 32-bit OS/2 port

- [BUILD-AND-VERIFICATION.md](BUILD-AND-VERIFICATION.md): clean patch/build, regression commands, release gates.
- [BETA-TEST-REGIMEN.md](BETA-TEST-REGIMEN.md): exact native beta-test commands and reporting requirements.
- [ENTROPY.md](ENTROPY.md): approved OS/2 weak AES salt fallback,
  threat model, native testing and future provider work.
- [POLICY.md](POLICY.md): approved native EA, dual-format encryption, kLIBC
  symlink and restoration-safety contracts.
- [TEST-PLAN-XTRO-V1.md](TEST-PLAN-XTRO-V1.md): multi-version/multi-filesystem
  acceptance matrix and reproducible reporting protocol.
- [os2-native-test-plan.md](os2-native-test-plan.md): basic OS/2 native LX
  smoke tests and utility tests.
- [os2-upstream-commit-audit.md](os2-upstream-commit-audit.md): bitwiseworks
  Zip/UnZip Git history audit.
- [os2-netlabs-svn-audit.md](os2-netlabs-svn-audit.md): Netlabs SVN snapshot audit.
- [../xtro-ea-v1/FORMAT.md](../xtro-ea-v1/FORMAT.md): platform-neutral V1
  binary-format specification.

The baseline Open Watcom cross-build proves a toolchain/link result only.
A production claim requires the integrated adapter, confidentiality-safe
encrypted metadata staging, verified symlink activation, and native acceptance.
The AES entropy compatibility fallback is implemented, but is **not secure
randomness** and does not imply certified AES behavior on an OS/2 host.

Implementation gate and exact test scope: [IMPLEMENTATION-STATUS.md](IMPLEMENTATION-STATUS.md).

### Native Xtro V1 beta-testing

See [BETA-TEST-REGIMEN.md](BETA-TEST-REGIMEN.md) for a step-by-step native
acceptance matrix covering Zip/UnZip, EA and ACL compatibility, directory
option B, AES, kLIBC symbolic links and failure cases. Build a fixture
inspector using `OS2_TEST_HELPERS=1 ./build-os2.sh` to produce
`os2/ea-fixture.exe`; use it only on disposable native OS/2 files.
