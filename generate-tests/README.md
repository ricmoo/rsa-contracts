Test Generation
===============

All tests were created using `generate-test.mjs`, which calls the
OpenSSL CLI to generate private keys and sign random data.

The script uses deterministic random numbers, so it will produce the
same test cases on each run.

The final file, `tests.json` is what you are likely interested in though.
