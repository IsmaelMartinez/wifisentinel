Scan the current network and produce a multi-persona security analysis.

Run the scanner using `tsx src/cli.ts analyse --verbose` and present the results.

If the scan fails (e.g. missing tools, permission errors), suggest the user run with `sudo` or install missing tools.

After the scan completes, provide a brief summary highlighting:
1. The overall compliance grade and score
2. The consensus risk rating across all five personas
3. The top 3 priority actions from the consensus
4. Any critical or high severity findings that need immediate attention

If the user provides arguments like `$ARGUMENTS`, pass them through to the command (e.g. `--skip-speed`, `--skip-ports`, `--skip-traffic`, `-o json`).
