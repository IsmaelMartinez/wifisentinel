# Terminal Revamp Design Spec

WiFi Sentinel's terminal output is functional but dated: fixed 72-char width, no scan progress, manual string padding, inaccessible red/green colour coding, and no connection between the dashboard and CLI for triggering scans. This spec describes a progressive enhancement of the terminal experience and a lightweight dashboard integration, designed so the architecture naturally extends into Phase 6 (Continuous Monitoring) when the time comes.

## Goals

The terminal and dashboard are two views of the same scan data, each playing to its medium's strengths. The terminal gets a progressive, accessible report with live scan feedback. The dashboard gets the ability to trigger scans and display results as they arrive, including a spatial network topology. Both consume the same underlying event stream from the collector.

Accessibility is not a flag. The default colour palette, icon choices, and information encoding work for everyone, including users with colour vision deficiency.

## Approach

Start with Approach A (progressive enhancement of the existing reporter), but design the internal event model so it supports Approach C (unified streaming architecture) later. The scan pipeline gains an internal EventEmitter; the terminal and dashboard are independent consumers. Scanners themselves are unchanged.

## 1. Accessible Colour System

The current reporter uses green for pass and red for fail, which is indistinguishable for roughly 8% of men with colour vision deficiency. The new palette communicates every status through three redundant channels: colour, icon shape, and text label.

The semantic palette maps statuses as follows. PASS uses teal/cyan (#4ec9b0) with a checkmark icon — teal is distinguishable from red across all common CVD types. FAIL keeps red (#f44747) with a cross icon, disambiguated from teal by both shape and label. WARN uses amber/gold (#cca700) with a triangle icon, distinct from both teal and red. INFO uses blue (#569cd6) with a circle icon for neutral information. N/A uses dim grey with a dash.

The `figures` library provides these Unicode symbols with automatic ASCII fallbacks for terminals that don't support them (e.g. checkmark falls back to a tick character). This replaces the current hardcoded Unicode characters in `render-helpers.ts`.

The same semantic palette applies to the dashboard. The existing dashboard colours (green-500, red-500, yellow-500) shift to match the teal/red/amber/blue system so both surfaces feel consistent without being identical.

## 2. Scan Progress

The current experience shows a blank terminal while scanners run, which can take 30-90 seconds depending on which stages are enabled. The new experience uses `listr2` to render a live task tree that maps to the collector's scan stages.

The task tree shows each scanner as a top-level task. Completed tasks display a one-line summary of what was found (e.g. "802.11ax, 5GHz, ch48, WPA3" for the WiFi scanner). The currently running task shows a spinner. Pending tasks are dimmed. listr2 supports concurrent task visualisation, so the parallel first stage (wifi, dns, security, connections) shows four spinners at once.

When host discovery completes, a network tree section appears below the task list. listr2 manages the progress area at the top; once it finishes rendering (all tasks complete or the bottom-rendered output begins), the network tree renders below it using `log-update` to overwrite its own section in place without scrolling. The two do not share the same output region — listr2 owns the top, the tree owns the bottom.

After all scanners complete, the full report renders below the progress section. An optional `--clean` flag clears the progress output first, leaving only the final report.

## 3. Progressive Network Tree (Terminal)

The network tree in the terminal evolves through three phases as scanners complete.

Phase 1 (Discovery) shows bare IP addresses as they're found, with a "scanning..." indicator at the bottom. The gateway is highlighted at the top.

Phase 2 (Enrichment) adds MAC addresses, vendor names, and device type flags. Cameras and other flagged devices are highlighted in red with a warning marker.

Phase 3 (Deep Analysis) adds open ports and services below each host. The tree header updates with aggregate counts ("7 hosts, 12 services").

The tree uses standard Unicode box-drawing characters (same as the existing reporter) and renders using `log-update` so it updates in place without scrolling.

## 4. Responsive Report Layout

The fixed 72-character inner width (`W = 72` in `render-helpers.ts`) is replaced with dynamic width detection via `process.stdout.columns`, clamped to a minimum of 60 and maximum of 120 characters.

Tabular data (host/port table, nearby networks, DNS records, compliance findings, connection destinations) switches from manual `pad()` alignment to `cli-table3`, which handles Unicode-bordered tables with cell spanning, alignment, word wrapping, and ANSI colour support. The box-drawing border style matches the existing aesthetic.

Section containers (the `hRule`/`boxLine`/`sectionHeader` functions in `render-helpers.ts`) are kept but adapted to use the dynamic width. These are simple enough that a library like `boxen` adds more complexity than it removes.

## 5. Inline Data Visualisation

Three types of inline visualisation are added using `sparkly` and Unicode block characters.

Channel saturation sparklines show per-channel occupancy for 2.4 GHz and 5 GHz bands as compact bar sequences with colour gradients (teal for low, amber for moderate, red for high). These replace or complement the existing saturation bar.

Signal strength trends show the last 10 scan readings (or fewer if less history exists) as a sparkline when scan history is available, with the average value and direction (improving/degrading) as a suffix.

Security score history shows the score trend across recent scans as a sparkline with the numeric change.

These appear inline in the relevant report sections and are omitted when no historical data is available.

## 6. Clickable Links

The `terminal-link` library creates hyperlinks in terminals that support them (iTerm2, Windows Terminal, Hyper, VS Code integrated terminal). Compliance findings that reference remediation URLs become clickable. In terminals that don't support hyperlinks, the URL prints as plain text — the library handles this fallback automatically.

## 7. Collector Event Model

The collector gains a Node.js `EventEmitter` mixin. Each scanner still returns its typed result as before — the collector wraps each scanner call to emit events at key points.

The event types are:

`scan:start` — emitted once when the scan begins, contains scan ID and timestamp.
`scanner:start` — emitted when a scanner begins, contains the scanner name.
`scanner:complete` — emitted when a scanner finishes, contains the scanner name and a one-line summary string.
`scanner:error` — emitted when a scanner fails, contains the scanner name and error message.
`host:found` — emitted during host discovery for each discovered host, contains IP and MAC.
`host:enriched` — emitted when vendor/type info is resolved for a host.
`port:found` — emitted during port scanning for each open port found.
`scan:complete` — emitted once when all scanners finish, contains the final `NetworkScanResult`.
`scan:score` — emitted after scoring, contains the security score.

A new `--events` flag on the CLI outputs these events as NDJSON to stdout instead of the formatted report. In Approach A, two consumers use these events: the terminal UI subscribes internally (via listr2 and the network tree), and the dashboard spawns the CLI with `--events` and reads the NDJSON stream. In future Approach C, the same NDJSON output becomes the public interface for piping into external SIEM tools, jq, and other consumers.

## 8. Dashboard Integration

The dashboard gains a "Run Scan" capability. The implementation has three parts.

A new API route `POST /api/scans/run` accepts scan options (matching the existing `--skip-*` flags) and spawns the CLI as a child process via `child_process.spawn`. The CLI is invoked with a new `--events` flag that outputs NDJSON events to stdout instead of the formatted report. The API route streams these events back to the browser as Server-Sent Events (SSE).

The dashboard scan list page gets a "Run Scan" button with checkboxes for scan options (ports, speed, traffic, analysis). Clicking it opens a live scan view that shows a progress panel (matching the listr2 task list structure) and a network topology panel.

The network topology uses a D3 force-directed graph. The gateway renders as a central node. Device nodes animate into existence as `host:found` events arrive. Node colour encodes risk level (teal for safe, amber for attention, red for risk, blue for info-only). Node size reflects the number of open services. Clicking a node shows its detail. When the scan completes, the view transitions to the standard scan detail page with all tabs (Summary, Personas, Compliance, RF).

Results are saved to `~/.wifisentinel/scans/` by the CLI process, the same as running from the terminal. The dashboard reads from the same store.

## 9. New Dependencies

Six new packages are added to the CLI:

`listr2` — scan progress rendering with spinners and nested tasks (~28M weekly downloads).
`cli-table3` — responsive Unicode tables with colour support (~19M weekly downloads).
`figures` — Unicode symbols with ASCII fallbacks (~30M weekly downloads).
`log-update` — overwrite previous terminal output for live updates (~17M weekly downloads).
`sparkly` — inline sparkline charts (~200K weekly downloads).
`terminal-link` — clickable hyperlinks with automatic fallback (~14M weekly downloads).

All are pure ESM, well-maintained, and have no native dependencies.

The dashboard gains one new dependency: `d3-force` (and supporting `d3-*` modules) for the topology graph. The dashboard already uses recharts (which depends on d3 internally), so this is a lightweight addition.

## 10. What Does Not Change

Scanner implementations are unchanged — they still return typed results via the same interfaces. The Zod schemas (`scan-result.ts` and related) are unchanged. The JSON reporter is unchanged. The analyser, persona modules, and standards scoring are unchanged. The store format and file structure are unchanged. The existing `--skip-*` flags and output options work as before. OTEL instrumentation is unchanged. The TV controller is unaffected. The recon command and its reporter are unchanged.

## 11. Spike Plan

Before full implementation, three spikes verify the critical unknowns against the real network.

Spike 1 (listr2 + events): wire listr2 into the existing collector with a minimal EventEmitter wrapper. Run a real scan and verify the task tree renders correctly with the current scanner timing. Confirm that listr2's output doesn't conflict with verbose stderr logging.

Spike 2 (progressive network tree): implement the three-phase tree rendering with log-update. Run against the home network to verify the discovery-to-enrichment-to-ports progression looks right with real device counts and timing.

Spike 3 (dashboard SSE): add the `--events` flag, the `POST /api/scans/run` route, and a minimal SSE consumer in the dashboard. Trigger a scan from the browser and verify events stream correctly. No topology graph yet — just the progress panel.

Each spike is a throwaway branch. Learnings feed back into the implementation plan.
