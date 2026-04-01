# Contributing to WiFi Sentinel

Contributions are welcome. This project follows a standard fork-and-PR workflow.

## Getting Started

```bash
git clone https://github.com/IsmaelMartinez/wifisentinel.git
cd wifisentinel
npm install
npm test
npm run lint
npm run build
```

## Development

Run the CLI in development mode (no build step needed):

```bash
npm run dev -- scan --skip-speed
```

Start the dashboard (separate dependencies):

```bash
cd dashboard && npm install
npm run dashboard
```

## Branch Conventions

All work goes through feature branches and pull requests. Direct pushes to `main` are not accepted.

- `feature/<description>` for new work
- `fix/<description>` for bug fixes

## Code Conventions

- UK English spelling throughout (analyser, analyse, normalised)
- TypeScript strict mode with ESM modules and `.js` extensions in imports
- Schemas use Zod for validation and type inference
- Terminal output uses chalk with box-drawing style from `render-helpers.ts`

## Commit Messages

Use imperative mood: "Add Linux WiFi scanner", "Fix schedule interval parsing".

## Testing

```bash
npm test           # run all tests
npm run typecheck  # tsc type-checking (includes tests)
npm run lint       # eslint
```

CI runs typecheck, build, lint, and tests on Node 20 and 22, plus a dashboard build, on every PR.

## Adding a Scanner

1. Create a new file in `src/collector/scanners/` following the existing pattern
2. Export a function that returns typed data matching the Zod schema in `src/collector/schema/scan-result.ts`
3. Wire it into the orchestrator in `src/collector/index.ts`
4. Add tests in `tests/`

## Adding a Persona

1. Create a new file in `src/analyser/personas/` following `red-team.ts` as a template
2. Export an `analyseAs<Name>` function returning `PersonaAnalysis`
3. Register it in `src/analyser/personas/index.ts`
4. Add tests in `tests/`
