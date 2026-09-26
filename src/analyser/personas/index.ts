import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import type { FullAnalysis, PersonaAnalysis, PersonaSpec } from "./types.js";
import { consensusActions, consensusRating, keyedActionsFor } from "./types.js";
import { analyseAsRedTeam, redTeamSpec } from "./red-team.js";
import { analyseAsBlueTeam, blueTeamSpec } from "./blue-team.js";
import { analyseAsCompliance, complianceSpec } from "./compliance.js";
import { analyseAsNetEngineer, netEngineerSpec } from "./net-engineer.js";
import { analyseAsPrivacy, privacySpec } from "./privacy.js";

export { analyseAsRedTeam } from "./red-team.js";
export { analyseAsBlueTeam } from "./blue-team.js";
export { analyseAsCompliance } from "./compliance.js";
export { analyseAsNetEngineer } from "./net-engineer.js";
export { analyseAsPrivacy } from "./privacy.js";

export type {
  PersonaId,
  Severity,
  Insight,
  RiskRating,
  PersonaAnalysis,
  FullAnalysis,
} from "./types.js";

export {
  riskFromInsights,
  consensusRating,
  consensusActions,
} from "./types.js";

export const PERSONAS: Array<[PersonaSpec, (result: NetworkScanResult) => PersonaAnalysis]> = [
  [redTeamSpec, analyseAsRedTeam],
  [blueTeamSpec, analyseAsBlueTeam],
  [complianceSpec, analyseAsCompliance],
  [netEngineerSpec, analyseAsNetEngineer],
  [privacySpec, analyseAsPrivacy],
];

/** Run all five persona analyses and compute consensus. */
export function analyseAllPersonas(result: NetworkScanResult): FullAnalysis {
  const analyses = PERSONAS.map(([, analyse]) => analyse(result));

  return {
    scanId: result.meta.scanId,
    timestamp: result.meta.timestamp,
    analyses,
    consensusRating: consensusRating(analyses.map((a) => a.riskRating)),
    consensusActions: consensusActions(
      analyses.map((a, i) => keyedActionsFor(a.insights, PERSONAS[i][0])),
    ),
  };
}
