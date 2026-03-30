import type { NetworkScanResult } from "../../collector/schema/scan-result.js";
import type { FullAnalysis, PersonaAnalysis, RiskRating } from "./types.js";
import { consensusActions, consensusRating } from "./types.js";
import { analyseAsRedTeam } from "./red-team.js";
import { analyseAsBlueTeam } from "./blue-team.js";
import { analyseAsCompliance } from "./compliance.js";
import { analyseAsNetEngineer } from "./net-engineer.js";
import { analyseAsPrivacy } from "./privacy.js";

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

/** Run all five persona analyses and compute consensus. */
export function analyseAllPersonas(result: NetworkScanResult): FullAnalysis {
  const analyses: PersonaAnalysis[] = [
    analyseAsRedTeam(result),
    analyseAsBlueTeam(result),
    analyseAsCompliance(result),
    analyseAsNetEngineer(result),
    analyseAsPrivacy(result),
  ];

  const ratings = analyses.map((a) => a.riskRating) as RiskRating[];
  const allActions = analyses.map((a) => a.priorityActions);

  return {
    scanId: result.meta.scanId,
    timestamp: result.meta.timestamp,
    analyses,
    consensusRating: consensusRating(ratings),
    consensusActions: consensusActions(allActions),
  };
}
