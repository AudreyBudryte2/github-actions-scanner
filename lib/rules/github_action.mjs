import { Finding } from "./common/finding.mjs";
import { actionSteps, stepMatches } from "../utils.mjs";

class OfficialGitHubActionRule {
    static id = "OFFICIAL_GITHUB_ACTION";
    static documentation = "https://github.com/snyk/github-actions-scanner/blob/main/README.md#OFFICIAL_GITHUB_ACTION";

    static async description(finding) {
        return `The action ${finding.details.uses} in job ${finding.job} is not from the official GitHub actions source (actions/<action-name>).`;
    }

    static async scan(action) {
        const findings = [];
        const yamlContent = await action.parsedContent();

        // Regular expression to match official GitHub actions
        const OFFICIAL_GITHUB_ACTION_REGEX = /^(actions|github)\/[\w-]+/;

        for (const [jobKey, job, step, stepidx] of actionSteps(yamlContent)) {
            if (step.uses && !OFFICIAL_GITHUB_ACTION_REGEX.test(step.uses)) {
                findings.push(new Finding(
                    OfficialGitHubActionRule,
                    action,
                    jobKey,
                    step.name || stepidx,
                    { uses: step.uses }
                ));
            }
        }

        return findings;
    }
}

export { OfficialGitHubActionRule as default };