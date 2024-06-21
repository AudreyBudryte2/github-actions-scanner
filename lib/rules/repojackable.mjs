import { Finding } from "./common/finding.mjs";
import { actionSteps } from "../utils.mjs";
import { get } from "https";

function get_statuscode(url) {
  return new Promise((resolve) =>
    get(url, res => resolve(res.statusCode))
  );
}

class Repojackable {
  static id = "REPOJACKABLE";
  static documentation = "https://github.com/snyk/github-actions-scanner#REPOJACKABLE";

  static async description(finding) {
    return `The identified used action may be repojackable due to ${finding.details.reason}. Action details: ${finding.details.repoInfo.owner}/${finding.details.repoInfo.repo}@${finding.details.repoInfo.version}`;
  }

  static async scan(action) {
    const findings = [];
    const yamlContent = await action.parsedContent();
    for (const [jobKey, job, step, stepidx] of actionSteps(yamlContent)) {
      if (step?.uses !== undefined) {
        const repoInfo = this.extractRepoInfo(step.uses);
        if (repoInfo) {
          const { owner: org, repo } = repoInfo;
          const repostatus = await get_statuscode(`https://github.com/${org}/${repo}`);
          if (repostatus >= 300 && repostatus < 400) {
            const reason = `repository redirect: ${org}/${repo}`;
            const description = await this.description({ details: { reason, repoInfo } });
            findings.push(new Finding(
              Repojackable,
              action,
              jobKey,
              step.name || stepidx,
              { uses: step.uses, repoInfo, reason, description }
            ));
          } else {
            const orgstatus = await get_statuscode(`https://github.com/${org}`);
            if (orgstatus === 404) {
              const reason = `organization not found: ${org}`;
              const description = await this.description({ details: { reason, repoInfo } });
              findings.push(new Finding(
                Repojackable,
                action,
                jobKey,
                step.name || stepidx,
                { uses: step.uses, repoInfo, reason, description }
              ));
            }
          }
        }
      }
    }

    return findings;
  }

  static extractRepoInfo(uses) {
    // Assuming the 'uses' field is in the format 'owner/repo@version'
    const match = uses.match(/^([^\/]+)\/([^@]+)@(.+)$/);
    if (match) {
      return {
        owner: match[1],
        repo: match[2],
        version: match[3]
      };
    }
    return null;
  }
}

export { Repojackable as default };
