export interface CiConfig {
  repo: string;
  prNumber: number;
  token: string;
  findingsCount: number;
  agencyScore: number;
  verdict: string;
  markdownReport: string;
}

export interface CiResult {
  posted: boolean;
  url?: string;
  error?: string;
}

export function detectCiEnv(): { isCi: boolean; repo?: string; prNumber?: number; token?: string } {
  const repo = process.env.GITHUB_REPOSITORY;
  const token = process.env.GITHUB_TOKEN;
  const prEnv = process.env.GITHUB_PR_NUMBER;
  const ghRef = process.env.GITHUB_REF;

  if (!repo || !token) {
    return { isCi: false };
  }

  let prNumber: number | undefined;
  if (prEnv) {
    prNumber = parseInt(prEnv, 10);
  } else if (ghRef) {
    const match = ghRef.match(/refs\/pull\/(\d+)\/merge/);
    if (match) {
      prNumber = parseInt(match[1], 10);
    }
  }

  if (!prNumber || isNaN(prNumber)) {
    return { isCi: false };
  }

  return { isCi: true, repo, prNumber, token };
}

export async function postPrComment(config: CiConfig): Promise<CiResult> {
  try {
    const url = `https://api.github.com/repos/${config.repo}/issues/${config.prNumber}/comments`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${config.token}`,
        'Content-Type': 'application/json',
        'User-Agent': 'sentinel-cli/4.0',
      },
      body: JSON.stringify({ body: config.markdownReport }),
    });

    if (response.status === 201) {
      const data = await response.json() as { html_url?: string };
      return { posted: true, url: data.html_url };
    }

    const errorBody = await response.text().catch(() => 'Unknown error');
    return { posted: false, error: `GitHub API returned ${response.status}: ${errorBody}` };
  } catch (err) {
    return { posted: false, error: err instanceof Error ? err.message : String(err) };
  }
}
