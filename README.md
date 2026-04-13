# OSSSecurityAgent

OSSSecurityAgent is a .NET-based security automation stack for analyzing dependencies, identifying vulnerable packages, generating remediation pull requests, and producing OSS license documentation.

It contains three working parts:

- **OssSecurityAgent**: core .NET CLI engine
- **OSSSecurityAgentAPI**: ASP.NET Core backend for the web workflow
- **OSSSecurityAgentWeb**: React frontend for analysis and remediation actions

## What it does

- Scans .NET projects for NuGet dependencies
- Detects known vulnerabilities and groups them by package
- Uses AI-assisted summaries and deterministic fixed-version selection
- Generates remediation branches, issues, and pull requests
- Approves and merges security fixes after reviewer approval
- Deletes merged PR branches after successful merge
- Generates OSS license notices for third-party packages

## Repository layout

```text
OssSecurityAgent/
├── BuildValidator.cs
├── ChatClientFactory.cs
├── Config.cs
├── DependencyGraph.cs
├── GitOperations.cs
├── OpenSourceLicenseAIGenerator.cs
├── Program.cs
├── PullRequestMergeService.cs
├── SecurityAgentTools.cs
├── Utility.cs
├── VulnerabilityRemediationService.cs
├── Models/
└── README.md

OSSSecurityAgentAPI/
├── Controllers/
├── Program.cs
└── appsettings*.json

OSSSecurityAgentWeb/
├── src/
├── public/
└── package.json
```

## Features

### CLI engine

- Dependency discovery from project assets and project files
- Vulnerability lookup and analysis
- AI-generated remediation summaries
- License notice generation
- Git-based remediation branch creation
- PR and issue creation for security fixes
- Merge validation for approved security PRs

### API backend

- REST endpoints for analysis and remediation
- GitHub integration for issues, PRs, approvals, merges, and branch cleanup
- CORS support for the web frontend
- Orchestration of the CLI engine from the web app

### Web frontend

- Repository URL input
- Dependency/vulnerability view by package
- Remediation trigger per package
- Issues and PR tracking
- Approve and merge workflow

## Prerequisites

- .NET 10 SDK
- Node.js 16+ and npm
- Git
- GitHub Personal Access Token with access to the target repository

Recommended GitHub token permissions:

- `repo` for classic PATs
- For fine-grained PATs: read/write access to contents, pull requests, and issues

## Quick start

### 1. Configure environment

Create or update [OssSecurityAgent/.env](OssSecurityAgent/.env) with your local values.

```env
MODEL_NAME=gpt-4.1-nano
MODEL_VERSION=latest
MODEL_TEMPERATURE=0.1
MODEL_MAX_TOKENS=300

COPILOT_API_URL=https://api.openai.com/v1/chat/completions
COPILOT_API_KEY=your_openai_api_key_here

GITHUB_TOKEN=your_github_pat_here
GITHUB_REPOSITORY_URL=https://github.com/owner/repo.git
GITHUB_REVIEWERS=username1,username2
```

### 2. Run the API

```bash
cd OSSSecurityAgentAPI
dotnet run
```

### 3. Run the web app

```bash
cd OSSSecurityAgentWeb
npm install
npm start
```

### 4. Run the CLI directly

```bash
cd OssSecurityAgent
dotnet run -- --repo "/path/to/project" --generate-osl
```

## Common workflows

### Analyze a repository

```bash
dotnet run -- --repo "/path/to/project" --skip-scan-detect-analyse --generate-osl
```

### Remediate vulnerabilities

```bash
dotnet run -- --repo "/path/to/project" --remediate
```

### Merge approved security fixes

```bash
dotnet run -- --repo "/path/to/project" --merge-approved-security-fixes
```

### Generate OSS license documentation

```bash
dotnet run -- --repo "/path/to/project" --generate-osl
```

## CLI options

| Option | Description |
|---|---|
| `--repo <path>` | Path to the target .NET project root |
| `--generate-osl` | Generate OSS license documentation |
| `--skip-scan-detect-analyse` | Skip vulnerability analysis for faster license-only runs |
| `--remediate` | Create remediation branches and PRs for vulnerable packages |
| `--merge-approved-security-fixes` | Merge approved security PRs |
| `--refresh-metadata` | Refresh dependency graph metadata |
| `--github-token <token>` | GitHub token for API access |
| `--approved-reviewers <list>` | Required approvers for merge workflows |
| `--package <name>` | Target a single package for remediation |
| `--target-version <version>` | Override the fixed version used for remediation |

## API endpoints

### Analyze

`GET /api/remediation/analyze?repo=<url>`

Returns vulnerabilities grouped by package.

### Remediate package

`POST /api/remediation/remediate`

```json
{
  "repoUrl": "https://github.com/owner/repo.git",
  "packageName": "package-name",
  "recommendedVersion": "1.2.3"
}
```

### List issues and PRs

`GET /api/remediation/issues-and-prs?repo=<url>`

### Approve PR

`POST /api/remediation/approve-pr`

```json
{
  "repoUrl": "https://github.com/owner/repo.git",
  "prNumber": 123
}
```

### Merge PR

`POST /api/remediation/merge-pr`

The merge flow:

- validates approval state
- merges the PR
- closes the linked issue when present
- deletes the source branch for same-repo PRs after a successful merge

## Security model

- Tokens are loaded from environment or local `.env` files
- `.env` is ignored by git
- No token values should be committed
- Use repository-scoped or fine-grained PATs when possible
- Rotate any token that has been exposed in logs or files

## Important files

- [OssSecurityAgent/Program.cs](OssSecurityAgent/Program.cs) - CLI entry point
- [OssSecurityAgent/SecurityAgentTools.cs](OssSecurityAgent/SecurityAgentTools.cs) - dependency and AI analysis
- [OssSecurityAgent/VulnerabilityRemediationService.cs](OssSecurityAgent/VulnerabilityRemediationService.cs) - remediation workflow
- [OssSecurityAgent/PullRequestMergeService.cs](OssSecurityAgent/PullRequestMergeService.cs) - merge logic
- [OSSSecurityAgentAPI/Controllers/RemediationController.cs](OSSSecurityAgentAPI/Controllers/RemediationController.cs) - web API orchestration
- [OSSSecurityAgentWeb/src/App.js](OSSSecurityAgentWeb/src/App.js) - frontend entry point

## Output locations

- Generated license notices are written to the target project’s `licenses/` folder
- Dependency graph metadata is cached as `dependency-graph.json`
- Remediation branches are created in git and pushed to GitHub

## Troubleshooting

### Token errors

- Verify `GITHUB_TOKEN` is set
- Check repository access on the token
- Use a fine-grained PAT for a single repo or an org-scoped GitHub App for multiple repos

### API connection issues

- Confirm the API is running
- Verify frontend CORS origin matches the API URL

### Remediation issues

- Ensure the project builds locally
- Confirm the package has a fixed version available
- Review the merge diagnostics if a PR does not merge

### License generation issues

- Confirm the target repo contains a supported project file
- Check network access to NuGet and GitHub

## Development notes

- The stack is designed to be run locally against a target repository
- Web actions call the API, which then invokes the CLI engine
- GitHub actions are performed only when the configured token has the required access

## Contribution guidance

1. Create a feature branch
2. Make focused changes
3. Build and test locally
4. Open a pull request

## License

MIT
