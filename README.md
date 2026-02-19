# OSSSecurityAgent

A comprehensive .NET tool for analyzing project dependencies, identifying security vulnerabilities, and generating Open Source Software (OSS) license documentation.

## Overview

OSSSecurityAgent is a powerful command-line tool that:
- **Scans .NET projects** for all NuGet package dependencies
- **Identifies security vulnerabilities** in dependencies using security advisories
- **Generates OSS license files** with complete license text for all third-party packages
- **Supports multiple license sources** (NuGet API, GitHub repositories, embedded .nuspec files, SPDX identifiers)
- **Handles complex license URLs** including HTTP redirects and GitHub blob URLs

## Features

### 📦 Dependency Analysis
- Automatically detects all NuGet package dependencies in your project
- Retrieves package metadata from the official NuGet registry
- Supports project file formats: `.csproj`, `.vbproj`, `.fsproj`

### 🔒 Security Scanning
- Identifies known security vulnerabilities in dependencies
- Cross-references packages against security advisory databases
- Provides vulnerability details and severity levels
- Suggests remediation and updates

### 📋 OSS License Generation
- Generates comprehensive third-party license documentation
- Automatically fetches license text from multiple sources in priority order:
  1. GitHub repositories (via repository metadata)
  2. NuGet API registration data
  3. Package .nuspec files
  4. SPDX identifier mappings
- Handles complex license URLs including HTTP redirects and GitHub blob URLs
- Supports both markdown and plain text license formats
- Gracefully handles packages without available license information

### 🚀 Automated Security Fix PR Management
- Scans for open pull requests with "Security fix:" prefix
- Automatically merges approved security updates when conditions are met:
  - All specified reviewers have approved the PR
  - Status checks pass
  - No merge conflicts
  - PR is not in draft state
- Provides detailed diagnostics for PRs that cannot be merged
- Integrates with GitHub branch protection rules

### 🌐 GitHub Integration
- Automatically detects GitHub repository URLs from package metadata
- Downloads license files directly from GitHub repositories
- Converts GitHub web URLs to raw file URLs for clean text extraction
- Handles GitHub blob URLs with `?raw=true` parameter
- Supports private repositories with GitHub authentication tokens
- Manages pull request workflows with automated merging capabilities

## Prerequisites

- **.NET 10.0** or higher
- **C# 13** compatible compiler
- Access to NuGet registry (usually public)
- (Optional) GitHub API token for enhanced rate limiting and private repository access

## Installation

### Clone the Repository
```bash
git clone https://github.com/yourusername/OSSSecurityAgent.git
cd OssSecurityAgent
```

### Build the Project
```bash
dotnet build
```

### Run the Tool
```bash
dotnet run -- --repo <path-to-your-project> [options]
```

## Usage

### Basic Scan and License Generation
```bash
dotnet run -- --repo "/path/to/your/project" --generate-osl
```

### Skip Security Analysis
```bash
dotnet run -- --repo "/path/to/your/project" --skip-scan-detect-analyse --generate-osl
```

### Merge Approved Security Fix PRs
```bash
dotnet run -- --repo "/path/to/your/project" --merge-security-prs --github-token $GITHUB_TOKEN --approved-reviewers "reviewer1,reviewer2"
```

### Complete Workflow (Scan, Fix, and Merge)
```bash
dotnet run -- --repo "/path/to/your/project" --generate-osl --merge-security-prs --github-token $GITHUB_TOKEN
```

### Output Formats
- License files are generated in the `licenses/` directory of the scanned project
- Default filename format: `open-source-license-{timestamp}.txt`
- Merge results are displayed in the console with detailed diagnostics

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--repo <path>` | **Required.** Path to the .NET project root directory containing `.csproj` file |
| `--generate-osl` | Generate Open Source License documentation file |
| `--skip-scan-detect-analyse` | Skip security scanning and vulnerability detection (faster for license-only generation) |
| `--merge-security-prs` | Automatically merge approved security fix pull requests |
| `--github-token <token>` | GitHub personal access token for API authentication and PR operations |
| `--approved-reviewers <list>` | Comma-separated list of GitHub usernames that must approve PRs before merging |

## Project Structure

```
OssSecurityAgent/
├── OpenSourceLicenseAIGenerator.cs   # Main license generation logic
├── SecurityAgentTools.cs              # Utility methods and helpers
├── PullRequestMergeService.cs         # Automated PR merge service
├── VulnerabilityRemediationService.cs # Security fix remediation
├── DependencyGraph.cs                 # Dependency analysis
├── GitOperations.cs                   # Git operations wrapper
├── BuildValidator.cs                  # Build validation utility
├── ChatClientFactory.cs               # AI client factory
├── Config.cs                          # Configuration management
├── OssSecurityAgent.csproj            # Project file
├── Program.cs                         # Entry point
├── README.md                          # This file
└── Models/                            # Data models
    ├── Vulnerability.cs
    ├── BuildResult.cs
    ├── AiResolutionResponse.cs
    └── BreakingChangeReport.cs
```

## Key Components

### OpenSourceLicenseAIGenerator.cs
Core functionality for:
- Fetching package metadata from NuGet API
- Extracting license information from multiple sources
- Downloading license files from GitHub repositories
- Formatting and combining license data
- Generating the final OSS license document

### PullRequestMergeService.cs
Handles automated security fix PR management:
- Scans open pull requests for "Security fix:" prefix
- Validates PR readiness and merge conditions
- Checks for reviewer approvals and status checks
- Executes merge operations with conflict detection
- Provides diagnostic information for merge failures

### VulnerabilityRemediationService.cs
Manages security vulnerability fixes:
- Identifies applicable package updates
- Generates remediation strategies using AI
- Creates GitHub issues for tracking
- Detects breaking changes in updates
- Manages branch creation and PR generation

### SecurityAgentTools.cs
Utility functions for:
- File system operations
- Project dependency discovery
- Vulnerability detection and reporting
- HTTP requests and API interactions
- Build validation

## License Fetching Strategy

The tool uses a four-step approach to find license information:

### STEP 1: GitHub Repository URLs
Attempts to fetch LICENSE files directly from GitHub repositories identified in package metadata (projectUrl, repository element, or repositoryUrl from NuGet API).

### STEP 2: NuGet API License URLs
Checks the NuGet registration data for licenseUrl. If the URL redirects to GitHub, it automatically extracts the raw file URL.

### STEP 3: .nuspec File License URLs
Parses the package's .nuspec XML file for the `<licenseUrl>` tag. Follows HTTP redirects and handles GitHub blob URLs.

### STEP 4: .nuspec License Element
Extracts the `<license>` element from .nuspec files, supporting:
- Inline license text
- URLs (processed like STEP 3)
- SPDX license identifiers

## Configuration

### GitHub Authentication (Optional)
For enhanced rate limiting and private repository access, set the `GITHUB_TOKEN` environment variable:

```bash
export GITHUB_TOKEN=your_github_personal_access_token
```

Or in `.env` file:
```
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
```

## Output Example

The generated OSL file contains:

```
THIRD-PARTY SOFTWARE NOTICES AND INFORMATION

Do Not Translate or Localize

This project incorporates components from the projects listed below...

PackageName 1.0.0
[Full License Text]

PackageName 2.0.0
[Full License Text]

...
```

## Automated Security Fix PR Management

The tool can automatically merge pull requests that contain security fixes for vulnerable dependencies:

### PR Requirements for Auto-Merge
- PR title must start with "Security fix:"
- All specified approved reviewers must have approved the PR
- All status checks must pass (GitHub Actions, CI/CD, etc.)
- PR must not be in draft state
- No merge conflicts present
- Base branch must be mergeable

### Configuration
```bash
# With environment variables
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
dotnet run -- --repo "/path/to/project" --merge-security-prs --approved-reviewers "alice,bob"

# With command-line arguments
dotnet run -- --repo "/path/to/project" --merge-security-prs \
  --github-token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --approved-reviewers "alice,bob"
```

### Merge Diagnostics
When a PR cannot be merged, the tool provides detailed diagnostic information:
- Current PR state (open, closed, draft)
- Mergeable status and conflicts
- List of pending approvals
- Status check results (passed/failed)
- Suggested remediation steps

## Error Handling

- **Missing packages**: Gracefully skips packages that cannot be resolved
- **Unavailable licenses**: Marks packages with "LICENSE TEXT NOT FOUND"
- **Network errors**: Retries with exponential backoff
- **Invalid responses**: Validates and filters HTML content from license files
- **PR merge failures**: Provides detailed diagnostics and continues processing

## Performance

- Uses parallel processing with a semaphore to limit concurrent requests
- Configurable timeout (default: 30 seconds per package)
- Efficient caching of HTTP responses
- Memory-optimized streaming for large files

## Security Considerations

### Data Privacy
- No personal or sensitive project data is transmitted
- Only package names and versions are used for lookups
- All communications use HTTPS

### Dependency Security
- Uses only official NuGet and GitHub APIs
- Validates SSL certificates
- Implements timeout protections

### Best Practices
- Run on a clean/private machine for sensitive projects
- Keep GitHub token secure and use repository-scoped tokens
- Review generated license files before publication
- Update dependencies regularly

## Troubleshooting

### Issue: "Build succeeded. 0 Error(s)" but licenses not generated
- Ensure the `--generate-osl` flag is provided
- Check that the project path is correct and contains a `.csproj` file

### Issue: Some packages show "LICENSE TEXT NOT FOUND"
- Some packages may not have published licenses
- Check the package on NuGet.org manually for license information
- Consider checking the package's GitHub repository directly

### Issue: GitHub API rate limiting
- Set a `GITHUB_TOKEN` environment variable for authenticated requests
- Authenticated requests have higher rate limits (5,000 vs 60 requests/hour)

### Issue: Timeout errors
- Check your internet connection
- Try running again (implements retry logic)
- Some GitHub URLs may be temporarily unavailable

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Future Enhancements

- [ ] Support for Python, JavaScript, Java dependency ecosystems
- [ ] Advanced vulnerability analytics and trend reporting
- [ ] Export to multiple formats (JSON, XML, SBOM, CycloneDX)
- [ ] License compliance checking and policy enforcement
- [ ] Interactive UI/Dashboard
- [ ] CI/CD pipeline integration templates (GitHub Actions, Azure Pipelines)
- [ ] SPDX document generation
- [ ] Custom remediation workflows
- [ ] Dependency graph visualization

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, questions, or suggestions:
- Create an issue on the GitHub repository
- Check existing issues for solutions
- Review the troubleshooting section above

## Changelog

### Version 2.0.0 (Current)
- Added automated security fix PR merging
- Vulnerability remediation with AI-driven fix suggestions
- Breaking change detection in package updates
- Enhanced GitHub integration for PR management
- Improved build validation and dependency graph analysis
- Zero-warning production build

### Version 1.0.0
- Initial release
- Basic dependency scanning
- OSS license file generation
- GitHub repository integration
- HTTP redirect handling for license URLs

## Acknowledgments

- Built with .NET 10.0
- Uses official NuGet and GitHub APIs
- Community feedback and contributions

---

**Last Updated**: February 18, 2026

For the latest information and updates, visit the [project repository](https://github.com/yourusername/OSSSecurityAgent).
