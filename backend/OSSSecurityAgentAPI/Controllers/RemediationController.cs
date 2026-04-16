using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text.Json;

[ApiController]
[Route("api/[controller]")]
public class RemediationController : ControllerBase
{
    private readonly ILogger<RemediationController> _logger;
    private readonly string _agentPath;
    private readonly IConfiguration _config;

    public RemediationController(ILogger<RemediationController> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;
        // Find the OssSecurityAgent project directory relative to this API project
        var currentDir = Directory.GetCurrentDirectory();
        var agentDir = Path.Combine(currentDir, "..", "OssSecurityAgent");
        if (!Directory.Exists(agentDir))
        {
            // If relative path doesn't work, try from workspace root
            agentDir = Path.Combine(currentDir, "..", "..", "OssSecurityAgent");
        }
        _agentPath = Path.GetFullPath(agentDir);
        _logger.LogInformation($"Agent path set to: {_agentPath}");
    }

    [HttpGet("analyze")]
    public async Task<IActionResult> Analyze([FromQuery] string repo)
    {
        try
        {
            if (string.IsNullOrEmpty(repo))
                return BadRequest(new { message = "Repository URL is required" });

            _logger.LogInformation($"Analyzing repository: {repo}");

            // Clone or get local path for the repository
            var localRepoPath = await GetOrCloneRepository(repo);
            if (string.IsNullOrEmpty(localRepoPath))
                return BadRequest(new { message = "Failed to access repository" });

            // Run scan and analyze on local path
            var result = await RunAgentCommand($"--repo \"{localRepoPath}\" --scan --analyze");

            if (!result.Success)
                return BadRequest(new { message = result.Error });

            // Parse the vulnerability output and count by package
            var vulnerabilitiesByPackage = ParseVulnerabilitiesFromOutput(result.Output);

            return Ok(new
            {
                success = true,
                vulnerabilitiesByPackage
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing repository");
            return StatusCode(500, new { message = ex.Message });
        }
    }

    [HttpPost("remediate")]
    public async Task<IActionResult> Remediate([FromBody] RemediateRequest request)
    {
        try
        {
            if (string.IsNullOrEmpty(request.RepoUrl) || string.IsNullOrEmpty(request.PackageName))
                return BadRequest(new { message = "Repository URL and package name are required" });

            _logger.LogInformation($"Remediating package {request.PackageName} in {request.RepoUrl}");

            var localRepoPath = await GetOrCloneRepository(request.RepoUrl);
            if (string.IsNullOrEmpty(localRepoPath))
                return BadRequest(new { message = "Failed to access repository" });

            // Run remediation for specific package using --package flag
            var args = $"--repo \"{localRepoPath}\" --remediate --package \"{request.PackageName}\"";
            if (!string.IsNullOrWhiteSpace(request.RecommendedVersion))
            {
                args += $" --target-version \"{request.RecommendedVersion}\"";
                _logger.LogInformation($"Using AI-recommended target version {request.RecommendedVersion} for package {request.PackageName}");
            }

            var result = await RunAgentCommand(args);

            if (!result.Success)
                return BadRequest(new { message = result.Error });

            // Clean up cloned repository after remediation completes
            await DeleteClonedRepository(localRepoPath);

            return Ok(new
            {
                success = true,
                message = $"Remediation started for {request.PackageName}",
                output = result.Output
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error remediating package");
            return StatusCode(500, new { message = ex.Message });
        }
    }

    [HttpGet("issues-and-prs")]
    public async Task<IActionResult> GetIssuesAndPRs([FromQuery] string repo)
    {
        try
        {
            if (string.IsNullOrEmpty(repo))
                return BadRequest(new { message = "Repository URL is required" });

            _logger.LogInformation($"Fetching issues and PRs for: {repo}");

            // Parse repository URL to get owner and repo
            var (owner, repoName) = ParseGitHubUrl(repo);

            // Get GitHub token from environment
            var githubToken = _config["GITHUB_TOKEN"] ?? Environment.GetEnvironmentVariable("GITHUB_TOKEN");
            if (string.IsNullOrEmpty(githubToken))
                return BadRequest(new { message = "GitHub token not configured" });

            var items = await FetchIssuesAndPRsFromGitHub(owner, repoName, githubToken);

            return Ok(new
            {
                success = true,
                items
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching issues and PRs");
            return StatusCode(500, new { message = ex.Message });
        }
    }

    [HttpPost("approve-pr")]
    public async Task<IActionResult> ApprovePR([FromBody] ApprovePRRequest request)
    {
        try
        {
            if (string.IsNullOrEmpty(request.RepoUrl) || request.PrNumber <= 0)
                return BadRequest(new { message = "Repository URL and PR number are required" });

            _logger.LogInformation($"Approving PR #{request.PrNumber} in {request.RepoUrl}");

            var githubToken = _config["GITHUB_TOKEN"] ?? Environment.GetEnvironmentVariable("GITHUB_TOKEN");
            if (string.IsNullOrEmpty(githubToken))
                return BadRequest(new { stage = "config", message = "GitHub token not configured" });

            var (owner, repo) = ParseGitHubUrl(request.RepoUrl);
            using var httpClient = new System.Net.Http.HttpClient();
            httpClient.DefaultRequestHeaders.Add("User-Agent", "OSSSecurityAgentAPI");
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", githubToken);
            httpClient.DefaultRequestHeaders.Add("Accept", "application/vnd.github+json");

            // 1) Fetch PR details
            var prResponse = await httpClient.GetAsync($"https://api.github.com/repos/{owner}/{repo}/pulls/{request.PrNumber}");
            var prContent = await prResponse.Content.ReadAsStringAsync();
            if (!prResponse.IsSuccessStatusCode)
                return BadRequest(new { stage = "fetch-pr", message = $"Failed to fetch PR #{request.PrNumber}: {prContent}" });

            using var prDoc = JsonDocument.Parse(prContent);
            var prRoot = prDoc.RootElement;
            var prHtmlUrl = prRoot.TryGetProperty("html_url", out var urlElem) ? urlElem.GetString() : null;
            var isApproved = HasLabel(prRoot, "approved");

            if (prRoot.TryGetProperty("merged_at", out var mergedAtElem) && mergedAtElem.ValueKind != JsonValueKind.Null)
            {
                await CleanupClonedRepositoryForRemoteAsync(request.RepoUrl);
                return Ok(new { success = true, stage = "noop", message = $"PR #{request.PrNumber} is already merged.", prUrl = prHtmlUrl });
            }

            if (isApproved)
            {
                return Ok(new
                {
                    success = true,
                    stage = "noop",
                    message = $"PR #{request.PrNumber} is already approved.",
                    prUrl = prHtmlUrl,
                    label = "approved"
                });
            }

            // 2) Add approved label
            var labelPayload = System.Text.Json.JsonSerializer.Serialize(new[] { "approved" });
            using var labelContent = new System.Net.Http.StringContent(labelPayload, System.Text.Encoding.UTF8, "application/json");
            var labelResponse = await httpClient.PostAsync($"https://api.github.com/repos/{owner}/{repo}/issues/{request.PrNumber}/labels", labelContent);
            var labelBody = await labelResponse.Content.ReadAsStringAsync();
            if (!labelResponse.IsSuccessStatusCode)
                return BadRequest(new { stage = "label", message = $"Failed to add approved label to PR #{request.PrNumber}: {labelBody}" });

            return Ok(new
            {
                success = true,
                stage = "approved",
                message = $"PR #{request.PrNumber} approved successfully.",
                prNumber = request.PrNumber,
                prUrl = prHtmlUrl,
                label = "approved"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error approving PR");
            return StatusCode(500, new { stage = "exception", message = ex.Message });
        }
    }

    [HttpPost("merge-pr")]
    public async Task<IActionResult> MergePR([FromBody] ApprovePRRequest request)
    {
        try
        {
            if (string.IsNullOrEmpty(request.RepoUrl) || request.PrNumber <= 0)
                return BadRequest(new { message = "Repository URL and PR number are required" });

            _logger.LogInformation($"Merging PR #{request.PrNumber} in {request.RepoUrl}");

            var githubToken = _config["GITHUB_TOKEN"] ?? Environment.GetEnvironmentVariable("GITHUB_TOKEN");
            if (string.IsNullOrEmpty(githubToken))
                return BadRequest(new { stage = "config", message = "GitHub token not configured" });

            var (owner, repo) = ParseGitHubUrl(request.RepoUrl);
            using var httpClient = new System.Net.Http.HttpClient();
            httpClient.DefaultRequestHeaders.Add("User-Agent", "OSSSecurityAgentAPI");
            httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", githubToken);
            httpClient.DefaultRequestHeaders.Add("Accept", "application/vnd.github+json");

            var prResponse = await httpClient.GetAsync($"https://api.github.com/repos/{owner}/{repo}/pulls/{request.PrNumber}");
            var prContent = await prResponse.Content.ReadAsStringAsync();
            if (!prResponse.IsSuccessStatusCode)
                return BadRequest(new { stage = "fetch-pr", message = $"Failed to fetch PR #{request.PrNumber}: {prContent}" });

            using var prDoc = JsonDocument.Parse(prContent);
            var prRoot = prDoc.RootElement;
            var prBody = prRoot.TryGetProperty("body", out var bodyElem) ? bodyElem.GetString() : string.Empty;
            var prHtmlUrl = prRoot.TryGetProperty("html_url", out var urlElem) ? urlElem.GetString() : null;
            var branchRef = GetPrHeadBranch(prRoot);
            var sameRepoBranch = IsPrHeadFromSameRepo(prRoot, owner, repo);

            if (prRoot.TryGetProperty("merged_at", out var mergedAtElem) && mergedAtElem.ValueKind != JsonValueKind.Null)
            {
                return Ok(new { success = true, stage = "noop", message = $"PR #{request.PrNumber} is already merged.", prUrl = prHtmlUrl });
            }

            if (!HasLabel(prRoot, "approved"))
            {
                return BadRequest(new { stage = "approval-required", message = $"PR #{request.PrNumber} must be approved before merging." });
            }

            // Merge the PR
            var mergePayload = System.Text.Json.JsonSerializer.Serialize(new { merge_method = "squash" });
            using var mergeContent = new System.Net.Http.StringContent(mergePayload, System.Text.Encoding.UTF8, "application/json");
            var mergeResponse = await httpClient.PutAsync($"https://api.github.com/repos/{owner}/{repo}/pulls/{request.PrNumber}/merge", mergeContent);
            var mergeBody = await mergeResponse.Content.ReadAsStringAsync();

            if (!mergeResponse.IsSuccessStatusCode)
            {
                var normalizedMergeBody = mergeBody ?? string.Empty;
                var isOutOfDate = mergeResponse.StatusCode == System.Net.HttpStatusCode.Conflict ||
                                  normalizedMergeBody.Contains("out of date", StringComparison.OrdinalIgnoreCase) ||
                                  normalizedMergeBody.Contains("Head branch is out of date", StringComparison.OrdinalIgnoreCase);

                return BadRequest(new
                {
                    stage = isOutOfDate ? "out-of-date" : "merge",
                    message = isOutOfDate
                        ? $"PR #{request.PrNumber} is out of date. Please update the branch and try again."
                        : $"Failed to merge PR #{request.PrNumber}: {mergeBody}"
                });
            }

            // Close linked issue (if any)
            var issueNumber = ExtractIssueNumberFromPrBody(prBody);
            string? issueUrl = null;
            if (!string.IsNullOrEmpty(issueNumber))
            {
                var issuePatch = System.Text.Json.JsonSerializer.Serialize(new { state = "closed" });
                using var issueContent = new System.Net.Http.StringContent(issuePatch, System.Text.Encoding.UTF8, "application/json");
                var issueResponse = await httpClient.PatchAsync($"https://api.github.com/repos/{owner}/{repo}/issues/{issueNumber}", issueContent);
                var issueBody = await issueResponse.Content.ReadAsStringAsync();

                if (!issueResponse.IsSuccessStatusCode)
                {
                    return BadRequest(new
                    {
                        stage = "close-issue",
                        message = $"PR #{request.PrNumber} merged, but failed to close issue #{issueNumber}: {issueBody}"
                    });
                }

                issueUrl = $"https://github.com/{owner}/{repo}/issues/{issueNumber}";
            }

            // PR is closed automatically after merge; return success with explicit details
            var branchDeleted = false;
            string? branchCleanupNote = null;

            if (sameRepoBranch && !string.IsNullOrWhiteSpace(branchRef))
            {
                var encodedRef = Uri.EscapeDataString($"heads/{branchRef}");
                var deleteBranchResponse = await httpClient.DeleteAsync($"https://api.github.com/repos/{owner}/{repo}/git/refs/{encodedRef}");
                if (deleteBranchResponse.IsSuccessStatusCode)
                {
                    branchDeleted = true;
                }
                else
                {
                    var deleteBody = await deleteBranchResponse.Content.ReadAsStringAsync();
                    branchCleanupNote = $"Branch cleanup skipped: {deleteBody}";
                }
            }
            else
            {
                branchCleanupNote = "Branch cleanup skipped: PR source branch is unavailable or from a fork.";
            }

            await CleanupClonedRepositoryForRemoteAsync(request.RepoUrl);

            return Ok(new
            {
                success = true,
                stage = "merged",
                message = branchDeleted
                    ? $"PR #{request.PrNumber} merged, linked issue closed, PR branch deleted, and local cloned code cleaned up."
                    : $"PR #{request.PrNumber} merged, linked issue closed, and local cloned code cleaned up.",
                prNumber = request.PrNumber,
                prUrl = prHtmlUrl,
                issueNumber,
                issueUrl,
                label = "approved",
                branchDeleted,
                branch = branchRef,
                branchCleanupNote
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error merging PR");
            return StatusCode(500, new { stage = "exception", message = ex.Message });
        }
    }

    private async Task<(bool Success, string Output, string? Error)> RunAgentCommand(string args)
    {
        try
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "dotnet",
                    Arguments = $"run --project \"{_agentPath}/OssSecurityAgent.csproj\" -- {args}",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = _agentPath
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            var error = await process.StandardError.ReadToEndAsync();
            process.WaitForExit(60000); // 60 second timeout

            return (process.ExitCode == 0, output, string.IsNullOrEmpty(error) ? null : error);
        }
        catch (Exception ex)
        {
            return (false, "", ex.Message);
        }
    }

    private static string? ExtractIssueNumberFromPrBody(string? prBody)
    {
        if (string.IsNullOrEmpty(prBody))
            return null;

        var match = System.Text.RegularExpressions.Regex.Match(prBody, @"[Cc]loses\s+#(\d+)");
        return match.Success ? match.Groups[1].Value : null;
    }

    private static bool HasLabel(JsonElement prRoot, string labelName)
    {
        if (!prRoot.TryGetProperty("labels", out var labelsElement) || labelsElement.ValueKind != JsonValueKind.Array)
            return false;

        return labelsElement.EnumerateArray().Any(label =>
            label.TryGetProperty("name", out var nameElement) &&
            string.Equals(nameElement.GetString(), labelName, StringComparison.OrdinalIgnoreCase));
    }

    private static string? GetPrHeadBranch(JsonElement prRoot)
    {
        if (!prRoot.TryGetProperty("head", out var headElement) || headElement.ValueKind != JsonValueKind.Object)
            return null;

        return headElement.TryGetProperty("ref", out var refElement) ? refElement.GetString() : null;
    }

    private static bool IsPrHeadFromSameRepo(JsonElement prRoot, string owner, string repo)
    {
        if (!prRoot.TryGetProperty("head", out var headElement) || headElement.ValueKind != JsonValueKind.Object)
            return false;

        if (!headElement.TryGetProperty("repo", out var headRepoElement) || headRepoElement.ValueKind != JsonValueKind.Object)
            return false;

        if (!headRepoElement.TryGetProperty("full_name", out var fullNameElement))
            return false;

        var fullName = fullNameElement.GetString();
        return !string.IsNullOrWhiteSpace(fullName) &&
               string.Equals(fullName, $"{owner}/{repo}", StringComparison.OrdinalIgnoreCase);
    }

    private async Task CleanupClonedRepositoryForRemoteAsync(string repoUrl)
    {
        try
        {
            var (_, repoName) = ParseGitHubUrl(repoUrl);
            var tempDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "oss-agent-repos");
            var localPath = System.IO.Path.Combine(tempDir, repoName);
            await DeleteClonedRepository(localPath);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, $"Failed to clean local cloned repo for {repoUrl}. Non-critical.");
        }
    }

    private async Task TryRemoveLabelAsync(System.Net.Http.HttpClient client, string owner, string repo, int prNumber, string label)
    {
        try
        {
            var deleteResponse = await client.DeleteAsync($"https://api.github.com/repos/{owner}/{repo}/issues/{prNumber}/labels/{label}");
            if (!deleteResponse.IsSuccessStatusCode)
            {
                var body = await deleteResponse.Content.ReadAsStringAsync();
                _logger.LogWarning($"Failed to remove label '{label}' from PR #{prNumber}: {body}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, $"Failed to remove label '{label}' from PR #{prNumber}");
        }
    }

    /// <summary>
    /// Gets the local path for a repository. If it's a GitHub URL, clones it to temp directory.
    /// If it's already a local path, validates and returns it.
    /// </summary>
    private async Task<string?> GetOrCloneRepository(string repoInput)
    {
        try
        {
            _logger.LogInformation($"GetOrCloneRepository called with: {repoInput}");
            
            // Check if it's a GitHub URL
            if (repoInput.StartsWith("http") || repoInput.StartsWith("git@"))
            {
                // It's a GitHub URL - clone it
                var repoName = System.IO.Path.GetFileNameWithoutExtension(repoInput.Split('/').Last());
                var tempDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "oss-agent-repos");
                Directory.CreateDirectory(tempDir);
                
                var localPath = System.IO.Path.Combine(tempDir, repoName);
                _logger.LogInformation($"Repository is a GitHub URL. Will clone to: {localPath}");
                
                // If already cloned, use it; otherwise clone
                if (!Directory.Exists(localPath))
                {
                    _logger.LogInformation($"Cloning repository from {repoInput} to {localPath}");
                    
                    var cloneProcess = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "git",
                            Arguments = $"clone \"{repoInput}\" \"{localPath}\"",
                            UseShellExecute = false,
                            RedirectStandardOutput = true,
                            RedirectStandardError = true,
                            CreateNoWindow = true
                        }
                    };
                    
                    cloneProcess.Start();
                    var cloneOutput = await cloneProcess.StandardOutput.ReadToEndAsync();
                    var cloneError = await cloneProcess.StandardError.ReadToEndAsync();
                    cloneProcess.WaitForExit(120000); // 2 minute timeout for clone
                    
                    if (cloneProcess.ExitCode != 0)
                    {
                        _logger.LogError($"Git clone failed with exit code {cloneProcess.ExitCode}. Error: {cloneError}");
                        return null;
                    }
                    _logger.LogInformation($"Git clone successful. Output: {cloneOutput}");
                }
                else
                {
                    _logger.LogInformation($"Repository already cloned at {localPath}, reusing it.");
                }
                
                _logger.LogInformation($"Returning local path: {localPath}");
                return localPath;
            }
            else
            {
                // It's already a local path - validate it exists
                _logger.LogInformation($"Repository is a local path: {repoInput}");
                if (Directory.Exists(repoInput))
                {
                    _logger.LogInformation($"Local path exists, returning: {repoInput}");
                    return repoInput;
                }
                
                _logger.LogWarning($"Local repository path does not exist: {repoInput}");
                return null;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting or cloning repository");
            return null;
        }
    }
    /// <summary>
    /// Safely deletes a cloned repository. Only deletes if the path is in the temp directory (cloned repos).
    /// Local paths provided by users are never deleted.
    /// </summary>
    private async Task DeleteClonedRepository(string repoPath)
    {
        try
        {
            if (string.IsNullOrEmpty(repoPath))
                return;

            // Only delete if it's in the temp directory (cloned repos)
            var tempDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "oss-agent-repos");
            if (!repoPath.StartsWith(tempDir))
            {
                _logger.LogInformation($"Repository is not a cloned repo (not in temp), skipping deletion: {repoPath}");
                return;
            }

            if (Directory.Exists(repoPath))
            {
                _logger.LogInformation($"Deleting cloned repository: {repoPath}");
                Directory.Delete(repoPath, recursive: true);
                _logger.LogInformation($"Successfully deleted cloned repository: {repoPath}");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, $"Failed to delete cloned repository at {repoPath}. This is non-critical.");
        }
    }
    private (string owner, string repo) ParseGitHubUrl(string url)
    {
        // Extract owner/repo from URLs like:
        // https://github.com/owner/repo.git
        // https://github.com/owner/repo
        // git@github.com:owner/repo.git

        var match = System.Text.RegularExpressions.Regex.Match(url, @"github\.com[:/]([^/]+)/(.+?)(\.git)?$");
        if (!match.Success)
            throw new Exception("Invalid GitHub URL format");

        return (match.Groups[1].Value, match.Groups[2].Value.Replace(".git", ""));
    }

    private async Task<List<GitHubItem>> FetchIssuesAndPRsFromGitHub(string owner, string repo, string token)
    {
        var items = new List<GitHubItem>();

        using var client = new System.Net.Http.HttpClient();
        client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");
        client.DefaultRequestHeaders.Add("User-Agent", "OSSSecurityAgent");
        client.DefaultRequestHeaders.Add("Accept", "application/vnd.github.v3+json");

        try
        {
            // Fetch PRs
            var prResponse = await client.GetAsync($"https://api.github.com/repos/{owner}/{repo}/pulls?state=all");
            if (prResponse.IsSuccessStatusCode)
            {
                var content = await prResponse.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(content);
                var root = doc.RootElement;

                foreach (var pr in root.EnumerateArray())
                {
                    var title = pr.GetProperty("title").GetString();
                    var number = pr.GetProperty("number").GetInt32();
                    var state = pr.GetProperty("state").GetString();
                    var isMerged = pr.TryGetProperty("merged_at", out var mergedAt) && mergedAt.ValueKind != JsonValueKind.Null;
                    var url = pr.GetProperty("html_url").GetString();
                    var createdAt = pr.GetProperty("created_at").GetString();

                    if (isMerged)
                        continue;

                    // Fetch per-PR details for reliable mergeability metadata
                    var prDetailResponse = await client.GetAsync($"https://api.github.com/repos/{owner}/{repo}/pulls/{number}");
                    string mergeableState = "unknown";
                    bool mergeable = false;
                    bool readyToMerge = false;
                    bool approved = false;

                    if (prDetailResponse.IsSuccessStatusCode)
                    {
                        var detailContent = await prDetailResponse.Content.ReadAsStringAsync();
                        using var detailDoc = JsonDocument.Parse(detailContent);
                        var detailRoot = detailDoc.RootElement;

                        if (detailRoot.TryGetProperty("mergeable_state", out var mergeableStateElement))
                            mergeableState = mergeableStateElement.GetString() ?? "unknown";

                        if (detailRoot.TryGetProperty("mergeable", out var mergeableElement) &&
                            mergeableElement.ValueKind is JsonValueKind.True or JsonValueKind.False)
                        {
                            mergeable = mergeableElement.GetBoolean();
                        }

                        approved = HasLabel(detailRoot, "approved");

                        readyToMerge = approved &&
                                       state == "open" &&
                                       !mergeableState.Equals("dirty", StringComparison.OrdinalIgnoreCase);
                    }

                    // Extract package name from PR title or description
                    var packageName = ExtractPackageFromTitle(title);

                    items.Add(new GitHubItem
                    {
                        Id = $"pr-{number}",
                        Type = "pr",
                        Number = number,
                        Title = title,
                        Status = state == "open" ? "open" : "closed",
                        Package = packageName,
                        Url = url,
                        CreatedAt = createdAt,
                        Branch = ExtractBranchFromTitle(title),
                        Mergeable = mergeable,
                        MergeableState = mergeableState,
                        ReadyToMerge = readyToMerge,
                        Approved = approved
                    });
                }
            }

            // Fetch Issues
            var issueResponse = await client.GetAsync($"https://api.github.com/repos/{owner}/{repo}/issues?state=all");
            if (issueResponse.IsSuccessStatusCode)
            {
                var content = await issueResponse.Content.ReadAsStringAsync();
                using var doc = JsonDocument.Parse(content);
                var root = doc.RootElement;

                foreach (var issue in root.EnumerateArray())
                {
                    // Skip pull requests (they appear in issues endpoint too)
                    if (issue.TryGetProperty("pull_request", out _))
                        continue;

                    var title = issue.GetProperty("title").GetString();
                    var number = issue.GetProperty("number").GetInt32();
                    var state = issue.GetProperty("state").GetString();
                    var url = issue.GetProperty("html_url").GetString();
                    var createdAt = issue.GetProperty("created_at").GetString();

                    // Extract package name
                    var packageName = ExtractPackageFromTitle(title);

                    // Check if labeled as security
                    var labels = issue.GetProperty("labels").EnumerateArray()
                        .Any(l => l.GetProperty("name").GetString() == "security");

                    if (labels)
                    {
                        items.Add(new GitHubItem
                        {
                            Id = $"issue-{number}",
                            Type = "issue",
                            Number = number,
                            Title = title,
                            Status = state == "open" ? "open" : "closed",
                            Package = packageName,
                            Url = url,
                            CreatedAt = createdAt
                        });
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching from GitHub API");
        }

        return items;
    }

    private string ExtractPackageFromTitle(string? title)
    {
        if (string.IsNullOrEmpty(title))
            return "Unknown";

        // Try to extract package name from titles like:
        // "[SECURITY] Update package-name to 1.2.3"
        // "Security fix: Upgrade package-name to 1.2.3"

        var match = System.Text.RegularExpressions.Regex.Match(title, @"(?:Update|Upgrade)\s+([^\s]+)\s+to");
        if (match.Success)
            return match.Groups[1].Value;

        // Fallback: extract first word after [SECURITY]
        match = System.Text.RegularExpressions.Regex.Match(title, @"\[SECURITY\]\s+Update\s+([^\s]+)");
        return match.Success ? match.Groups[1].Value : "Unknown";
    }

    private string ExtractBranchFromTitle(string? title)
    {
        if (string.IsNullOrEmpty(title))
            return "unknown";

        // Extract branch name from security fix title format
        var match = System.Text.RegularExpressions.Regex.Match(title, @"Upgrade\s+[\w\-\.]+\s+to\s+([\d\.]+)");
        return match.Success ? $"security-fix/{match.Groups[1].Value}" : "security-fix";
    }

    private Dictionary<string, object> ParseVulnerabilitiesFromOutput(string output)
    {
        var vulnerabilities = new Dictionary<string, object>();

        try
        {
            // Parse the output to count vulnerabilities per package
            // Looking for patterns like "Magick.NET-Q16-AnyCPU: 52 vulnerabilities"
            var matches = System.Text.RegularExpressions.Regex.Matches(output, @"([^\s]+):\s*(\d+)\s+vulnerabilities");

            foreach (System.Text.RegularExpressions.Match match in matches)
            {
                var packageName = match.Groups[1].Value;
                if (int.TryParse(match.Groups[2].Value, out var count))
                {
                    vulnerabilities[packageName] = new
                    {
                        count,
                        severities = new { Critical = 0, High = 0, Medium = 0, Low = 0 }
                    };
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not parse vulnerabilities from output");
        }

        return vulnerabilities;
    }
}

public class RemediateRequest
{
    public string RepoUrl { get; set; } = string.Empty;
    public string PackageName { get; set; } = string.Empty;
    public string? RecommendedVersion { get; set; }
}

public class ApprovePRRequest
{
    public string RepoUrl { get; set; } = string.Empty;
    public int PrNumber { get; set; }
}

public class GitHubItem
{
    public string Id { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty; // "pr" or "issue"
    public int Number { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty; // "open", "merged", "closed"
    public string Package { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string CreatedAt { get; set; } = string.Empty;
    public string? Branch { get; set; }
    public GitHubItem? LinkedPR { get; set; }
    public bool? Mergeable { get; set; }
    public string? MergeableState { get; set; }
    public bool ReadyToMerge { get; set; }
    public bool Approved { get; set; }
}
