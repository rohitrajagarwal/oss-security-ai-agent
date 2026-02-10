using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Octokit;
using OssSecurityAgent.Models;

public class PullRequestMergeService
{
    private readonly string _repoPath;
    private readonly string _githubToken;
    private readonly List<string> _approvedReviewers;
    private readonly GitHubClient _gitHubClient;

    public PullRequestMergeService(
        string repoPath,
        string githubToken,
        List<string> approvedReviewers)
    {
        _repoPath = repoPath ?? throw new ArgumentNullException(nameof(repoPath));
        _githubToken = githubToken ?? throw new ArgumentNullException(nameof(githubToken));
        _approvedReviewers = approvedReviewers ?? new();
        _gitHubClient = new GitHubClient(new ProductHeaderValue("OssSecurityAgent"))
        {
            Credentials = new Credentials(githubToken)
        };
    }

    public async Task<MergeResult> MergeApprovedSecurityFixesAsync()
    {
        var result = new MergeResult();

        try
        {
            var (owner, repo) = await GetRepositoryInfoAsync();
            Console.WriteLine($"🔍 Scanning {owner}/{repo} for approved security fix PRs...\n");

            // Get all open PRs
            var prRequest = new PullRequestRequest
            {
                State = ItemStateFilter.Open,
                SortDirection = SortDirection.Descending,
                SortProperty = PullRequestSort.Updated
            };
            var prs = (await _gitHubClient.PullRequest.GetAllForRepository(owner, repo, prRequest)).ToList();
            Console.WriteLine($"Found {prs.Count} open PRs to check...");
            foreach (var pr in prs)
            {
                var labels = string.Join(", ", pr.Labels.Select(l => l.Name));
                Console.WriteLine($"  PR #{pr.Number}: {pr.Title} - Labels: [{labels}]");
            }
            Console.WriteLine();

            foreach (var pr in prs)
            {
                var prResult = new PullRequestMergeResult { PRNumber = pr.Number, Title = pr.Title };

                try
                {
                    Console.WriteLine($"Checking PR #{pr.Number} for required labels...");

                    // Check if PR has both "approved" and "security-fix" labels
                    var prLabels = pr.Labels.Select(l => l.Name).ToList();
                    var hasApprovedLabel = prLabels.Contains("approved", StringComparer.OrdinalIgnoreCase);
                    var hasSecurityFixLabel = prLabels.Contains("security-fix", StringComparer.OrdinalIgnoreCase);

                    if (!hasApprovedLabel)
                    {
                        Console.WriteLine($"  ⏭️  Skipping PR #{pr.Number}: Missing 'approved' label");
                        prResult.Status = "missing-approved-label";
                        prResult.Message = "Missing 'approved' label";
                        result.SkippedPRs.Add(prResult);
                        continue;
                    }

                    if (!hasSecurityFixLabel)
                    {
                        Console.WriteLine($"  ⏭️  Skipping PR #{pr.Number}: Missing 'security-fix' label");
                        prResult.Status = "missing-security-fix-label";
                        prResult.Message = "Missing 'security-fix' label";
                        result.SkippedPRs.Add(prResult);
                        continue;
                    }

                    Console.WriteLine($"  ✓ PR #{pr.Number} has both 'approved' and 'security-fix' labels");
                    Console.WriteLine($"Processing approved security fix PR #{pr.Number}...");

                    // Run final build verification
                    var buildResult = await RunFinalBuildVerificationAsync();
                    if (!buildResult.Success)
                    {
                        prResult.Status = "build-verification-failed";
                        prResult.Error = buildResult.ErrorSummary;
                        result.FailedMerges.Add(prResult);

                        await CommentOnPullRequestAsync(owner, repo, pr.Number,
                            $"❌ Build verification failed: {buildResult.ErrorSummary}");
                        continue;
                    }

                    // Merge PR
                    var mergePullRequest = new MergePullRequest
                    {
                        CommitTitle = $"Security fix: {pr.Title}",
                        MergeMethod = PullRequestMergeMethod.Squash
                    };

                    var mergeResult = await _gitHubClient.PullRequest.Merge(owner, repo, pr.Number, mergePullRequest);

                    if (mergeResult.Merged)
                    {
                        prResult.Status = "merged";
                        prResult.MergeCommitSha = mergeResult.Sha;

                        // Extract issue number from PR body (look for "Closes #N" pattern)
                        var issueNumber = ExtractIssueNumberFromPRBody(pr.Body);
                        
                        // Close the associated issue if found
                        if (!string.IsNullOrEmpty(issueNumber))
                        {
                            try
                            {
                                int issueNum = int.Parse(issueNumber);
                                await _gitHubClient.Issue.Get(owner, repo, issueNum);
                                await _gitHubClient.Issue.Update(owner, repo, issueNum, 
                                    new IssueUpdate { State = ItemState.Closed });
                                
                                // Add comment to closed issue
                                await CommentOnIssueAsync(owner, repo, issueNum,
                                    $"✅ Fixed by PR #{pr.Number}. Issue closed automatically.");
                                
                                Console.WriteLine($"  ✓ Closed associated issue #{issueNumber}");
                            }
                            catch (OverflowException)
                            {
                                // Issue number is too large, use GitHub API directly
                                try
                                {
                                    using var httpClient = new System.Net.Http.HttpClient();
                                    httpClient.DefaultRequestHeaders.Add("User-Agent", "OssSecurityAgent");
                                    httpClient.DefaultRequestHeaders.Authorization = 
                                        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _githubToken);
                                    
                                    var patchPayload = System.Text.Json.JsonSerializer.Serialize(new { state = "closed" });
                                    var content = new System.Net.Http.StringContent(patchPayload, System.Text.Encoding.UTF8, "application/json");
                                    var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Patch,
                                        $"https://api.github.com/repos/{owner}/{repo}/issues/{issueNumber}")
                                    {
                                        Content = content
                                    };
                                    var response = await httpClient.SendAsync(request);
                                    
                                    if (response.IsSuccessStatusCode)
                                    {
                                        var commentPayload = System.Text.Json.JsonSerializer.Serialize(new
                                        {
                                            body = $"✅ Fixed by PR #{pr.Number}. Issue closed automatically."
                                        });
                                        var commentContent = new System.Net.Http.StringContent(
                                            commentPayload,
                                            System.Text.Encoding.UTF8,
                                            "application/json");
                                        var commentResponse = await httpClient.PostAsync(
                                            $"https://api.github.com/repos/{owner}/{repo}/issues/{issueNumber}/comments",
                                            commentContent);
                                        if (!commentResponse.IsSuccessStatusCode)
                                        {
                                            Console.WriteLine($"  ⚠️ Closed issue #{issueNumber} but could not add comment: {commentResponse.StatusCode}");
                                        }
                                        Console.WriteLine($"  ✓ Closed associated issue #{issueNumber}");
                                    }
                                }
                                catch (Exception ex)
                                {
                                    Console.WriteLine($"  ⚠️ Could not close issue #{issueNumber}: {ex.Message}");
                                }
                            }
                            catch (Exception closeEx)
                            {
                                Console.WriteLine($"  ⚠️ Could not close issue #{issueNumber}: {closeEx.Message}");
                            }
                        }

                        // Comment on PR
                        var comment = GenerateMergeComment(pr, mergeResult, "automated-merge");
                        await CommentOnPullRequestAsync(owner, repo, pr.Number, comment);

                        result.SuccessfulMerges.Add(prResult);
                        Console.WriteLine($"✅ PR #{pr.Number} merged successfully");
                    }
                    else
                    {
                        prResult.Status = "merge-failed";
                        prResult.Error = mergeResult.Message ?? "Unknown merge error";
                        result.FailedMerges.Add(prResult);
                        Console.WriteLine($"❌ PR #{pr.Number} merge failed: {mergeResult.Message}");
                    }
                }
                catch (Exception ex)
                {
                    prResult.Status = "merge-failed";
                    prResult.Error = ex.Message;
                    result.FailedMerges.Add(prResult);
                    Console.WriteLine($"❌ Error processing PR #{pr.Number}: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
            Console.WriteLine($"❌ Merge workflow error: {ex.Message}");
        }

        await PrintMergeSummaryAsync(result);
        return result;
    }

    private string? ExtractIssueNumberFromPRBody(string? prBody)
    {
        if (string.IsNullOrEmpty(prBody))
            return null;

        // Look for patterns like "Closes #123" or "closes #123"
        var match = System.Text.RegularExpressions.Regex.Match(prBody, @"[Cc]loses\s+#(\d+)");
        return match.Success ? match.Groups[1].Value : null;
    }

    private async Task CommentOnIssueAsync(string owner, string repo, int issueNumber, string comment)
    {
        try
        {
            await _gitHubClient.Issue.Comment.Create(owner, repo, issueNumber, comment);
        }
        catch (OverflowException)
        {
            // Fallback to GitHub API directly for large issue numbers
            try
            {
                using var httpClient = new System.Net.Http.HttpClient();
                httpClient.DefaultRequestHeaders.Add("User-Agent", "OssSecurityAgent");
                httpClient.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", Config.GitHubToken);
                
                var jsonPayload = System.Text.Json.JsonSerializer.Serialize(new { body = comment });
                using var content = new System.Net.Http.StringContent(jsonPayload, System.Text.Encoding.UTF8, "application/json");
                var response = await httpClient.PostAsync(
                    $"https://api.github.com/repos/{owner}/{repo}/issues/{issueNumber}/comments",
                    content);
                
                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"  Note: Failed to add comment to issue #{issueNumber}: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  Note: Could not comment on issue #{issueNumber}: {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Note: Could not comment on issue #{issueNumber}: {ex.Message}");
        }
    }

    private async Task<(string owner, string repo)> GetRepositoryInfoAsync()
    {
        var gitOps = new GitOperations(_repoPath);
        var repoUrl = await gitOps.GetRepositoryUrlAsync();

        // Parse: https://github.com/owner/repo.git or git@github.com:owner/repo.git
        var uri = new Uri(repoUrl.Replace("git@github.com:", "https://github.com/").Replace(".git", ""));
        var segments = uri.AbsolutePath.TrimStart('/').Split('/');

        if (segments.Length >= 2)
            return (segments[0], segments[1]);

        throw new InvalidOperationException($"Unable to parse repository from URL: {repoUrl}");
    }

    private async Task<BuildResult> RunFinalBuildVerificationAsync()
    {
        var result = new BuildResult();

        try
        {
            var (success, output) = await RunDotnetBuildAsync();
            result.Success = success;
            if (!success)
                result.ErrorSummary = output;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorSummary = ex.Message;
        }

        return result;
    }

    private async Task<(bool success, string output)> RunDotnetBuildAsync()
    {
        var processInfo = new System.Diagnostics.ProcessStartInfo("dotnet", "build")
        {
            WorkingDirectory = _repoPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (var process = System.Diagnostics.Process.Start(processInfo))
        {
            if (process == null)
                return (false, "Failed to start dotnet build");

            var stdout = await process.StandardOutput.ReadToEndAsync();
            var stderr = await process.StandardError.ReadToEndAsync();
            process.WaitForExit();

            return (process.ExitCode == 0, process.ExitCode == 0 ? stdout : stderr);
        }
    }

    private string GenerateMergeComment(PullRequest pr, PullRequestMerge mergeResult, string approver)
    {
        var sb = new StringBuilder();
        sb.AppendLine("## ✅ Automated Security Fix Merged");
        sb.AppendLine();
        sb.AppendLine($"**Merged by:** OssSecurityAgent");
        sb.AppendLine($"**Approved by:** @{approver}");
        sb.AppendLine($"**Commit:** {mergeResult.Sha}");
        sb.AppendLine();
        sb.AppendLine("### Build Status");
        sb.AppendLine("✅ Build verification passed");
        sb.AppendLine();
        sb.AppendLine("### Details");
        sb.AppendLine($"- **PR:** #{pr.Number}");
        sb.AppendLine($"- **Branch:** {pr.Head.Ref}");
        sb.AppendLine($"- **Merge Method:** Squash");

        return sb.ToString();
    }

    private async Task CommentOnPullRequestAsync(string owner, string repo, int prNumber, string comment)
    {
        try
        {
            await _gitHubClient.Issue.Comment.Create(owner, repo, prNumber, comment);
        }
        catch (OverflowException)
        {
            // Fallback to GitHub API directly for large PR numbers
            try
            {
                using var httpClient = new System.Net.Http.HttpClient();
                httpClient.DefaultRequestHeaders.Add("User-Agent", "OssSecurityAgent");
                httpClient.DefaultRequestHeaders.Authorization = 
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", Config.GitHubToken);
                
                var jsonPayload = System.Text.Json.JsonSerializer.Serialize(new { body = comment });
                var content = new System.Net.Http.StringContent(jsonPayload, System.Text.Encoding.UTF8, "application/json");
                var response = await httpClient.PostAsync(
                    $"https://api.github.com/repos/{owner}/{repo}/issues/{prNumber}/comments",
                    content);
                
                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"⚠️  Failed to comment on PR #{prNumber}: {response.StatusCode}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️  Unable to comment on PR #{prNumber}: {ex.Message}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"⚠️  Unable to comment on PR #{prNumber}: {ex.Message}");
        }
    }

    private async Task PrintMergeSummaryAsync(MergeResult result)
    {
        var (owner, repo) = await GetRepositoryInfoAsync();
        
        Console.WriteLine("\n" + new string('=', 60));
        Console.WriteLine("=== Merge Summary ===");
        Console.WriteLine(new string('=', 60));

        if (result.SuccessfulMerges.Any())
        {
            Console.WriteLine($"\n✅ Successful Merges: {result.SuccessfulMerges.Count}");
            foreach (var pr in result.SuccessfulMerges)
            {
                Console.WriteLine($"   PR #{pr.PRNumber}: {pr.Title}");
                Console.WriteLine($"   Link: https://github.com/{owner}/{repo}/pull/{pr.PRNumber}");
                Console.WriteLine($"   Commit: {pr.MergeCommitSha}");
            }
        }

        if (result.FailedMerges.Any())
        {
            Console.WriteLine($"\n❌ Failed Merges: {result.FailedMerges.Count}");
            foreach (var pr in result.FailedMerges)
            {
                Console.WriteLine($"   PR #{pr.PRNumber}: {pr.Title}");
                Console.WriteLine($"   Link: https://github.com/{owner}/{repo}/pull/{pr.PRNumber}");
                Console.WriteLine($"   Reason: {pr.Error}");
            }
        }

        if (result.SkippedPRs.Any())
        {
            Console.WriteLine($"\n⏭️  Skipped PRs: {result.SkippedPRs.Count}");
            foreach (var pr in result.SkippedPRs)
            {
                Console.WriteLine($"   PR #{pr.PRNumber}: {pr.Title}");
                Console.WriteLine($"   Link: https://github.com/{owner}/{repo}/pull/{pr.PRNumber}");
                Console.WriteLine($"   Reason: {pr.Message}");
            }
        }

        if (!string.IsNullOrEmpty(result.Error))
        {
            Console.WriteLine($"\n❌ Error: {result.Error}");
        }

        Console.WriteLine("\n" + new string('=', 60));
    }
}

public class MergeResult
{
    public List<PullRequestMergeResult> SuccessfulMerges { get; } = new();
    public List<PullRequestMergeResult> FailedMerges { get; } = new();
    public List<PullRequestMergeResult> SkippedPRs { get; } = new();
    public string? Error { get; set; }
}

public class PullRequestMergeResult
{
    public int PRNumber { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Status { get; set; } = string.Empty;
    public string? Message { get; set; }
    public string? Error { get; set; }
    public string? MergeCommitSha { get; set; }
}
