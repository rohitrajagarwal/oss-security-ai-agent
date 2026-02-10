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
                    Console.WriteLine($"Checking PR #{pr.Number} for approved reviews...");

                    // Get reviews for this PR
                    var reviews = await _gitHubClient.PullRequest.Review.GetAll(owner, repo, pr.Number);
                    
                    // Filter to only approved reviews
                    var approvedReviews = reviews.Where(r => r.State.Value == PullRequestReviewState.Approved).ToList();
                    
                    // Check if at least one approving review is from an authorized reviewer
                    var hasApprovedReview = false;
                    string? authorizedApproverUsername = null;
                    
                    if (_approvedReviewers.Any())
                    {
                        // If we have a list of approved reviewers, validate against it
                        foreach (var review in approvedReviews)
                        {
                            if (_approvedReviewers.Contains(review.User.Login, StringComparer.OrdinalIgnoreCase))
                            {
                                hasApprovedReview = true;
                                authorizedApproverUsername = review.User.Login;
                                break;
                            }
                        }
                        
                        if (!hasApprovedReview)
                        {
                            Console.WriteLine($"  ⏭️  Skipping PR #{pr.Number}: No approval from authorized reviewers");
                            prResult.Status = "no-authorized-approval";
                            prResult.Message = "No approval from authorized reviewers";
                            result.SkippedPRs.Add(prResult);
                            continue;
                        }
                    }
                    else
                    {
                        // If no approved reviewers list is configured, accept any approved review
                        var approvedReview = approvedReviews.FirstOrDefault();
                        if (approvedReview != null)
                        {
                            hasApprovedReview = true;
                            authorizedApproverUsername = approvedReview.User.Login;
                        }
                        else
                        {
                            Console.WriteLine($"  ⏭️  Skipping PR #{pr.Number}: No approved reviews found");
                            prResult.Status = "no-approval";
                            prResult.Message = "No approved reviews";
                            result.SkippedPRs.Add(prResult);
                            continue;
                        }
                    }

                    Console.WriteLine($"  ✓ PR #{pr.Number} approved by @{authorizedApproverUsername}");
                    Console.WriteLine($"Processing approved PR #{pr.Number}...");

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
                                    var response = await httpClient.PatchAsync(
                                        $"https://api.github.com/repos/{owner}/{repo}/issues/{issueNumber}",
                                        content);
                                    
                                    if (response.IsSuccessStatusCode)
                                    {
                                        await CommentOnIssueAsync(owner, repo, int.MaxValue, // Dummy, will use API fallback
                                            $"✅ Fixed by PR #{pr.Number}. Issue closed automatically.");
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
                        var comment = GenerateMergeComment(pr, mergeResult, authorizedApproverUsername ?? "automated");
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

        PrintMergeSummary(result);
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
                var content = new System.Net.Http.StringContent(jsonPayload, System.Text.Encoding.UTF8, "application/json");
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

    private void PrintMergeSummary(MergeResult result)
    {
        Console.WriteLine("\n" + new string('=', 50));
        Console.WriteLine("=== Merge Summary ===");
        Console.WriteLine(new string('=', 50));

        if (result.SuccessfulMerges.Any())
        {
            Console.WriteLine($"\n✅ Successful Merges: {result.SuccessfulMerges.Count}");
            foreach (var pr in result.SuccessfulMerges)
            {
                Console.WriteLine($"   PR #{pr.PRNumber}: {pr.Title}");
                Console.WriteLine($"   Commit: {pr.MergeCommitSha}");
            }
        }

        if (result.FailedMerges.Any())
        {
            Console.WriteLine($"\n❌ Failed Merges: {result.FailedMerges.Count}");
            foreach (var pr in result.FailedMerges)
            {
                Console.WriteLine($"   PR #{pr.PRNumber}: {pr.Error}");
            }
        }

        if (result.SkippedPRs.Any())
        {
            Console.WriteLine($"\n⏭️  Skipped PRs: {result.SkippedPRs.Count}");
            foreach (var pr in result.SkippedPRs)
            {
                Console.WriteLine($"   PR #{pr.PRNumber}: {pr.Status}");
            }
        }

        if (!string.IsNullOrEmpty(result.Error))
        {
            Console.WriteLine($"\n❌ Error: {result.Error}");
        }

        Console.WriteLine("\n" + new string('=', 50));
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
