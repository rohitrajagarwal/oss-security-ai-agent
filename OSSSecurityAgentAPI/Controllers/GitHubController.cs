using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

[ApiController]
[Route("api/[controller]")]
public class GitHubController : ControllerBase
{
    private readonly ILogger<GitHubController> _logger;
    private readonly string _agentPath;
    private readonly IConfiguration _config;

    public GitHubController(ILogger<GitHubController> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;
        var currentDir = Directory.GetCurrentDirectory();
        var agentDir = Path.Combine(currentDir, "..", "OssSecurityAgent");
        if (!Directory.Exists(agentDir))
        {
            agentDir = Path.Combine(currentDir, "..", "..", "OssSecurityAgent");
        }
        _agentPath = Path.GetFullPath(agentDir);
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

            var localRepoPath = await GetOrCloneRepository(request.RepoUrl);
            if (string.IsNullOrEmpty(localRepoPath))
                return BadRequest(new { message = "Failed to access repository" });

            // Run merge workflow
            var result = await RunAgentCommand($"--repo \"{localRepoPath}\" --merge-approved-security-fixes");

            if (!result.Success)
                return BadRequest(new { message = result.Error });

            return Ok(new
            {
                success = true,
                message = $"PR #{request.PrNumber} approved and merged successfully",
                output = result.Output
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error approving PR");
            return StatusCode(500, new { message = ex.Message });
        }
    }

    private (string owner, string repoName) ParseGitHubUrl(string url)
    {
        // Extract owner and repo from GitHub URL
        // e.g., https://github.com/Samirasimha/OSSTest.git -> (Samirasimha, OSSTest)
        var parts = url.Replace("https://github.com/", "").Replace("git@github.com:", "").Split('/');
        var owner = parts.Length > 0 ? parts[0] : "";
        var repo = parts.Length > 1 ? parts[1].Replace(".git", "") : "";
        return (owner, repo);
    }

    private async Task<List<dynamic>> FetchIssuesAndPRsFromGitHub(string owner, string repo, string token)
    {
        var items = new List<dynamic>();
        // Implementation to fetch from GitHub API
        // This would use Octokit or HttpClient to fetch PRs and issues
        return items;
    }

    private async Task<string?> GetOrCloneRepository(string repoInput)
    {
        try
        {
            _logger.LogInformation($"GetOrCloneRepository called with: {repoInput}");
            
            if (repoInput.StartsWith("http") || repoInput.StartsWith("git@"))
            {
                var repoName = System.IO.Path.GetFileNameWithoutExtension(repoInput.Split('/').Last());
                var tempDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "oss-agent-repos");
                Directory.CreateDirectory(tempDir);
                
                var localPath = System.IO.Path.Combine(tempDir, repoName);
                _logger.LogInformation($"Repository is a GitHub URL. Will clone to: {localPath}");
                
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
                    cloneProcess.WaitForExit(120000);
                    
                    if (cloneProcess.ExitCode != 0)
                    {
                        _logger.LogError($"Git clone failed with exit code {cloneProcess.ExitCode}. Error: {cloneError}");
                        return null;
                    }
                    _logger.LogInformation($"Git clone successful.");
                }
                else
                {
                    _logger.LogInformation($"Repository already cloned at {localPath}, reusing it.");
                }
                
                return localPath;
            }
            else
            {
                _logger.LogInformation($"Repository is a local path: {repoInput}");
                if (Directory.Exists(repoInput))
                {
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
            process.WaitForExit(60000);

            return (process.ExitCode == 0, output, string.IsNullOrEmpty(error) ? null : error);
        }
        catch (Exception ex)
        {
            return (false, "", ex.Message);
        }
    }

    public class ApprovePRRequest
    {
        public string RepoUrl { get; set; }
        public int PrNumber { get; set; }
    }
}
