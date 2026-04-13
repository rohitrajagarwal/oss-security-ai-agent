using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

[ApiController]
[Route("api/[controller]")]
public class RemediateController : ControllerBase
{
    private readonly ILogger<RemediateController> _logger;
    private readonly string _agentPath;
    private readonly IConfiguration _config;

    public RemediateController(ILogger<RemediateController> logger, IConfiguration config)
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
        _logger.LogInformation($"Agent path set to: {_agentPath}");
    }

    [HttpPost("package")]
    public async Task<IActionResult> RemediatePackage([FromBody] RemediateRequest request)
    {
        try
        {
            if (string.IsNullOrEmpty(request.RepoUrl) || string.IsNullOrEmpty(request.PackageName))
                return BadRequest(new { message = "Repository URL and package name are required" });

            _logger.LogInformation($"Remediating package {request.PackageName} in {request.RepoUrl}");

            var localRepoPath = await GetOrCloneRepository(request.RepoUrl);
            if (string.IsNullOrEmpty(localRepoPath))
                return BadRequest(new { message = "Failed to access repository" });

            _logger.LogInformation("Building repository to generate dependency lock files...");
            var buildSuccess = await BuildRepository(localRepoPath);
            if (!buildSuccess)
            {
                _logger.LogWarning("Build failed or timed out, proceeding with remediation anyway...");
            }

            var remediationPath = FindProjectPath(localRepoPath);
            _logger.LogInformation($"Using remediation path: {remediationPath}");

            // Run remediation for specific package using --package flag
            var args = $"--repo \"{remediationPath}\" --remediate --package \"{request.PackageName}\"";
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

    [HttpPost("all")]
    public async Task<IActionResult> RemediateAll([FromBody] RemediateAllRequest request)
    {
        try
        {
            if (string.IsNullOrEmpty(request.RepoUrl))
                return BadRequest(new { message = "Repository URL is required" });

            _logger.LogInformation($"Remediating all vulnerabilities in {request.RepoUrl}");

            var localRepoPath = await GetOrCloneRepository(request.RepoUrl);
            if (string.IsNullOrEmpty(localRepoPath))
                return BadRequest(new { message = "Failed to access repository" });

            _logger.LogInformation("Building repository to generate dependency lock files...");
            var buildSuccess = await BuildRepository(localRepoPath);
            if (!buildSuccess)
            {
                _logger.LogWarning("Build failed or timed out, proceeding with remediation anyway...");
            }

            var remediationPath = FindProjectPath(localRepoPath);
            _logger.LogInformation($"Using remediation path: {remediationPath}");

            // Run remediation for all packages
            var result = await RunAgentCommand($"--repo \"{remediationPath}\" --remediate");

            if (!result.Success)
                return BadRequest(new { message = result.Error });

            // Clean up cloned repository after remediation completes
            await DeleteClonedRepository(localRepoPath);

            return Ok(new
            {
                success = true,
                message = "Remediation started for all vulnerabilities",
                output = result.Output
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error remediating all packages");
            return StatusCode(500, new { message = ex.Message });
        }
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

    private string FindProjectPath(string repoPath)
    {
        var rootProjects = Directory.GetFiles(repoPath, "*.csproj", SearchOption.TopDirectoryOnly);
        if (rootProjects.Length > 0)
            return repoPath;

        var allProjects = Directory.GetFiles(repoPath, "*.csproj", SearchOption.AllDirectories);
        if (allProjects.Length > 0)
        {
            var projectDir = Path.GetDirectoryName(allProjects[0]);
            return projectDir ?? repoPath;
        }

        return repoPath;
    }

    private async Task<bool> BuildRepository(string repoPath)
    {
        try
        {
            var projFiles = Directory.GetFiles(repoPath, "*.csproj", SearchOption.AllDirectories);
            if (projFiles.Length == 0)
            {
                _logger.LogWarning("No .csproj files found in repository");
                return true;
            }

            foreach (var projFile in projFiles)
            {
                var projDir = Path.GetDirectoryName(projFile) ?? repoPath;
                var buildProcess = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "dotnet",
                        Arguments = "build",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true,
                        WorkingDirectory = projDir
                    }
                };

                buildProcess.Start();
                _ = await buildProcess.StandardOutput.ReadToEndAsync();
                _ = await buildProcess.StandardError.ReadToEndAsync();
                var completed = buildProcess.WaitForExit(300000);
                if (!completed)
                {
                    buildProcess.Kill();
                    return false;
                }
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error building repository");
            return false;
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

    public class RemediateRequest
    {
        public string RepoUrl { get; set; }
        public string PackageName { get; set; }
        public string? RecommendedVersion { get; set; }
    }

    public class RemediateAllRequest
    {
        public string RepoUrl { get; set; }
    }
}
