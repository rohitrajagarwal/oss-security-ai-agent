using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Text.Json;
using OssSecurityAgent;
using OssSecurityAgent.Models;
using OSSSecurityAgentAPI.Models;
using OSSSecurityAgentAPI.Services;

[ApiController]
[Route("api/[controller]")]
public class ScanController : ControllerBase
{
    private readonly ILogger<ScanController> _logger;
    private readonly string _agentPath;
    private readonly IConfiguration _config;
    private readonly SolutionAnalysisService _solutionAnalysisService;

    public ScanController(ILogger<ScanController> logger, IConfiguration config)
    {
        _logger = logger;
        _config = config;
        _solutionAnalysisService = new SolutionAnalysisService();
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

            // Build the repository first to generate lock files
            _logger.LogInformation($"Building repository to generate dependency lock files...");
            var buildSuccess = await BuildRepository(localRepoPath);
            if (!buildSuccess)
            {
                _logger.LogWarning("Build failed or timed out, proceeding with scan anyway...");
            }

            // Find the correct path to scan (could be root or a subdirectory with .csproj)
            var scanPath = FindProjectPath(localRepoPath);
            _logger.LogInformation($"Scanning path: {scanPath}");

            // Run scan + detect + analyze so dependency JSON is always emitted,
            // even when vulnerability count is zero.
            var result = await RunAgentCommand($"--repo \"{scanPath}\" --scan --detect --analyze");

            if (!result.Success)
                return BadRequest(new { message = result.Error });

            // Parse the vulnerability output and count by package
            var vulnerabilitiesByPackage = ParseVulnerabilitiesFromOutput(result.Output);

            // Fallback: if still empty, run scan-only output parsing to recover dependency names/versions.
            if (vulnerabilitiesByPackage.Count == 0)
            {
                var scanOnlyResult = await RunAgentCommand($"--repo \"{scanPath}\" --scan");
                if (scanOnlyResult.Success)
                {
                    var parsedDependencies = ParseDependenciesFromScanOutput(scanOnlyResult.Output);
                    MergeScannedDependencies(vulnerabilitiesByPackage, parsedDependencies);
                }
            }

            // Clean up cloned repository after analysis completes
            await DeleteClonedRepository(localRepoPath);

            return Ok(new
            {
                success = true,
                vulnerabilitiesByPackage,
                rawOutput = result.Output
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error analyzing repository");
            return StatusCode(500, new { message = ex.Message });
        }
    }

    /// <summary>
    /// Scans a solution (.sln) file for vulnerabilities at the solution level
    /// Returns structured data about projects, packages, and vulnerabilities
    /// </summary>
    [HttpPost("scan-solution")]
    public async Task<IActionResult> ScanSolution([FromBody] ScanSolutionRequest request)
    {
        try
        {
            if (string.IsNullOrEmpty(request?.RepositoryPath))
                return BadRequest(new { success = false, error = "RepositoryPath is required" });

            _logger.LogInformation($"Scanning solution: {request.RepositoryPath}");

            // Get or clone the repository
            var localRepoPath = await GetOrCloneRepository(request.RepositoryPath);
            if (string.IsNullOrEmpty(localRepoPath))
                return BadRequest(new { success = false, error = "Failed to access repository" });

            _logger.LogInformation($"Building solution to generate lock files...");
            var buildSuccess = await BuildRepository(localRepoPath);
            if (!buildSuccess)
            {
                _logger.LogWarning("Build failed or timed out, proceeding with solution scan anyway...");
            }

            // Find the solution file
            var solutionFile = FindSolutionFile(localRepoPath);
            SolutionModel solutionModel = null;

            if (string.IsNullOrEmpty(solutionFile))
            {
                _logger.LogWarning("No .sln file found, falling back to project-level scanning");

                // Fall back to scanning individual projects if no .sln found
                var scanPath = FindProjectPath(localRepoPath);
                var result = await RunAgentCommand($"--repo \"{scanPath}\" --scan --detect --analyze");

                if (!result.Success)
                {
                    await DeleteClonedRepository(localRepoPath);
                    return BadRequest(new { success = false, error = result.Error });
                }

                // Parse output and create a synthetic SolutionModel for compatibility
                var vulnerabilities = ParseVulnerabilitiesFromOutput(result.Output);
                solutionModel = CreateSolutionModelFromProjectScan(localRepoPath, scanPath, vulnerabilities);
            }
            else
            {
                _logger.LogInformation($"Found solution file: {solutionFile}");

                // Create scanner with necessary dependencies
                var packageCategorizer = new PackageCategorizer();
                var scanner = new SolutionScanner(solutionFile, packageCategorizer);

                // Parse the solution (this does the full analysis)
                _logger.LogInformation($"Parsing solution structure...");
                solutionModel = await scanner.ParseSolutionAsync();
            }

            if (solutionModel == null)
            {
                _logger.LogError("Failed to parse solution/project");
                await DeleteClonedRepository(localRepoPath);
                return StatusCode(500, new { success = false, error = "Failed to analyze repository" });
            }

            _logger.LogInformation($"Analysis complete. Found {solutionModel.Projects?.Count ?? 0} projects");

            // Transform to API response format
            var response = _solutionAnalysisService.TransformSolutionModel(solutionModel);
            
            // Clean up cloned repository
            await DeleteClonedRepository(localRepoPath);

            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error scanning solution");
            return StatusCode(500, new { success = false, error = ex.Message });
        }
    }

    /// <summary>
    /// Request model for solution scanning endpoint
    /// </summary>
    public class ScanSolutionRequest
    {
        public string? RepositoryPath { get; set; }
    }

    /// <summary>
    /// Debug endpoint to trace each step of the flow
    /// </summary>
    [HttpGet("debug")]
    public async Task<IActionResult> Debug([FromQuery] string repo)
    {
        try
        {
            var steps = new List<string>();

            // Step 1: Receive repo
            steps.Add($"1. Received repo: {repo}");

            // Step 2: Clone/get local path
            var localRepoPath = await GetOrCloneRepository(repo);
            steps.Add($"2. Local repo path: {localRepoPath}");

            // Step 3: Build repository
            var buildSuccess = await BuildRepository(localRepoPath);
            steps.Add($"3. Build success: {buildSuccess}");

            // Step 4: Find project path
            var scanPath = FindProjectPath(localRepoPath);
            steps.Add($"4. Scan path: {scanPath}");

            // Step 5: Check if lock file exists
            var lockFilePath = Path.Combine(scanPath, "obj", "project.assets.json");
            var lockFileExists = System.IO.File.Exists(lockFilePath);
            steps.Add($"5. Lock file exists: {lockFileExists} at {lockFilePath}");

            // Step 6: List all csproj files
            var csprojFiles = Directory.GetFiles(localRepoPath, "*.csproj", SearchOption.AllDirectories);
            steps.Add($"6. All .csproj files found: {string.Join(", ", csprojFiles)}");

            return Ok(new { steps });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = ex.Message });
        }
    }

    [HttpGet("detect")]
    public async Task<IActionResult> Detect([FromQuery] string repo)
    {
        try
        {
            if (string.IsNullOrEmpty(repo))
                return BadRequest(new { message = "Repository URL is required" });

            _logger.LogInformation($"Detecting vulnerabilities in: {repo}");

            var localRepoPath = await GetOrCloneRepository(repo);
            if (string.IsNullOrEmpty(localRepoPath))
                return BadRequest(new { message = "Failed to access repository" });

            // Build the repository first
            _logger.LogInformation($"Building repository to generate dependency lock files...");
            var buildSuccess = await BuildRepository(localRepoPath);
            if (!buildSuccess)
            {
                _logger.LogWarning("Build failed or timed out, proceeding with scan anyway...");
            }

            // Find the correct path to scan
            var scanPath = FindProjectPath(localRepoPath);
            _logger.LogInformation($"Scanning path: {scanPath}");

            var result = await RunAgentCommand($"--repo \"{scanPath}\" --scan");

            if (!result.Success)
                return BadRequest(new { message = result.Error });

            var vulnerabilities = ParseVulnerabilitiesFromOutput(result.Output);

            // Clean up cloned repository after detection completes
            await DeleteClonedRepository(localRepoPath);

            return Ok(new
            {
                success = true,
                vulnerabilities,
                rawOutput = result.Output
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error detecting vulnerabilities");
            return StatusCode(500, new { message = ex.Message });
        }
    }

    /// <summary>
    /// Finds the correct project path to scan. 
    /// If root has .csproj, returns root. Otherwise finds first directory with .csproj
    /// </summary>
    private string FindProjectPath(string repoPath)
    {
        _logger.LogInformation($"FindProjectPath called with repoPath: {repoPath}");
        _logger.LogInformation($"repoPath exists: {Directory.Exists(repoPath)}");
        
        // Check if root has any .csproj files
        var rootProjects = Directory.GetFiles(repoPath, "*.csproj", SearchOption.TopDirectoryOnly);
        _logger.LogInformation($"Root .csproj files found: {rootProjects.Length}");
        if (rootProjects.Length > 0)
        {
            _logger.LogInformation($"Found .csproj files in root directory: {string.Join(", ", rootProjects)}");
            return repoPath;
        }

        // Look for subdirectories with .csproj
        var allProjects = Directory.GetFiles(repoPath, "*.csproj", SearchOption.AllDirectories);
        _logger.LogInformation($"All .csproj files found recursively: {allProjects.Length}");
        if (allProjects.Length > 0)
        {
            var projectDir = Path.GetDirectoryName(allProjects[0]);
            _logger.LogInformation($"Found .csproj in subdirectory: {allProjects[0]}");
            _logger.LogInformation($"Extracted project directory: {projectDir}");
            _logger.LogInformation($"Project directory exists: {Directory.Exists(projectDir)}");
            return projectDir ?? repoPath;
        }

        // No projects found, return root
        _logger.LogInformation("No .csproj files found, scanning root");
        return repoPath;
    }

    /// <summary>
    /// Finds the solution (.sln) file in the repository. Searches top-level only by default.
    /// </summary>
    private string? FindSolutionFile(string repoPath)
    {
        _logger.LogInformation($"FindSolutionFile called with repoPath: {repoPath}");
        
        // Look for .sln files at the root level first
        var rootSolutions = Directory.GetFiles(repoPath, "*.sln", SearchOption.TopDirectoryOnly);
        
        if (rootSolutions.Length > 0)
        {
            _logger.LogInformation($"Found {rootSolutions.Length} solution file(s) at root: {string.Join(", ", rootSolutions)}");
            return rootSolutions[0]; // Return the first one
        }

        // If not found at root, search recursively (but this is less common)
        var allSolutions = Directory.GetFiles(repoPath, "*.sln", SearchOption.AllDirectories);
        
        if (allSolutions.Length > 0)
        {
            _logger.LogInformation($"Found solution file in subdirectory: {allSolutions[0]}");
            return allSolutions[0];
        }

        _logger.LogInformation("No .sln files found");
        return null;
    }

    /// <summary>
    /// Creates a SolutionModel from project-level scanning when no .sln file exists.
    /// This ensures consistent response format regardless of .sln presence.
    /// </summary>
    private SolutionModel CreateSolutionModelFromProjectScan(string repoPath, string scanPath, Dictionary<string, dynamic> vulnerabilities)
    {
        var repoName = new DirectoryInfo(repoPath).Name;
        var projectName = new DirectoryInfo(scanPath).Name;

        var solution = new SolutionModel
        {
            Name = repoName,
            Path = repoPath
        };

        // Create a single project entry representing the scanned directory
        var project = new ProjectModel
        {
            Name = projectName,
            Path = scanPath,
            Guid = Guid.NewGuid().ToString()
        };

        // Process vulnerabilities and add packages to aggregated collection
        if (vulnerabilities != null)
        {
            foreach (var vulnEntry in vulnerabilities)
            {
                var packageKey = vulnEntry.Key;
                var vulnData = vulnEntry.Value;

                // Extract package name and version
                var packageName = vulnData.package ?? packageKey;
                var version = vulnData.version ?? "unknown";

                // Add to aggregated packages
                var aggregatedPkg = new AggregatedPackageInfo
                {
                    Name = packageName,
                    Version = version,
                    Type = PackageType.NuGet, // Default to NuGet for scanned packages
                    UsedByProjects = new List<string> { projectName }
                };

                // Add vulnerabilities if present
                if (vulnData.vulnerabilities is System.Collections.IEnumerable vulns)
                {
                    foreach (var vuln in vulns)
                    {
                        if (vuln is System.Collections.Generic.Dictionary<string, object> vulnDict)
                        {
                            aggregatedPkg.Vulnerabilities.Add(new Vulnerability
                            {
                                Id = vulnDict.ContainsKey("id") ? vulnDict["id"]?.ToString() : "UNKNOWN",
                                Severity = vulnDict.ContainsKey("severity") ? vulnDict["severity"]?.ToString() : "LOW",
                                Summary = vulnDict.ContainsKey("summary") ? vulnDict["summary"]?.ToString() : "",
                                Details = vulnDict.ContainsKey("details") ? vulnDict["details"]?.ToString() : ""
                            });
                        }
                    }
                }

                solution.AggregatedPackages[$"{packageName}@{version}"] = aggregatedPkg;

                // Also add to project packages
                project.Packages[packageKey] = new PackageInfo
                {
                    Name = packageName,
                    Version = version,
                    Type = PackageType.NuGet,
                    Vulnerabilities = aggregatedPkg.Vulnerabilities
                };
            }
        }

        solution.Projects.Add(project);
        solution.Metadata = new AnalysisMetadata
        {
            ProjectsScanned = 1,
            TotalPackages = solution.AggregatedPackages.Count,
            AnalysisDate = DateTime.UtcNow
        };

        return solution;
    }

    private async Task<(bool Success, string Output, string? Error)> RunAgentCommand(string args)
    {
        try
        {
            _logger.LogInformation($"RunAgentCommand called with args: {args}");
            
            var fullCommand = $"run --project \"{_agentPath}/OssSecurityAgent.csproj\" -- {args}";
            _logger.LogInformation($"Full dotnet command: dotnet {fullCommand}");
            
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "dotnet",
                    Arguments = fullCommand,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = _agentPath
                }
            };

            _logger.LogInformation($"Working directory: {_agentPath}");
            
            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync();
            var error = await process.StandardError.ReadToEndAsync();
            process.WaitForExit(60000); // 60 second timeout
            
            _logger.LogInformation($"Agent command exit code: {process.ExitCode}");
            if (!string.IsNullOrEmpty(error))
            {
                _logger.LogError($"Agent stderr: {error}");
            }

            return (process.ExitCode == 0, output, string.IsNullOrEmpty(error) ? null : error);
        }
        catch (Exception ex)
        {
            return (false, "", ex.Message);
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

    /// <summary>
    /// Builds the repository to generate lock files (project.assets.json) required for dependency detection
    /// </summary>
    private async Task<bool> BuildRepository(string repoPath)
    {
        try
        {
            _logger.LogInformation($"Building repository at: {repoPath}");

            // Find all .NET project files (.csproj) recursively
            var projFiles = Directory.GetFiles(repoPath, "*.csproj", SearchOption.AllDirectories);
            if (projFiles.Length == 0)
            {
                _logger.LogWarning("No .csproj files found in repository");
                return true; // Not a .NET project, but not an error
            }

            _logger.LogInformation($"Found {projFiles.Length} project file(s)");

            // Build ALL project files found
            foreach (var projFile in projFiles)
            {
                var projDir = Path.GetDirectoryName(projFile) ?? repoPath;
                _logger.LogInformation($"Building project: {projFile}");

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
                var buildOutput = await buildProcess.StandardOutput.ReadToEndAsync();
                var buildError = await buildProcess.StandardError.ReadToEndAsync();
                
                // Wait for build with 5 minute timeout per project
                bool completed = buildProcess.WaitForExit(300000);

                if (!completed)
                {
                    _logger.LogWarning($"Build timed out for {projFile} after 5 minutes");
                    buildProcess.Kill();
                    return false;
                }

                if (buildProcess.ExitCode == 0)
                {
                    _logger.LogInformation($"Build succeeded for {projFile}");
                }
                else
                {
                    _logger.LogWarning($"Build failed for {projFile} with exit code {buildProcess.ExitCode}");
                    _logger.LogWarning($"Build error: {buildError}");
                    // Continue to next project even if one fails
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

    private Dictionary<string, dynamic> ParseVulnerabilitiesFromOutput(string output)
    {
        var vulnerabilitiesByPackage = new Dictionary<string, dynamic>();
        
        try
        {
            string? jsonStr = null;

            // Preferred source: Code usage analysis report
            jsonStr = ExtractJsonBlockAfterMarker(output, "--- Code Usage Analysis Report ---");

            // Fallback source: vulnerability scan JSON (present even when no vulnerabilities are found)
            if (string.IsNullOrEmpty(jsonStr))
            {
                jsonStr = ExtractJsonBlockAfterMarker(output, "--- Vulnerability Check Complete ---");
            }

            if (string.IsNullOrEmpty(jsonStr))
            {
                _logger.LogWarning("Could not find dependency JSON in output");
                return vulnerabilitiesByPackage;
            }

            var json = JsonSerializer.Deserialize<JsonElement>(jsonStr);
            
            if (json.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in json.EnumerateObject())
                {
                    var packageKey = property.Name;
                    var packageData = property.Value;

                    if (packageData.ValueKind == JsonValueKind.Object)
                    {
                        var packageName = packageData.TryGetProperty("package", out var packageElement)
                            ? packageElement.GetString() ?? packageKey
                            : packageKey;

                        var version = packageData.TryGetProperty("version", out var versionElement)
                            ? versionElement.GetString() ?? "unknown"
                            : "unknown";

                        var aiRecommendation = packageData.TryGetProperty("aiRecommendation", out var aiRecommendationElement)
                            ? aiRecommendationElement.GetString() ?? ""
                            : "";

                        var riskSummary = packageData.TryGetProperty("riskSummary", out var riskSummaryElement)
                            ? riskSummaryElement.GetString() ?? ""
                            : "";

                        var vulnerabilities = new List<object>();
                        if (packageData.TryGetProperty("vulnerabilities", out var vulnsArray) && vulnsArray.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var vuln in vulnsArray.EnumerateArray())
                            {
                                var vulnObject = JsonSerializer.Deserialize<object>(vuln.GetRawText());
                                if (vulnObject != null)
                                {
                                    vulnerabilities.Add(vulnObject);
                                }
                            }
                        }

                        var vulnCount = vulnerabilities.Count;

                        vulnerabilitiesByPackage[packageKey] = new
                        {
                            package = packageName,
                            version,
                            vulnerabilities,
                            count = vulnCount,
                            aiRecommendation,
                            riskSummary
                        };
                    }
                    else if (packageData.ValueKind == JsonValueKind.Array)
                    {
                        // Fallback format: "Package@Version": [ ... vulnerabilities ... ]
                        var atIndex = packageKey.LastIndexOf('@');
                        var packageName = atIndex > 0 ? packageKey.Substring(0, atIndex) : packageKey;
                        var version = atIndex > 0 && atIndex < packageKey.Length - 1 ? packageKey.Substring(atIndex + 1) : "unknown";

                        var vulnerabilities = new List<object>();
                        foreach (var vuln in packageData.EnumerateArray())
                        {
                            var vulnObject = JsonSerializer.Deserialize<object>(vuln.GetRawText());
                            if (vulnObject != null)
                            {
                                vulnerabilities.Add(vulnObject);
                            }
                        }

                        vulnerabilitiesByPackage[packageKey] = new
                        {
                            package = packageName,
                            version,
                            vulnerabilities,
                            count = vulnerabilities.Count,
                            aiRecommendation = "",
                            riskSummary = ""
                        };
                    }
                }
            }
            
            _logger.LogInformation($"Parsed {vulnerabilitiesByPackage.Count} packages from output");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not parse vulnerabilities output");
        }
        
        return vulnerabilitiesByPackage;
    }

    private void MergeScannedDependencies(
        Dictionary<string, dynamic> vulnerabilitiesByPackage,
        IEnumerable<(string packageName, string version)> scannedDependencies)
    {
        foreach (var (packageName, version) in scannedDependencies)
        {
            var safeVersion = string.IsNullOrWhiteSpace(version) ? "unknown" : version;
            var packageKey = $"{packageName}@{safeVersion}";

            if (vulnerabilitiesByPackage.ContainsKey(packageKey))
                continue;

            vulnerabilitiesByPackage[packageKey] = new
            {
                package = packageName,
                version = safeVersion,
                vulnerabilities = new List<object>(),
                count = 0,
                aiRecommendation = "",
                riskSummary = ""
            };
        }
    }

    private IEnumerable<(string packageName, string version)> ParseDependenciesFromScanOutput(string output)
    {
        var dependencies = new List<(string packageName, string version)>();

        if (string.IsNullOrWhiteSpace(output))
            return dependencies;

        var lines = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (!line.StartsWith("- ", StringComparison.Ordinal))
                continue;

            var content = line.Substring(2).Trim();
            if (string.IsNullOrWhiteSpace(content))
                continue;

            var lastSpace = content.LastIndexOf(' ');
            if (lastSpace <= 0 || lastSpace >= content.Length - 1)
                continue;

            var packageName = content.Substring(0, lastSpace).Trim();
            var version = content.Substring(lastSpace + 1).Trim();

            if (!string.IsNullOrWhiteSpace(packageName))
            {
                dependencies.Add((packageName, string.IsNullOrWhiteSpace(version) ? "unknown" : version));
            }
        }

        return dependencies;
    }

    private string? ExtractJsonBlockAfterMarker(string output, string marker)
    {
        var markerIndex = output.IndexOf(marker, StringComparison.Ordinal);
        if (markerIndex == -1)
            return null;

        var searchStart = markerIndex + marker.Length;
        var jsonStart = output.IndexOf('{', searchStart);
        if (jsonStart == -1)
            return null;

        var depth = 0;
        for (var index = jsonStart; index < output.Length; index++)
        {
            if (output[index] == '{')
                depth++;
            else if (output[index] == '}')
                depth--;

            if (depth == 0)
            {
                return output.Substring(jsonStart, index - jsonStart + 1);
            }
        }

        return null;
    }
}
