using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Build.Locator;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

// AI Namespaces
using GitHub.Copilot.SDK;
using Microsoft.Agents.AI;
using Microsoft.Extensions.AI; // Now comes safely from the Agent package

// Vulnerability Remediation
using OssSecurityAgent.Models;
using Octokit;

namespace OssSecurityAgent;

class Program
{
    static async Task Main(string[] args)
    {
        // 0. LOAD CONFIGURATION
        // Load config from the directory where this executable is running from
        var executingDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? Directory.GetCurrentDirectory();
        Config.Load(executingDir);

        // Check if user wants to verify configuration
        if (args.Any(a => string.Equals(a, "--verify-config", StringComparison.OrdinalIgnoreCase)))
        {
            Config.VerifyConfiguration();
            return;
        }

        // 1. PRE-HOST: Register MSBuild
        if (!MSBuildLocator.IsRegistered)
        {
            var instances = MSBuildLocator.QueryVisualStudioInstances().ToArray();
            if (instances.Length == 0)
            {
                Console.WriteLine("Error: No MSBuild instances found.");
                return;
            }
            MSBuildLocator.RegisterInstance(instances.OrderByDescending(x => x.Version).First());
        }

        // 2. SETUP HOST
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddSingleton<SecurityAgentTools>();
        
        // Register IChatClient if available
        try
        {
            var chatClientFactory = new ChatClientFactory();
            var chatClient = chatClientFactory.CreateChatClient();
            if (chatClient != null)
            {
                builder.Services.AddSingleton<IChatClient>(chatClient);
            }
        }
        catch
        {
            // If chat client cannot be initialized, continue without it
            Console.WriteLine("Warning: IChatClient could not be initialized. AI features will be unavailable.");
        }
        
        var host = builder.Build();

        // 2.0 Initialize the standardized chat client for all LLM calls (optional)
        var chatClientOptional = host.Services.GetService<IChatClient>();
        if (chatClientOptional != null)
        {
            SecurityAgentTools.SetChatClient(chatClientOptional);
        }

        // 2.1 get repo path from args
        var repoPath = Utility.ParseRepoPath(args) ?? string.Empty;
        if (repoPath == "")
        {
            Console.WriteLine("Error: Please provide a repository path using the --repo flag.");
            return;
        }

        // 2.2 SOLUTION-FIRST APPROACH: Check if input is a .sln file or if there's a .sln in the directory
        string? slnPath = null;
        if (repoPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase) && File.Exists(repoPath))
        {
            slnPath = repoPath;
        }
        else if (Directory.Exists(repoPath))
        {
            // Try to find a .sln file in the directory
            var slnFiles = Directory.GetFiles(repoPath, "*.sln", SearchOption.TopDirectoryOnly);
            if (slnFiles.Length > 0)
            {
                slnPath = slnFiles[0]; // Use the first .sln found
                Console.WriteLine($"[Program] Auto-detected solution: {slnPath}");
            }
            else if (slnFiles.Length > 1)
            {
                Console.WriteLine($"[Program] Warning: Found {slnFiles.Length} .sln files. Using the first one.");
                slnPath = slnFiles[0];
            }
        }

        // Flag to indicate whether we're using solution-level scanning
        var useSolutionScanning = slnPath != null;

        // New flags: control whether to run scan / detect / analyze
        var flagScan = args.Any(a => string.Equals(a, "--scan", StringComparison.OrdinalIgnoreCase));
        var flagDetect = args.Any(a => string.Equals(a, "--detect", StringComparison.OrdinalIgnoreCase));
        var flagAnalyze = args.Any(a => string.Equals(a, "--analyze", StringComparison.OrdinalIgnoreCase));
        var skipScanFlag = args.Any(a => string.Equals(a, "--skip-scan-detect-analyze", StringComparison.OrdinalIgnoreCase)
                          || string.Equals(a, "-skip-scan-detect-analyze", StringComparison.OrdinalIgnoreCase)
                          || string.Equals(a, "--skip-scan-detect-analyse", StringComparison.OrdinalIgnoreCase)
                          || string.Equals(a, "-skip-scan-detect-analyse", StringComparison.OrdinalIgnoreCase));

        if ((flagScan || flagDetect || flagAnalyze) && skipScanFlag)
        {
            Console.WriteLine("Error: cannot use --skip-scan-detect-analyze with specific operation flags (--scan/--detect/--analyze).");
            return;
        }

        // Get remediation flags early
        var remediate = args.Any(a => string.Equals(a, "--remediate", StringComparison.OrdinalIgnoreCase));
        var mergeApprovedFixes = args.Any(a => string.Equals(a, "--merge-approved-security-fixes", StringComparison.OrdinalIgnoreCase));
        var refreshMetadata = args.Any(a => string.Equals(a, "--refresh-metadata", StringComparison.OrdinalIgnoreCase));
        
        // Parse optional --package flag for per-package remediation
        string? filterPackageName = null;
        var packageFlagIndex = Array.FindIndex(args, a => string.Equals(a, "--package", StringComparison.OrdinalIgnoreCase));
        if (packageFlagIndex >= 0 && packageFlagIndex + 1 < args.Length)
        {
            filterPackageName = args[packageFlagIndex + 1];
        }

        // Parse optional --target-version flag for per-package remediation
        string? targetVersion = null;
        var targetVersionIndex = Array.FindIndex(args, a => string.Equals(a, "--target-version", StringComparison.OrdinalIgnoreCase));
        if (targetVersionIndex >= 0 && targetVersionIndex + 1 < args.Length)
        {
            targetVersion = args[targetVersionIndex + 1];
        }

        // Define local function to filter vulnerabilities by package
        string FilterVulnerabilitiesByPackage(string vulnerabilityJson, string packageName)
        {
            try
            {
                using var doc = JsonDocument.Parse(vulnerabilityJson);
                var root = doc.RootElement;
                var filtered = new Dictionary<string, JsonElement>();

                foreach (var item in root.EnumerateObject())
                {
                    // Package keys are in format "packageName@version"
                    if (item.Name.StartsWith(packageName + "@") || item.Name.Equals(packageName, StringComparison.OrdinalIgnoreCase))
                    {
                        filtered[item.Name] = item.Value;
                    }
                }

                // Convert back to JSON string
                var options = new JsonSerializerOptions { WriteIndented = true };
                return JsonSerializer.Serialize(filtered, options);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not filter vulnerabilities: {ex.Message}. Returning original JSON.");
                return vulnerabilityJson;
            }
        }

        // Define local function to override fixed version for a specific package
        string OverrideFixedVersionForPackage(string vulnerabilityJson, string packageName, string fixedVersion)
        {
            try
            {
                using var doc = JsonDocument.Parse(vulnerabilityJson);
                if (doc.RootElement.ValueKind != JsonValueKind.Object)
                    return vulnerabilityJson;

                var patched = new Dictionary<string, object?>();

                foreach (var packageEntry in doc.RootElement.EnumerateObject())
                {
                    var key = packageEntry.Name;
                    var value = packageEntry.Value;

                    var isTargetPackage = key.StartsWith(packageName + "@", StringComparison.OrdinalIgnoreCase)
                                          || key.Equals(packageName, StringComparison.OrdinalIgnoreCase);

                    if (!isTargetPackage || value.ValueKind != JsonValueKind.Array)
                    {
                        patched[key] = JsonSerializer.Deserialize<object>(value.GetRawText());
                        continue;
                    }

                    var patchedVulns = new List<Dictionary<string, object?>>();
                    foreach (var vuln in value.EnumerateArray())
                    {
                        if (vuln.ValueKind != JsonValueKind.Object)
                        {
                            patchedVulns.Add(new Dictionary<string, object?>());
                            continue;
                        }

                        var vulnDict = JsonSerializer.Deserialize<Dictionary<string, object?>>(vuln.GetRawText())
                                       ?? new Dictionary<string, object?>();

                        vulnDict["fixed_in"] = new List<string> { fixedVersion };
                        vulnDict["fixed_version"] = fixedVersion;

                        patchedVulns.Add(vulnDict);
                    }

                    patched[key] = patchedVulns;
                }

                var options = new JsonSerializerOptions { WriteIndented = true };
                return JsonSerializer.Serialize(patched, options);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Could not override fixed version: {ex.Message}. Using original vulnerability data.");
                return vulnerabilityJson;
            }
        }

        // If merge or remediate mode, skip the default scan/detect/analyze workflow
        if (mergeApprovedFixes || remediate || refreshMetadata)
        {
            skipScanFlag = true;
        }

        // If no specific flags provided, default to running scan+detect+analyze unless explicitly skipped or in remediation mode
        var noSpecific = !flagScan && !flagDetect && !flagAnalyze && !mergeApprovedFixes && !remediate && !refreshMetadata;
        var performScan = noSpecific && !skipScanFlag || flagScan || flagDetect || flagAnalyze;
        var performDetect = noSpecific && !skipScanFlag || flagDetect || flagAnalyze;
        var performAnalyze = noSpecific && !skipScanFlag || flagAnalyze;

        // 3. START AGENT
        Console.WriteLine("--- OssSecurityAgent Initialized ---");
        
        try
        {
            if (!performScan && !performDetect && !performAnalyze)
            {
                Console.WriteLine("Skipping scan, vulnerability detection, and usage analysis as requested.");
            }
            else
            {
                Console.WriteLine($"\n--- Operating on Repository: {repoPath} ---");

                // SOLUTION-LEVEL SCANNING (if .sln file was found)
                if (useSolutionScanning && slnPath != null)
                {
                    Console.WriteLine($"[Program] Using solution-level scanning: {slnPath}");
                    
                    try
                    {
                        // Initialize the solution scanner and reporter
                        var categorizer = new PackageCategorizer();
                        var scanner = new SolutionScanner(slnPath, categorizer);
                        
                        var solution = await scanner.ParseSolutionAsync();
                        
                        // Generate reports (JSON and/or console based on config)
                        var reportDir = Path.GetDirectoryName(slnPath) ?? ".";
                        var reporter = new SolutionReporter(solution, reportDir);
                        await reporter.GenerateReportsAsync();

                        Console.WriteLine("\n[Program] Solution analysis complete!");
                        
                        // For compatibility with downstream logic, we could extract flattened dependencies
                        // This allows the metadata to continue working if needed
                        var dependencies = solution.AggregatedPackages
                            .Select(kvp => (kvp.Value.Name, kvp.Value.Version))
                            .ToList();

                        // Handle analyze step if requested
                        if (performAnalyze)
                        {
                            Console.WriteLine($"\nPerforming AI-based code usage analysis for solution...");
                            
                            // Convert solution model vulnerabilities to CheckVulnerabilities JSON format
                            var vulnerabilitiesJson = ConvertSolutionVulnerabilitiesToJson(solution);
                            
                            // Call AnalyzeCodeUsage with the vulnerabilities
                            var analysisReport = await SecurityAgentTools.AnalyzeCodeUsage(vulnerabilitiesJson, repoPath);
                            Console.WriteLine("\n--- Code Usage Analysis Report ---");
                            Console.WriteLine(analysisReport);
                        }
                        else if (performDetect)
                        {
                            Console.WriteLine($"\nNote: Vulnerabilities already queried in solution scan. Analyze step not requested.");
                        }
                    }
                    catch (Exception sEx)
                    {
                        Console.WriteLine($"Error during solution scanning: {sEx.Message}");
                        throw;
                    }
                }
                else
                {
                    // LEGACY: Project-level scanning (backward compatibility)
                    Console.WriteLine($"[Program] Using project-level scanning (single project)");

                    // Always scan if any downstream step needs the deps
                    var dependencies = Enumerable.Empty<(string packageName, string version)>();
                    var depList = new List<(string packageName, string version)>();
                    if (performScan || performDetect || performAnalyze)
                    {
                        dependencies = SecurityAgentTools.GetProjectDependencies(repoPath) ?? Enumerable.Empty<(string packageName, string version)>();
                        depList = dependencies.ToList();
                    }

                    if (flagScan && !flagDetect && !flagAnalyze)
                    {
                        // --scan only: list all detected packages with versions
                        Console.WriteLine("\n--- Scan Complete: packages found ---");
                        Console.WriteLine($"Total: {depList.Count} dependencies");
                        foreach (var (packageName, version) in depList)
                        {
                            Console.WriteLine($"- {packageName} {version}");
                        }
                    }

                    if (performDetect)
                    {
                        // run vulnerability detection (uses scanned packages)
                        var finalResult = await SecurityAgentTools.CheckVulnerabilities(depList);
                        
                        // Filter vulnerabilities by affected version (project mode)
                        finalResult = SecurityAgentTools.FilterVulnerabilitiesByAffectedVersion(finalResult);
                        
                        Console.WriteLine("\n--- Vulnerability Check Complete ---");

                        // Print simple vulnerability count and full vulnerability output
                        int vulnCount = 0;
                        try
                        {
                            using var doc = JsonDocument.Parse(finalResult);
                            if (doc.RootElement.ValueKind == JsonValueKind.Object)
                            {
                                foreach (var prop in doc.RootElement.EnumerateObject())
                                {
                                    var val = prop.Value;
                                    if (val.ValueKind == JsonValueKind.Array)
                                        vulnCount += val.GetArrayLength();
                                }
                            }
                        }
                        catch { }

                        Console.WriteLine($"Dependencies scanned: {depList.Count}");
                        Console.WriteLine($"Vulnerabilities found: {vulnCount}");

                        // Show full vulnerabilities JSON for --detect
                        Console.WriteLine(finalResult);

                        // If --analyze was also requested, fall through to analysis below
                        if (!performAnalyze)
                        {
                            // done when only detect requested
                        }
                    }

                    if (performAnalyze)
                    {
                        // Ensure vuln detection was run to pass results into AnalyzeCodeUsage
                        var finalResult = await SecurityAgentTools.CheckVulnerabilities(depList);
                        
                        // Filter vulnerabilities by affected version (project mode)
                        finalResult = SecurityAgentTools.FilterVulnerabilitiesByAffectedVersion(finalResult);

                        int vulnCount = 0;
                        try
                        {
                            using var doc = JsonDocument.Parse(finalResult);
                            if (doc.RootElement.ValueKind == JsonValueKind.Object)
                            {
                                foreach (var prop in doc.RootElement.EnumerateObject())
                                {
                                    var val = prop.Value;
                                    if (val.ValueKind == JsonValueKind.Array)
                                        vulnCount += val.GetArrayLength();
                                }
                            }
                        }
                        catch { }

                        Console.WriteLine($"\n--- Analysis Summary ---");
                        Console.WriteLine($"Dependencies scanned: {depList.Count}");
                        Console.WriteLine($"Vulnerabilities found: {vulnCount}");

                        if (vulnCount > 0)
                        {
                            var analysisReport = await SecurityAgentTools.AnalyzeCodeUsage(finalResult, repoPath);
                            Console.WriteLine("\n--- Code Usage Analysis Report ---");
                            Console.WriteLine(analysisReport);
                        }
                        else
                        {
                            Console.WriteLine("There are no vulnerabilities therefore no risk summary/recommendation was generated.");
                        }
                    }
                }
            }

            // ========== VULNERABILITY REMEDIATION SYSTEM ==========
            
            // Validate conflicting flags
            if (remediate && mergeApprovedFixes)
            {
                Console.WriteLine("Error: cannot use --remediate with --merge-approved-security-fixes simultaneously. Run them in sequence.");
                return;
            }

            if (mergeApprovedFixes && (flagScan || flagDetect || flagAnalyze))
            {
                Console.WriteLine("Error: --merge-approved-security-fixes should not be combined with --scan, --detect, or --analyze.");
                return;
            }

            // Handle --merge-approved-security-fixes (must come before --remediate check)
            if (mergeApprovedFixes)
            {
                Console.WriteLine("\n--- Merging Approved Security Fix Pull Requests ---");
                try
                {
                    var gitHubToken = Config.GitHubToken;
                    var reviewers = Config.GitHubReviewers;
                    
                    if (string.IsNullOrEmpty(gitHubToken))
                    {
                        Console.WriteLine("Error: GITHUB_TOKEN environment variable is not set.");
                        return;
                    }

                    var mergeService = new PullRequestMergeService(repoPath, gitHubToken, reviewers);
                    var mergeResult = await mergeService.MergeApprovedSecurityFixesAsync();
                    
                    if (mergeResult.SuccessfulMerges.Any())
                    {
                        Console.WriteLine($"\n✓ Successfully merged {mergeResult.SuccessfulMerges.Count} PR(s):");
                        foreach (var pr in mergeResult.SuccessfulMerges)
                        {
                            Console.WriteLine($"  - #{pr.PRNumber}: {pr.Title}");
                        }
                    }

                    if (mergeResult.FailedMerges.Any())
                    {
                        Console.WriteLine($"\n✗ Failed to merge {mergeResult.FailedMerges.Count} PR(s):");
                        foreach (var failed in mergeResult.FailedMerges)
                        {
                            Console.WriteLine($"  - #{failed.PRNumber}: {failed.Error}");
                        }
                    }

                    if (!mergeResult.SuccessfulMerges.Any() && !mergeResult.FailedMerges.Any())
                    {
                        Console.WriteLine("No approved security fix PRs found.");
                    }

                    Console.WriteLine($"\n--- Merge Summary ---");
                    Console.WriteLine($"Total PRs checked: {mergeResult.SuccessfulMerges.Count + mergeResult.FailedMerges.Count + mergeResult.SkippedPRs.Count}");
                    Console.WriteLine($"Approved for merge: {mergeResult.SuccessfulMerges.Count}");
                    Console.WriteLine($"Failed: {mergeResult.FailedMerges.Count}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error during merge workflow: {ex.Message}");
                }
                return;
            }

            // Handle --remediate (create security fix PRs for detected vulnerabilities)
            if (remediate)
            {
                Console.WriteLine("\n--- Remediating Security Vulnerabilities ---");
                try
                {
                    var gitHubToken = Config.GitHubToken;
                    var reviewers = Config.GitHubReviewers;
                    
                    if (string.IsNullOrEmpty(gitHubToken))
                    {
                        Console.WriteLine("Error: GITHUB_TOKEN environment variable is not set.");
                        return;
                    }

                    // Step 1: Get dependencies
                    Console.WriteLine("Scanning dependencies...");
                    var dependencies = SecurityAgentTools.GetProjectDependencies(repoPath) ?? Enumerable.Empty<(string packageName, string version)>();
                    var depList = dependencies.ToList();

                    if (!depList.Any())
                    {
                        Console.WriteLine("No dependencies found.");
                        return;
                    }

                    // Step 2: Check for vulnerabilities
                    Console.WriteLine("Checking for vulnerabilities...");
                    var vulnerabilityJson = await SecurityAgentTools.CheckVulnerabilities(depList);

                    // Step 2.5: Filter vulnerabilities by package if --package flag provided
                    if (!string.IsNullOrEmpty(filterPackageName))
                    {
                        Console.WriteLine($"Filtering vulnerabilities for package: {filterPackageName}");
                        vulnerabilityJson = FilterVulnerabilitiesByPackage(vulnerabilityJson, filterPackageName);

                        if (!string.IsNullOrEmpty(targetVersion))
                        {
                            Console.WriteLine($"Applying target version override for {filterPackageName}: {targetVersion}");
                            vulnerabilityJson = OverrideFixedVersionForPackage(vulnerabilityJson, filterPackageName, targetVersion);
                        }
                    }

                    // Step 2.5: Build dependency graph in memory
                    Console.WriteLine("Building dependency graph...");
                    var graph = await SecurityAgentTools.BuildDependencyGraphAsync(repoPath);

                    // Step 4: Create remediation service and process vulnerabilities
                    var gitOps = new GitOperations(repoPath);
                    var githubRepoUrl = await gitOps.GetRepositoryUrlAsync();
                    if (string.IsNullOrEmpty(githubRepoUrl))
                    {
                        Console.WriteLine("Error: Unable to determine the GitHub repository URL from the git remote.");
                        Console.WriteLine("Please ensure the target repo has an origin remote configured.");
                        return;
                    }

                    var remediationService = new VulnerabilityRemediationService(repoPath, gitHubToken, githubRepoUrl, reviewers);
                    var remediationResult = await remediationService.ProcessVulnerabilitiesAsync(vulnerabilityJson, graph);

                    var remediatedItems = remediationResult.Items.Where(i => i.Success).ToList();
                    var failedItems = remediationResult.Items.Where(i => !i.Success).ToList();

                    if (remediatedItems.Any())
                    {
                        Console.WriteLine($"\n✓ Created fix PRs for {remediatedItems.Count} vulnerability group(s):");
                        foreach (var item in remediatedItems)
                        {
                            if (item.Vulnerability != null)
                                Console.WriteLine($"  - {item.Vulnerability.PackageName}: {item.Vulnerability.CurrentVersion} → {item.Vulnerability.FixedVersion}");
                            if (!string.IsNullOrEmpty(item.GitHubPullRequestUrl))
                                Console.WriteLine($"    PR: {item.GitHubPullRequestUrl}");
                        }
                    }

                    if (failedItems.Any())
                    {
                        Console.WriteLine($"\n✗ Failed to remediate {failedItems.Count} vulnerability group(s):");
                        foreach (var failed in failedItems)
                        {
                            var vulnName = failed.Vulnerability?.PackageName ?? "Unknown";
                            Console.WriteLine($"  - {vulnName}: {failed.Error}");
                        }
                    }

                    if (!remediatedItems.Any() && !failedItems.Any())
                    {
                        Console.WriteLine("No vulnerabilities detected. Repository is clean.");
                    }

                    Console.WriteLine($"\n--- Remediation Summary ---");
                    Console.WriteLine($"Total vulnerabilities processed: {remediationResult.TotalVulnerabilities}");
                    Console.WriteLine($"Successfully remediated: {remediationResult.SuccessfulRemediations}");
                    Console.WriteLine($"Failed: {remediationResult.FailedRemediations}");
                    Console.WriteLine($"Message: {remediationResult.Message}");

                    if (remediationResult.SuccessfulRemediations > 0)
                    {
                        Console.WriteLine("\n--- Next Steps ---");
                        Console.WriteLine("1. Review the generated PRs on GitHub");
                        Console.WriteLine("2. Wait for CI/CD checks to complete");
                        Console.WriteLine("3. Approve the PRs once verified");
                        Console.WriteLine("4. Run: dotnet run -- --repo <path> --merge-approved-security-fixes");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error during remediation workflow: {ex.Message}");
                }
                return;
            }

            // ========== END VULNERABILITY REMEDIATION SYSTEM ==========

            // CLI flags for Open Source License generation
            var generateOsl = args.Any(a => string.Equals(a, "--generate-osl", StringComparison.OrdinalIgnoreCase));
            var skipOsl = args.Any(a => string.Equals(a, "--skip-osl", StringComparison.OrdinalIgnoreCase));
            if (generateOsl && skipOsl)
            {
                Console.WriteLine("Error: cannot use both --generate-osl and --skip-osl simultaneously.");
                return;
            }

            if (generateOsl)
            {
                try
                {
                    Console.WriteLine("\n--- Generating consolidated open-source license file (AI) ---");
                    var oslPath = await OpenSourceLicenseAIGenerator.GenerateWithAIAsync(repoPath);
                    Console.WriteLine($"OSL file written: {oslPath}");
                }
                catch (Exception ex)
                {
                    var err = $"OSL generation failed: {ex}\n";
                    Console.WriteLine(err);
                    try
                    {
                        var logDir = Path.Combine(repoPath, "licenses");
                        Directory.CreateDirectory(logDir);
                        var logPath = Path.Combine(logDir, "osl-error.log");
                        await File.AppendAllTextAsync(logPath, DateTime.UtcNow.ToString("o") + " - " + err + Environment.NewLine);
                    }
                    catch { }
                }
            }
            else if (skipOsl)
            {
                Console.WriteLine("Skipping OSL generation as requested.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n[FATAL ERROR]: {ex}");
        }
    }

    /// <summary>
    /// Convert solution model vulnerabilities into the JSON format expected by AnalyzeCodeUsage
    /// </summary>
    static string ConvertSolutionVulnerabilitiesToJson(SolutionModel solution)
    {
        var vulnerabilitiesDict = new Dictionary<string, object>();

        // Process each package in the solution
        foreach (var kvp in solution.AggregatedPackages)
        {
            var packageKey = kvp.Key;  // e.g., "PackageName@Version"
            var packageInfo = kvp.Value;

            if (packageInfo.Vulnerabilities != null && packageInfo.Vulnerabilities.Count > 0)
            {
                Console.WriteLine($"[ConvertVulnerabilities] Processing {packageKey} with {packageInfo.Vulnerabilities.Count} vulnerabilities");

                // Convert Vulnerability objects to the format expected by AnalyzeCodeUsage
                var vulnsList = new List<Dictionary<string, object?>>();

                foreach (var vuln in packageInfo.Vulnerabilities)
                {
                    var vulnObj = new Dictionary<string, object?>
                    {
                        ["id"] = vuln.Id ?? "",
                        ["summary"] = vuln.Summary ?? "",
                        ["details"] = vuln.Details ?? "",
                        ["score"] = vuln.CvssScore,
                        ["description"] = vuln.Details ?? vuln.Summary ?? "",
                        ["fixed_in"] = new List<string> { vuln.FixedVersion ?? "" }.Where(s => !string.IsNullOrEmpty(s)).ToList(),
                        ["affected_versions"] = new List<string> { packageInfo.Version },
                        ["published_date"] = vuln.Published?.ToString("o") ?? "",
                        ["references"] = new List<string>()
                    };

                    vulnsList.Add(vulnObj);
                }

                if (vulnsList.Count > 0)
                {
                    vulnerabilitiesDict[packageKey] = vulnsList;
                }
            }
        }

        // Serialize to JSON with proper formatting
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };

        var resultJson = JsonSerializer.Serialize(vulnerabilitiesDict, options);
        Console.WriteLine($"[ConvertVulnerabilities] Total packages with vulnerabilities: {vulnerabilitiesDict.Count}");
        return resultJson;
    }
}