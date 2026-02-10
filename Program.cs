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

class Program
{
    static async Task Main(string[] args)
    {
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
        var host = builder.Build();

        // 2.1 get repo path from args
        var repoPath = Utility.ParseRepoPath(args) ?? string.Empty;
        if (repoPath == "")
        {
            Console.WriteLine("Error: Please provide a repository path using the --repo flag.");
            return;
        }

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

                    // Step 2.5: Build dependency graph (must complete before reading it)
                    Console.WriteLine("Building dependency graph...");
                    await SecurityAgentTools.BuildDependencyGraphAsync(repoPath);

                    // Step 3: Load or create dependency graph
                    var graphPath = Path.Combine(repoPath, "dependency-graph.json");
                    var graph = await DependencyGraph.LoadFromFileAsync(graphPath) ?? new DependencyGraph();

                    // Step 4: Create remediation service and process vulnerabilities
                    var githubRepoUrl = Config.GitHubRepositoryUrl;
                    if (string.IsNullOrEmpty(githubRepoUrl))
                    {
                        Console.WriteLine("Error: GITHUB_REPOSITORY_URL environment variable is not set.");
                        Console.WriteLine("Please set it to your GitHub repository URL (e.g., https://github.com/owner/repo)");
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
}