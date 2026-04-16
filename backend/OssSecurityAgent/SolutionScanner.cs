using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
using OssSecurityAgent.Models;

namespace OssSecurityAgent
{
    /// <summary>
    /// Parses .sln files and builds solution models with project information
    /// </summary>
    public class SolutionScanner
    {
        private readonly string _slnPath;
        private readonly PackageCategorizer _categorizer;
        private SolutionModel? _solution = null;

        public SolutionScanner(string slnPath, PackageCategorizer categorizer)
        {
            _slnPath = slnPath ?? throw new ArgumentNullException(nameof(slnPath));
            _categorizer = categorizer ?? throw new ArgumentNullException(nameof(categorizer));
        }

        /// <summary>
        /// Parse the solution file and discover all projects
        /// </summary>
        public async Task<SolutionModel> ParseSolutionAsync()
        {
            if (!File.Exists(_slnPath))
                throw new FileNotFoundException($"Solution file not found: {_slnPath}");

            var slnDir = Path.GetDirectoryName(_slnPath) ?? "";
            var slnName = Path.GetFileNameWithoutExtension(_slnPath);

            Console.WriteLine($"[SolutionScanner] Parsing solution: {_slnPath}");

            _solution = new SolutionModel
            {
                Path = _slnPath,
                Name = slnName
            };

            // Parse .sln file to extract project references
            var projectReferences = ParseSolutionFile(_slnPath);
            Console.WriteLine($"[SolutionScanner] Found {projectReferences.Count} projects in solution");

            // Load each project
            foreach (var projRef in projectReferences)
            {
                var csprojPath = Path.Combine(slnDir, projRef.RelativePath);
                csprojPath = Path.GetFullPath(csprojPath); // Normalize path

                if (!File.Exists(csprojPath))
                {
                    Console.WriteLine($"[SolutionScanner] Warning: Project file not found: {csprojPath}");
                    continue;
                }

                try
                {
                    var project = await LoadProjectAsync(csprojPath, projRef.Name, projRef.Guid);
                    if (project != null)
                    {
                        _solution.Projects.Add(project);
                        Console.WriteLine($"[SolutionScanner] Loaded project: {project.Name}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SolutionScanner] Error loading project {csprojPath}: {ex.Message}");
                }
            }

            // Auto-discover first-party packages from project names
            var projectNames = _solution.Projects.Select(p => p.Name).ToList();
            _categorizer.AddProjectsFromSolution(projectNames);
            _categorizer.LoadConfigurationFromEnv();

            // Build project dependency graph and aggregate packages
            await BuildProjectDependenciesAsync();

            // Query vulnerabilities for all packages
            await QueryVulnerabilitiesAsync();

            Console.WriteLine($"[SolutionScanner] Solution parsing complete. {_solution.Projects.Count} projects loaded.");

            return _solution;
        }

        /// <summary>
        /// Parse .sln text file to extract project information
        /// </summary>
        private List<SolutionProjectReference> ParseSolutionFile(string slnPath)
        {
            var projects = new List<SolutionProjectReference>();

            try
            {
                var slnContent = File.ReadAllText(slnPath);

                // Regex to match: Project("{guid}") = "ProjectName", "RelativePath\ProjectName.csproj", "{guid}"
                var pattern = @"Project\(""{[^}]+}""\)\s*=\s*""([^""]+)"",\s*""([^""]+)"",\s*""{([^}]+)}""";
                var matches = Regex.Matches(slnContent, pattern);

                foreach (Match match in matches)
                {
                    var projectName = match.Groups[1].Value;
                    var relativePath = match.Groups[2].Value.Replace("\\", "/");  // Normalize paths
                    var projectGuid = match.Groups[3].Value;

                    // Skip solution folders (they don't have actual project files)
                    if (relativePath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) ||
                        relativePath.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase))
                    {
                        projects.Add(new SolutionProjectReference
                        {
                            Name = projectName,
                            RelativePath = relativePath,
                            Guid = projectGuid
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SolutionScanner] Error parsing .sln file: {ex.Message}");
            }

            return projects;
        }

        /// <summary>
        /// Load a .csproj file and extract its metadata
        /// </summary>
        private async Task<ProjectModel?> LoadProjectAsync(string csprojPath, string name, string guid)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var doc = XDocument.Load(csprojPath);
                    var project = new ProjectModel
                    {
                        Name = name,
                        Path = csprojPath,
                        Guid = guid
                    };

                    // Extract ProjectReference items (project-to-project dependencies)
                    var projectRefElements = doc.Descendants("ProjectReference");
                    foreach (var elem in projectRefElements)
                    {
                        var include = elem.Attribute("Include")?.Value;
                        if (!string.IsNullOrWhiteSpace(include))
                        {
                            var refPath = Path.Combine(Path.GetDirectoryName(csprojPath) ?? "", include);
                            var refProjectName = Path.GetFileNameWithoutExtension(include);
                            var refProjectPath = Path.GetFullPath(refPath);

                            project.ProjectReferences.Add(new ProjectReference
                            {
                                ProjectName = refProjectName,
                                ProjectPath = refProjectPath,
                                ProjectGuid = "" // Could be extracted from metadata if needed
                            });
                        }
                    }

                    // Load packages from lock file if it exists
                    LoadPackagesFromLockFile(project);

                    return project;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SolutionScanner] Error loading .csproj {csprojPath}: {ex.Message}");
                    return null;
                }
            });
        }

        /// <summary>
        /// Load package information from project.assets.json (lock file)
        /// </summary>
        private void LoadPackagesFromLockFile(ProjectModel project)
        {
            var lockFilePath = Path.Combine(Path.GetDirectoryName(project.Path) ?? "", "obj", "project.assets.json");

            if (!File.Exists(lockFilePath))
            {
                Console.WriteLine($"[SolutionScanner] Warning: Lock file not found for {project.Name}: {lockFilePath}");
                return;
            }

            try
            {
                var dependencies = SecurityAgentTools.GetProjectDependencies(project.Path);
                foreach (var (packageName, version) in dependencies)
                {
                    var key = $"{packageName}@{version}";
                    var type = _categorizer.CategorizePackage(packageName, (string?)null);

                    project.Packages[key] = new PackageInfo
                    {
                        Name = packageName,
                        Version = version,
                        Type = type,
                        Source = _categorizer.GetSourceDescription(type)
                    };
                }

                Console.WriteLine($"[SolutionScanner] Loaded {project.Packages.Count} packages for {project.Name}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SolutionScanner] Error loading packages for {project.Name}: {ex.Message}");
            }
        }

        /// <summary>
        /// Build inter-project dependency graph and aggregate packages
        /// </summary>
        private async Task BuildProjectDependenciesAsync()
        {
            if (_solution == null) return;

            var aggregatedPackages = new Dictionary<string, AggregatedPackageInfo>();

            // Aggregate all packages across projects
            foreach (var project in _solution.Projects)
            {
                foreach (var (packageKey, packageInfo) in project.Packages)
                {
                    if (!aggregatedPackages.TryGetValue(packageKey, out var aggPackage))
                    {
                        aggPackage = new AggregatedPackageInfo
                        {
                            Name = packageInfo.Name,
                            Version = packageInfo.Version,
                            Type = packageInfo.Type,
                            Source = packageInfo.Source,
                            Vulnerabilities = new List<Vulnerability>(packageInfo.Vulnerabilities)
                        };
                        aggregatedPackages[packageKey] = aggPackage;
                    }

                    // Track which projects use this package
                    if (!aggPackage.UsedByProjects.Contains(project.Name))
                    {
                        aggPackage.UsedByProjects.Add(project.Name);
                    }
                }
            }

            _solution.AggregatedPackages = aggregatedPackages;

            // Update metadata
            _solution.Metadata.ProjectsScanned = _solution.Projects.Count;
            _solution.Metadata.TotalPackages = aggregatedPackages.Count;

            Console.WriteLine($"[SolutionScanner] Aggregated {aggregatedPackages.Count} unique packages across {_solution.Projects.Count} projects");

            await Task.CompletedTask;
        }

        /// <summary>
        /// Query OSV.dev for vulnerabilities in all packages
        /// </summary>
        private async Task QueryVulnerabilitiesAsync()
        {
            if (_solution == null || _solution.AggregatedPackages.Count == 0)
            {
                Console.WriteLine("[SolutionScanner] No packages to check for vulnerabilities");
                return;
            }

            Console.WriteLine($"[SolutionScanner] Querying vulnerabilities for {_solution.AggregatedPackages.Count} packages...");

            try
            {
                // Prepare package list for OSV query
                var packages = _solution.AggregatedPackages.Values
                    .Select(p => (packageName: p.Name, version: p.Version))
                    .ToList();

                // Query OSV.dev
                var vulnJson = await SecurityAgentTools.CheckVulnerabilities(packages);

                // Parse and populate vulnerability data
                await PopulateVulnerabilitiesFromOsvAsync(vulnJson);

                Console.WriteLine($"[SolutionScanner] Vulnerability check complete");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SolutionScanner] Error querying vulnerabilities: {ex.Message}");
            }
        }

        /// <summary>
        /// Parse OSV response and populate vulnerability data
        /// </summary>
        private async Task PopulateVulnerabilitiesFromOsvAsync(string osvJson)
        {
            await Task.Run(() =>
            {
                try
                {
                    using var doc = JsonDocument.Parse(osvJson);
                    var root = doc.RootElement;

                    // Initialize vulnerability counts
                    var criticalCount = 0;
                    var highCount = 0;
                    var mediumCount = 0;
                    var lowCount = 0;

                    // Parse results array
                    if (root.TryGetProperty("results", out var resultsArray))
                    {
                        foreach (var result in resultsArray.EnumerateArray())
                        {
                            if (!result.TryGetProperty("query", out var queryElem)) continue;

                            var packageName = GetJsonString(queryElem, "name");
                            var packageVersion = GetJsonString(result, "version");

                            if (string.IsNullOrEmpty(packageName)) continue;

                            var packageKey = $"{packageName}@{packageVersion}";

                            if (!_solution.AggregatedPackages.TryGetValue(packageKey, out var aggPackage))
                            {
                                // Try without version
                                var noVersionKey = _solution.AggregatedPackages.Keys
                                    .FirstOrDefault(k => k.StartsWith(packageName + "@", StringComparison.OrdinalIgnoreCase));
                                
                                if (noVersionKey != null)
                                {
                                    aggPackage = _solution.AggregatedPackages[noVersionKey];
                                }
                                else
                                {
                                    continue;
                                }
                            }

                            // Parse vulnerabilities
                            if (result.TryGetProperty("vulnerabilities", out var vulnsArray))
                            {
                                foreach (var vulnElem in vulnsArray.EnumerateArray())
                                {
                                    var vulnId = GetJsonString(vulnElem, "id");
                                    var severity = GetJsonString(vulnElem, "severity");
                                    var summary = GetJsonString(vulnElem, "summary");
                                    var details = GetJsonString(vulnElem, "details");

                                    if (!string.IsNullOrEmpty(vulnId))
                                    {
                                        var vuln = new Vulnerability
                                        {
                                            Id = vulnId,
                                            Severity = severity,
                                            Summary = summary,
                                            Details = details
                                        };

                                        aggPackage.Vulnerabilities.Add(vuln);

                                        // Update counts
                                        switch (severity?.ToUpper())
                                        {
                                            case "CRITICAL": criticalCount++; break;
                                            case "HIGH": highCount++; break;
                                            case "MEDIUM": mediumCount++; break;
                                            case "LOW": lowCount++; break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Update metadata vulnerability counts
                    _solution.Metadata.Vulnerabilities.Critical = criticalCount;
                    _solution.Metadata.Vulnerabilities.High = highCount;
                    _solution.Metadata.Vulnerabilities.Medium = mediumCount;
                    _solution.Metadata.Vulnerabilities.Low = lowCount;

                    Console.WriteLine($"[SolutionScanner] Found vulnerabilities: {criticalCount} Critical, {highCount} High, {mediumCount} Medium, {lowCount} Low");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SolutionScanner] Error parsing vulnerability data: {ex.Message}");
                }
            });
        }

        /// <summary>
        /// Helper to safely extract JSON string property
        /// </summary>
        private static string GetJsonString(JsonElement element, string propertyName)
        {
            if (element.TryGetProperty(propertyName, out var prop) && prop.ValueKind == JsonValueKind.String)
            {
                return prop.GetString() ?? string.Empty;
            }
            return string.Empty;
        }

        /// <summary>
        /// Data class for solution project references
        /// </summary>
        private class SolutionProjectReference
        {
            public string Name { get; set; } = string.Empty;
            public string RelativePath { get; set; } = string.Empty;
            public string Guid { get; set; } = string.Empty;
        }
    }
}

