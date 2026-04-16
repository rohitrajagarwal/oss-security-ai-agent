using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using OssSecurityAgent;
using OssSecurityAgent.Models;
using OSSSecurityAgentAPI.Models;

namespace OSSSecurityAgentAPI.Services
{
    /// <summary>
    /// Service to transform SolutionModel into API response contracts
    /// </summary>
    public class SolutionAnalysisService
    {
        public SolutionAnalysisResponse TransformSolutionModel(SolutionModel solutionModel)
        {
            var response = new SolutionAnalysisResponse
            {
                Solution = BuidlSolutionSummary(solutionModel),
                Projects = BuildProjectSummaries(solutionModel),
                Packages = BuildPackagesSummary(solutionModel),
                Vulnerabilities = BuildVulnerabilitiesSummary(solutionModel)
            };

            // Generate recommendations
            response.Recommendations = GenerateRecommendations(solutionModel);

            return response;
        }

        private SolutionSummary BuidlSolutionSummary(SolutionModel solution)
        {
            var criticalCount = solution.AggregatedPackages.Values
                .SelectMany(p => p.Vulnerabilities)
                .Count(v => v.Severity?.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase) ?? false);

            var highCount = solution.AggregatedPackages.Values
                .SelectMany(p => p.Vulnerabilities)
                .Count(v => v.Severity?.Equals("HIGH", StringComparison.OrdinalIgnoreCase) ?? false);

            var mediumCount = solution.AggregatedPackages.Values
                .SelectMany(p => p.Vulnerabilities)
                .Count(v => v.Severity?.Equals("MEDIUM", StringComparison.OrdinalIgnoreCase) ?? false);

            var lowCount = solution.AggregatedPackages.Values
                .SelectMany(p => p.Vulnerabilities)
                .Count(v => v.Severity?.Equals("LOW", StringComparison.OrdinalIgnoreCase) ?? false);

            return new SolutionSummary
            {
                Name = solution.Name,
                Path = solution.Path,
                ProjectsCount = solution.Projects?.Count ?? 0,
                TotalPackages = solution.AggregatedPackages?.Count ?? 0,
                TotalVulnerabilities = criticalCount + highCount + mediumCount + lowCount
            };
        }

        private List<ProjectSummary> BuildProjectSummaries(SolutionModel solution)
        {
            var projects = new List<ProjectSummary>();

            if (solution.Projects == null)
                return projects;

            foreach (var project in solution.Projects)
            {
                var vulnCount = solution.AggregatedPackages
                    .Where(pkg => pkg.Value.UsedByProjects?.Contains(project.Name) ?? false)
                    .SelectMany(pkg => pkg.Value.Vulnerabilities)
                    .Count();

                projects.Add(new ProjectSummary
                {
                    Name = project.Name,
                    Path = project.Path,
                    Guid = project.Guid,
                    PackageCount = project.Packages?.Count ?? 0,
                    Dependencies = project.ProjectReferences?.Select(pr => pr.ProjectName).ToList() ?? new List<string>(),
                    VulnerabilityCount = vulnCount
                });
            }

            return projects;
        }

        private PackagesSummary BuildPackagesSummary(SolutionModel solution)
        {
            var packagesSummary = new PackagesSummary();

            if (solution.AggregatedPackages == null)
                return packagesSummary;

            var typeCounts = solution.AggregatedPackages
                .GroupBy(p => p.Value.Type.ToString())
                .ToDictionary(g => g.Key, g => g.Count());

            packagesSummary.ByType = typeCounts;
            packagesSummary.Total = solution.AggregatedPackages.Count;

            // Build detailed list
            foreach (var package in solution.AggregatedPackages.Values)
            {
                var vulnCount = package.Vulnerabilities?.Count ?? 0;
                if (vulnCount > 0)
                {
                    packagesSummary.UniqueVulnerable++;
                }

                packagesSummary.Detailed.Add(new PackageDetail
                {
                    Name = package.Name,
                    Version = package.Version,
                    Type = package.Type.ToString(),
                    UsedByProjects = package.UsedByProjects?.ToList() ?? new List<string>(),
                    VulnerabilityCount = vulnCount,
                    Vulnerabilities = (package.Vulnerabilities ?? new List<Vulnerability>())
                        .Select(v => new VulnerabilityDetail
                        {
                            Id = v.Id,
                            Severity = v.Severity,
                            Summary = v.Summary,
                            Details = v.Details
                        })
                        .ToList()
                });
            }

            return packagesSummary;
        }

        private VulnerabilitiesSummary BuildVulnerabilitiesSummary(SolutionModel solution)
        {
            var vulnSummary = new VulnerabilitiesSummary();

            if (solution.AggregatedPackages == null)
                return vulnSummary;

            var severityCounts = new Dictionary<string, int>
            {
                { "CRITICAL", 0 },
                { "HIGH", 0 },
                { "MEDIUM", 0 },
                { "LOW", 0 }
            };

            var affectedProjects = new Dictionary<string, HashSet<string>>();

            foreach (var package in solution.AggregatedPackages.Values)
            {
                if (package.Vulnerabilities == null)
                    continue;

                foreach (var vuln in package.Vulnerabilities)
                {
                    var severity = vuln.Severity?.ToUpper() ?? "LOW";
                    if (severityCounts.ContainsKey(severity))
                    {
                        severityCounts[severity]++;
                    }

                    // Track affected projects
                    foreach (var project in package.UsedByProjects ?? new List<string>())
                    {
                        if (!affectedProjects.ContainsKey(project))
                            affectedProjects[project] = new HashSet<string>();
                        affectedProjects[project].Add($"{package.Name}@{package.Version}");
                    }
                }
            }

            vulnSummary.BySeverity = severityCounts;
            vulnSummary.AffectedProjects = affectedProjects
                .ToDictionary(kv => kv.Key, kv => kv.Value.Count);

            // Get top vulnerable packages
            vulnSummary.TopVulnerablePackages = solution.AggregatedPackages.Values
                .Where(p => p.Vulnerabilities?.Count > 0)
                .OrderByDescending(p => p.Vulnerabilities.Count)
                .ThenBy(p => GetHighestSeverity(p.Vulnerabilities))
                .Take(10)
                .Select(p => new VulnerablePackageSummary
                {
                    PackageName = p.Name,
                    Version = p.Version,
                    VulnerabilityCount = p.Vulnerabilities?.Count ?? 0,
                    HighestSeverity = GetHighestSeverityString(p.Vulnerabilities ?? new List<Vulnerability>()),
                    AffectedProjects = p.UsedByProjects?.ToList() ?? new List<string>()
                })
                .ToList();

            return vulnSummary;
        }

        private List<string> GenerateRecommendations(SolutionModel solution)
        {
            var recommendations = new List<string>();

            var criticalCount = solution.AggregatedPackages.Values
                .SelectMany(p => p.Vulnerabilities ?? new List<Vulnerability>())
                .Count(v => v.Severity?.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase) ?? false);

            var highCount = solution.AggregatedPackages.Values
                .SelectMany(p => p.Vulnerabilities ?? new List<Vulnerability>())
                .Count(v => v.Severity?.Equals("HIGH", StringComparison.OrdinalIgnoreCase) ?? false);

            if (criticalCount > 0)
            {
                recommendations.Add($"⚠️ URGENT: {criticalCount} critical vulnerabilities detected. Address these immediately before deploying to production.");
            }

            if (highCount > 0)
            {
                recommendations.Add($"🔴 {highCount} high-severity vulnerabilities found. These should be patched in the next release cycle.");
            }

            var unusedPackages = solution.AggregatedPackages.Values
                .Where(p => (p.UsedByProjects?.Count ?? 0) == 0)
                .ToList();

            if (unusedPackages.Any())
            {
                recommendations.Add($"📦 Found {unusedPackages.Count} potentially unused packages. Review and remove if not needed to reduce attack surface.");
            }

            // Check for packages with same name but different versions across projects
            var packagesByBaseName = solution.AggregatedPackages.Values
                .GroupBy(p => p.Name)
                .Where(g => g.Count() > 1)
                .ToList();

            if (packagesByBaseName.Any())
            {
                recommendations.Add($"🔄 {packagesByBaseName.Count} packages have multiple versions across projects. Align versions for consistency and maintainability.");
            }

            if (recommendations.Count == 0)
            {
                recommendations.Add("✅ No critical issues detected. Continue monitoring for security updates.");
            }

            return recommendations;
        }

        private int GetHighestSeverity(List<Vulnerability> vulnerabilities)
        {
            var severityMap = new Dictionary<string, int>
            {
                { "CRITICAL", 0 },
                { "HIGH", 1 },
                { "MEDIUM", 2 },
                { "LOW", 3 }
            };

            try
            {
                var nums = vulnerabilities
                    .Select(v => v.Severity?.ToUpper())
                    .Where(s => severityMap.ContainsKey(s ?? "LOW"))
                    .Select(s => severityMap[s ?? "LOW"])
                    .ToList();

                return nums.Count > 0 ? nums.Min() : 3;
            }
            catch
            {
                return 3;
            }
        }

        private string GetHighestSeverityString(List<Vulnerability> vulnerabilities)
        {
            var severities = new[] { "CRITICAL", "HIGH", "MEDIUM", "LOW" };
            
            foreach (var severity in severities)
            {
                if (vulnerabilities?.Any(v => v.Severity?.Equals(severity, StringComparison.OrdinalIgnoreCase) ?? false) ?? false)
                    return severity;
            }

            return "LOW";
        }
    }
}
