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
                // Get only vulnerable packages for this project
                var vulnerablePackages = new List<PackageDetail>();
                var projectVulnerabilities = new List<VulnerabilityDetail>();

                if (project.Packages != null)
                {
                    foreach (var (pkgKey, pkgInfo) in project.Packages)
                    {
                        // Only include packages with vulnerabilities
                        if (pkgInfo.Vulnerabilities != null && pkgInfo.Vulnerabilities.Count > 0)
                        {
                            // Use AI summaries from agent's analyze output, or generate if not available
                            var aiRecommendation = !string.IsNullOrEmpty(pkgInfo.AiRecommendation) 
                                ? pkgInfo.AiRecommendation 
                                : GenerateAiRecommendation(pkgInfo);
                            
                            var riskSummary = !string.IsNullOrEmpty(pkgInfo.RiskSummary) 
                                ? pkgInfo.RiskSummary 
                                : GenerateRiskSummary(pkgInfo);

                            var packageDetail = new PackageDetail
                            {
                                Name = pkgInfo.Name,
                                Version = pkgInfo.Version,
                                Type = pkgInfo.Type.ToString(),
                                UsedByProjects = new List<string> { project.Name },
                                VulnerabilityCount = pkgInfo.Vulnerabilities.Count,
                                Vulnerabilities = pkgInfo.Vulnerabilities.Select(v => new VulnerabilityDetail
                                {
                                    Id = v.Id,
                                    Severity = v.Severity,
                                    Summary = v.Summary,
                                    Details = v.Details
                                }).ToList(),
                                AiRecommendation = aiRecommendation,
                                RiskSummary = riskSummary
                            };

                            vulnerablePackages.Add(packageDetail);

                            // Collect vulnerabilities
                            foreach (var vuln in pkgInfo.Vulnerabilities)
                            {
                                projectVulnerabilities.Add(new VulnerabilityDetail
                                {
                                    Id = vuln.Id,
                                    Severity = vuln.Severity,
                                    Summary = vuln.Summary,
                                    Details = vuln.Details
                                });
                            }
                        }
                    }
                }

                // Only add project if it has vulnerable packages
                if (vulnerablePackages.Count > 0)
                {
                    projects.Add(new ProjectSummary
                    {
                        Name = project.Name,
                        Guid = project.Guid,
                        PackageCount = project.Packages?.Count ?? 0,
                        Dependencies = project.ProjectReferences?.Select(pr => pr.ProjectName).ToList() ?? new List<string>(),
                        VulnerabilityCount = projectVulnerabilities.Count,
                        Packages = vulnerablePackages,
                        Vulnerabilities = projectVulnerabilities
                    });
                }
            }

            return projects;
        }

        /// <summary>
        /// Generate AI recommendation for a vulnerable package
        /// Uses actual vulnerability details from analysis
        /// </summary>
        private string GenerateAiRecommendation(PackageInfo package)
        {
            if (package.Vulnerabilities == null || package.Vulnerabilities.Count == 0)
                return "";

            var criticalCount = package.Vulnerabilities.Count(v => v.Severity?.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase) ?? false);
            var highCount = package.Vulnerabilities.Count(v => v.Severity?.Equals("HIGH", StringComparison.OrdinalIgnoreCase) ?? false);

            var severityLevel = "";
            if (criticalCount > 0)
                severityLevel = "CRITICAL";
            else if (highCount > 0)
                severityLevel = "HIGH";
            else
                severityLevel = "MEDIUM/LOW";

            // Collect detailed vulnerability information
            var detailedInfo = string.Join(" ", package.Vulnerabilities
                .Where(v => !string.IsNullOrWhiteSpace(v.Details))
                .Select(v => v.Details)
                .Distinct()
                .Take(2)); // Take first 2 detailed descriptions

            if (!string.IsNullOrWhiteSpace(detailedInfo) && detailedInfo.Length > 50)
            {
                return $"{severityLevel} PRIORITY: {package.Name} ({package.Version}) has {package.Vulnerabilities.Count} vulnerability/ies. " +
                    $"Details: {detailedInfo} " +
                    $"Fixed versions available: {string.Join(", ", package.Vulnerabilities.Where(v => !string.IsNullOrWhiteSpace(v.FixedVersion)).Select(v => v.FixedVersion).Distinct())}";
            }

            if (criticalCount > 0)
                return $"URGENT: {package.Name} ({package.Version}) has {criticalCount} CRITICAL vulnerability/ies. Update immediately to a patched version. " +
                    $"Available fixes: {string.Join(", ", package.Vulnerabilities.Where(v => !string.IsNullOrWhiteSpace(v.FixedVersion)).Select(v => v.FixedVersion).Distinct())}";
            else if (highCount > 0)
                return $"HIGH PRIORITY: {package.Name} ({package.Version}) has {highCount} HIGH severity vulnerability/ies. Prioritize patching in next release cycle. " +
                    $"Update to: {string.Join(", ", package.Vulnerabilities.Where(v => !string.IsNullOrWhiteSpace(v.FixedVersion)).Select(v => v.FixedVersion).Distinct())}";
            else
                return $"Review {package.Name} ({package.Version}) for available security updates and plan patching. " +
                    $"Recommended versions: {string.Join(", ", package.Vulnerabilities.Where(v => !string.IsNullOrWhiteSpace(v.FixedVersion)).Select(v => v.FixedVersion).Distinct())}";
        }

        /// <summary>
        /// Generate risk summary for a vulnerable package
        /// Uses actual vulnerability details from analysis
        /// </summary>
        private string GenerateRiskSummary(PackageInfo package)
        {
            if (package.Vulnerabilities == null || package.Vulnerabilities.Count == 0)
                return "No known vulnerabilities";

            var severityCounts = new Dictionary<string, int>();
            foreach (var vuln in package.Vulnerabilities)
            {
                var severity = vuln.Severity?.ToUpper() ?? "UNKNOWN";
                if (!severityCounts.ContainsKey(severity))
                    severityCounts[severity] = 0;
                severityCounts[severity]++;
            }

            // Collect CVE information
            var cveInfo = string.Join(", ", package.Vulnerabilities
                .Where(v => !string.IsNullOrWhiteSpace(v.CVE))
                .Select(v => v.CVE)
                .Distinct()
                .Take(3));

            // Get summary from vulnerabilities
            var vulnSummaries = string.Join(" ", package.Vulnerabilities
                .Where(v => !string.IsNullOrWhiteSpace(v.Summary))
                .Select(v => v.Summary)
                .Distinct()
                .Take(2));

            var summaryParts = severityCounts.OrderByDescending(kvp => kvp.Key)
                .Select(kvp => $"{kvp.Value} {kvp.Key}")
                .ToList();

            var result = $"Found {package.Vulnerabilities.Count} vulnerabilities ({string.Join(", ", summaryParts)}). ";
            
            if (!string.IsNullOrWhiteSpace(cveInfo))
                result += $"CVEs: {cveInfo}. ";
            
            if (!string.IsNullOrWhiteSpace(vulnSummaries) && vulnSummaries.Length > 30)
                result += $"Summary: {vulnSummaries}";
            
            return result;
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

                // Use AI summaries from agent's analyze output, or generate if not available
                var aiRecommendation = !string.IsNullOrEmpty(package.AiRecommendation)
                    ? package.AiRecommendation
                    : (vulnCount > 0 ? GenerateAiRecommendation(package) : string.Empty);
                
                var riskSummary = !string.IsNullOrEmpty(package.RiskSummary)
                    ? package.RiskSummary
                    : (vulnCount > 0 ? GenerateRiskSummary(package) : string.Empty);

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
                        .ToList(),
                    AiRecommendation = aiRecommendation,
                    RiskSummary = riskSummary
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
