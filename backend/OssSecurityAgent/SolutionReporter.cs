using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using OssSecurityAgent.Models;

namespace OssSecurityAgent
{
    /// <summary>
    /// Reports solution analysis results in JSON and/or console format
    /// </summary>
    public class SolutionReporter
    {
        private readonly SolutionModel _solution;
        private readonly string _outputDirectory;

        public SolutionReporter(SolutionModel solution, string outputDirectory = ".")
        {
            _solution = solution ?? throw new ArgumentNullException(nameof(solution));
            _outputDirectory = outputDirectory;
        }

        /// <summary>
        /// Generate and output reports based on configured format
        /// </summary>
        public async Task GenerateReportsAsync()
        {
            var format = Config.OutputFormat ?? "both";

            switch (format.ToLower())
            {
                case "json":
                    await ExportJsonAsync();
                    break;

                case "console":
                    PrintConsoleReport();
                    break;

                case "both":
                    await ExportJsonAsync();
                    PrintConsoleReport();
                    break;

                default:
                    Console.WriteLine($"[SolutionReporter] Unknown output format: {format}. Using 'both'.");
                    await ExportJsonAsync();
                    PrintConsoleReport();
                    break;
            }
        }

        /// <summary>
        /// Export solution model to JSON file
        /// </summary>
        public async Task ExportJsonAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    var fileName = $"{_solution.Name}_analysis_{DateTime.Now:yyyyMMdd_HHmmss}.json";
                    var filePath = Path.Combine(_outputDirectory, fileName);

                    var options = new JsonSerializerOptions
                    {
                        WriteIndented = true,
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                    };

                    var json = JsonSerializer.Serialize(_solution, options);
                    File.WriteAllText(filePath, json);

                    Console.WriteLine($"[SolutionReporter] JSON report saved: {filePath}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SolutionReporter] Error exporting JSON: {ex.Message}");
                }
            });
        }

        /// <summary>
        /// Print human-readable console report
        /// </summary>
        public void PrintConsoleReport()
        {
            Console.WriteLine("\n" + new string('=', 80));
            Console.WriteLine($"OSS SECURITY AGENT - SOLUTION ANALYSIS REPORT");
            Console.WriteLine($"Solution: {_solution.Name}");
            Console.WriteLine($"Path: {_solution.Path}");
            Console.WriteLine($"Analysis Time: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
            Console.WriteLine(new string('=', 80));

            PrintSolutionSummary();
            PrintProjectsSection();
            PrintPackagesByTypeSection();
            PrintVulnerabilitySection();
            PrintRecommendationsSection();

            Console.WriteLine(new string('=', 80));
        }

        private void PrintSolutionSummary()
        {
            Console.WriteLine("\n📊 SOLUTION SUMMARY");
            Console.WriteLine(new string('-', 80));
            Console.WriteLine($"  Projects Found: {_solution.Metadata.ProjectsScanned}");
            Console.WriteLine($"  Unique Packages: {_solution.Metadata.TotalPackages}");
            Console.WriteLine($"  Vulnerabilities: {_solution.Metadata.Vulnerabilities.Critical + _solution.Metadata.Vulnerabilities.High + _solution.Metadata.Vulnerabilities.Medium + _solution.Metadata.Vulnerabilities.Low} total");
            Console.WriteLine($"    - 🔴 Critical: {_solution.Metadata.Vulnerabilities.Critical}");
            Console.WriteLine($"    - 🟠 High: {_solution.Metadata.Vulnerabilities.High}");
            Console.WriteLine($"    - 🟡 Medium: {_solution.Metadata.Vulnerabilities.Medium}");
            Console.WriteLine($"    - 🔵 Low: {_solution.Metadata.Vulnerabilities.Low}");
        }

        private void PrintProjectsSection()
        {
            Console.WriteLine("\n📁 PROJECTS");
            Console.WriteLine(new string('-', 80));

            var projects = _solution.Projects.OrderBy(p => p.Name).ToList();
            for (int i = 0; i < projects.Count; i++)
            {
                var project = projects[i];
                var isLast = (i == projects.Count - 1);
                var prefix = isLast ? "└── " : "├── ";

                Console.WriteLine($"{prefix}{project.Name}");
                Console.WriteLine($"    Path: {project.Path}");
                Console.WriteLine($"    Packages: {project.Packages.Count}");

                if (project.ProjectReferences.Count > 0)
                {
                    Console.WriteLine($"    Dependencies: {string.Join(", ", project.ProjectReferences.Select(r => r.ProjectName))}");
                }
            }
        }

        private void PrintPackagesByTypeSection()
        {
            Console.WriteLine("\n📦 PACKAGES BY TYPE");
            Console.WriteLine(new string('-', 80));

            var packagesByType = _solution.AggregatedPackages
                .GroupBy(kvp => kvp.Value.Type)
                .OrderBy(g => g.Key)
                .ToList();

            var typeDescriptions = new Dictionary<PackageType, string>
            {
                { PackageType.NuGet, "NuGet (Open Source)" },
                { PackageType.FirstPartyInternal, "First-Party (Internal)" },
                { PackageType.ThirdPartyLocal, "Third-Party (Local)" },
                { PackageType.ThirdPartyCustom, "Third-Party (Custom)" },
                { PackageType.Unknown, "Unknown" }
            };

            foreach (var group in packagesByType)
            {
                var typeDesc = typeDescriptions.TryGetValue(group.Key, out var desc) ? desc : group.Key.ToString();
                Console.WriteLine($"\n  {typeDesc}: {group.Count()} package(s)");

                var topPackages = group.OrderByDescending(kvp => kvp.Value.UsedByProjects.Count).Take(10);
                foreach (var (key, pkg) in topPackages)
                {
                    var usageStr = string.Join(", ", pkg.UsedByProjects.OrderBy(p => p));
                    Console.WriteLine($"    • {pkg.Name}@{pkg.Version} (used by: {usageStr})");
                }

                if (group.Count() > 10)
                {
                    Console.WriteLine($"    ... and {group.Count() - 10} more");
                }
            }
        }

        private void PrintVulnerabilitySection()
        {
            var vulnerablePackages = _solution.AggregatedPackages
                .Where(kvp => kvp.Value.Vulnerabilities.Count > 0)
                .OrderByDescending(kvp => kvp.Value.Vulnerabilities.Count)
                .ThenByDescending(kvp => kvp.Value.Vulnerabilities
                    .Count(v => v.Severity.Equals("CRITICAL", StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (vulnerablePackages.Count == 0)
            {
                Console.WriteLine("\n✅ NO VULNERABILITIES FOUND");
                return;
            }

            Console.WriteLine("\n🚨 VULNERABLE PACKAGES");
            Console.WriteLine(new string('-', 80));
            Console.WriteLine($"Found {vulnerablePackages.Count} package(s) with vulnerabilities:\n");

            foreach (var kvp in vulnerablePackages.Take(20))
            {
                var pkg = kvp.Value;
                var vulnsByServer = pkg.Vulnerabilities
                    .GroupBy(v => v.Severity ?? "UNKNOWN")
                    .OrderBy(g => g.Key)
                    .ToList();

                Console.WriteLine($"  {pkg.Name}@{pkg.Version}");
                foreach (var group in vulnsByServer)
                {
                    var icon = group.Key switch
                    {
                        "CRITICAL" => "🔴",
                        "HIGH" => "🟠",
                        "MEDIUM" => "🟡",
                        "LOW" => "🔵",
                        _ => "⚪"
                    };
                    Console.WriteLine($"    {icon} {group.Key}: {group.Count()} vulnerability/ies");
                }

                var projectsAffected = string.Join(", ", pkg.UsedByProjects.OrderBy(p => p));
                Console.WriteLine($"    Affects: {projectsAffected}");
            }

            if (vulnerablePackages.Count > 20)
            {
                Console.WriteLine($"\n  ... and {vulnerablePackages.Count - 20} more vulnerable package(s)");
            }
        }

        private void PrintRecommendationsSection()
        {
            Console.WriteLine("\n💡 RECOMMENDATIONS");
            Console.WriteLine(new string('-', 80));

            var recommendations = new List<string>();

            // Check for vulnerabilities
            var criticalVulns = _solution.Metadata.Vulnerabilities.Critical;
            var highVulns = _solution.Metadata.Vulnerabilities.High;
            if (criticalVulns > 0)
            {
                recommendations.Add($"2. URGENT: Update {criticalVulns} package(s) with CRITICAL vulnerabilities.");
            }
            if (highVulns > 0)
            {
                recommendations.Add($"3. High Priority: Update {highVulns} package(s) with HIGH severity vulnerabilities.");
            }

            // Check for first-party vs third-party distribution
            var firstPartyCount = _solution.AggregatedPackages
                .Values
                .Count(p => p.Type == PackageType.FirstPartyInternal);
            var nugetCount = _solution.AggregatedPackages
                .Values
                .Count(p => p.Type == PackageType.NuGet);

            if (firstPartyCount > 0)
            {
                recommendations.Add($"4. Review {firstPartyCount} internal package(s) for licensing compliance and security.");
            }

            if (nugetCount > 100)
            {
                recommendations.Add($"5. Large dependency tree ({nugetCount} NuGet packages). Consider consolidating dependencies.");
            }

            // Check for project count
            if (_solution.Projects.Count > 10)
            {
                recommendations.Add($"6. Solution has {_solution.Projects.Count} projects. Verify build time and modularity are acceptable.");
            }

            if (recommendations.Count == 0)
            {
                Console.WriteLine("  ✅ No major issues detected. Continue monitoring for new vulnerabilities.");
            }
            else
            {
                foreach (var rec in recommendations)
                {
                    Console.WriteLine($"  {rec}");
                }
            }
        }
    }
}
