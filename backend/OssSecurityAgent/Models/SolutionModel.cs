using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace OssSecurityAgent.Models
{
    /// <summary>
    /// Represents a complete .sln file with all projects and aggregated analysis
    /// </summary>
    public class SolutionModel
    {
        [JsonPropertyName("path")]
        public string Path { get; set; } = string.Empty;

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("projects")]
        public List<ProjectModel> Projects { get; set; } = new();

        [JsonPropertyName("aggregatedPackages")]
        public Dictionary<string, AggregatedPackageInfo> AggregatedPackages { get; set; } = new();

        [JsonPropertyName("analysisMetadata")]
        public AnalysisMetadata Metadata { get; set; } = new();

        /// <summary>
        /// Get all visited project names (for tracking traversal)
        /// </summary>
        public HashSet<string> GetVisitedProjects()
        {
            return new HashSet<string>(Projects.Select(p => p.Name), StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Get all package names across all projects (deduplicated)
        /// </summary>
        public IEnumerable<string> GetAllPackageKeys()
        {
            return AggregatedPackages.Keys;
        }

        /// <summary>
        /// Get summary of packages by type
        /// </summary>
        public Dictionary<PackageType, int> GetPackageCountByType()
        {
            return AggregatedPackages.Values
                .GroupBy(p => p.Type)
                .ToDictionary(g => g.Key, g => g.Count());
        }
    }

    /// <summary>
    /// Represents a single project (.csproj) within the solution
    /// </summary>
    public class ProjectModel
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("path")]
        public string Path { get; set; } = string.Empty;

        [JsonPropertyName("guid")]
        public string Guid { get; set; } = string.Empty;

        [JsonPropertyName("projectReferences")]
        public List<ProjectReference> ProjectReferences { get; set; } = new();

        [JsonPropertyName("packages")]
        public Dictionary<string, PackageInfo> Packages { get; set; } = new();

        [JsonPropertyName("isVisited")]
        public bool IsVisited { get; set; } = false;

        [JsonPropertyName("vulnerabilityCount")]
        public int VulnerabilityCount { get; set; } = 0;

        /// <summary>
        /// Get count of each package type in this project
        /// </summary>
        public Dictionary<PackageType, int> GetPackageCountByType()
        {
            return Packages.Values
                .GroupBy(p => p.Type)
                .ToDictionary(g => g.Key, g => g.Count());
        }
    }

    /// <summary>
    /// Represents a reference to another project within the same solution
    /// </summary>
    public class ProjectReference
    {
        [JsonPropertyName("projectName")]
        public string ProjectName { get; set; } = string.Empty;

        [JsonPropertyName("projectPath")]
        public string ProjectPath { get; set; } = string.Empty;

        [JsonPropertyName("projectGuid")]
        public string ProjectGuid { get; set; } = string.Empty;

        [JsonPropertyName("isVisited")]
        public bool IsVisited { get; set; } = false;
    }

    /// <summary>
    /// Represents a package and its metadata
    /// </summary>
    public class PackageInfo
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("version")]
        public string Version { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        public PackageType Type { get; set; } = PackageType.Unknown;

        [JsonPropertyName("source")]
        public string Source { get; set; } = string.Empty;

        [JsonPropertyName("vulnerabilities")]
        public List<Vulnerability> Vulnerabilities { get; set; } = new();

        [JsonPropertyName("aiRecommendation")]
        public string AiRecommendation { get; set; } = string.Empty;

        [JsonPropertyName("riskSummary")]
        public string RiskSummary { get; set; } = string.Empty;

        /// <summary>
        /// Get unique key for this package (Name@Version)
        /// </summary>
        public string GetKey() => $"{Name}@{Version}";

        /// <summary>
        /// Check if package has vulnerabilities
        /// </summary>
        public bool HasVulnerabilities => Vulnerabilities.Any();

        /// <summary>
        /// Get highest severity from vulnerabilities
        /// </summary>
        public string GetMaxSeverity()
        {
            if (!HasVulnerabilities) return "None";

            var severities = new[] { "critical", "high", "medium", "low" };
            foreach (var severity in severities)
            {
                if (Vulnerabilities.Any(v => v.Severity?.ToLower() == severity))
                    return severity;
            }
            return "Unknown";
        }
    }

    /// <summary>
    /// Aggregated package info across all projects in solution
    /// </summary>
    public class AggregatedPackageInfo : PackageInfo
    {
        [JsonPropertyName("usedByProjects")]
        public List<string> UsedByProjects { get; set; } = new();

        /// <summary>
        /// How many projects use this package
        /// </summary>
        public int ProjectCount => UsedByProjects.Count;
    }

    /// <summary>
    /// Package categorization type
    /// </summary>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum PackageType
    {
        NuGet,              // Open source from nuget.org
        FirstPartyInternal, // Internal to organization
        ThirdPartyLocal,    // Local file reference
        ThirdPartyCustom,   // Custom built, non-standard
        Unknown             // Unable to determine
    }

    /// <summary>
    /// Metadata about the analysis run
    /// </summary>
    public class AnalysisMetadata
    {
        [JsonPropertyName("analysisDate")]
        public DateTime AnalysisDate { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("durationSeconds")]
        public double DurationSeconds { get; set; } = 0;

        [JsonPropertyName("projectsScanned")]
        public int ProjectsScanned { get; set; } = 0;

        [JsonPropertyName("totalPackages")]
        public int TotalPackages { get; set; } = 0;

        [JsonPropertyName("vulnerabilityCount")]
        public VulnerabilityCount Vulnerabilities { get; set; } = new();
    }

    /// <summary>
    /// Count of vulnerabilities by severity
    /// </summary>
    public class VulnerabilityCount
    {
        [JsonPropertyName("critical")]
        public int Critical { get; set; } = 0;

        [JsonPropertyName("high")]
        public int High { get; set; } = 0;

        [JsonPropertyName("medium")]
        public int Medium { get; set; } = 0;

        [JsonPropertyName("low")]
        public int Low { get; set; } = 0;

        [JsonPropertyName("total")]
        public int Total => Critical + High + Medium + Low;
    }
}
