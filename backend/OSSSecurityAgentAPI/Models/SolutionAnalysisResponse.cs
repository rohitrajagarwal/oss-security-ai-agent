using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace OSSSecurityAgentAPI.Models
{
    /// <summary>
    /// Top-level response for solution analysis
    /// </summary>
    public class SolutionAnalysisResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; } = true;

        [JsonPropertyName("message")]
        public string Message { get; set; } = "Analysis complete";

        [JsonPropertyName("solution")]
        public SolutionSummary Solution { get; set; } = new();

        [JsonPropertyName("projects")]
        public List<ProjectSummary> Projects { get; set; } = new();

        [JsonPropertyName("packages")]
        public PackagesSummary Packages { get; set; } = new();

        [JsonPropertyName("vulnerabilities")]
        public VulnerabilitiesSummary Vulnerabilities { get; set; } = new();

        [JsonPropertyName("recommendations")]
        public List<string> Recommendations { get; set; } = new();

        [JsonPropertyName("analysisTime")]
        public DateTime AnalysisTime { get; set; } = DateTime.UtcNow;
    }

    public class SolutionSummary
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("path")]
        public string Path { get; set; } = string.Empty;

        [JsonPropertyName("projectsCount")]
        public int ProjectsCount { get; set; }

        [JsonPropertyName("totalPackages")]
        public int TotalPackages { get; set; }

        [JsonPropertyName("totalVulnerabilities")]
        public int TotalVulnerabilities { get; set; }
    }

    public class ProjectSummary
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("path")]
        public string Path { get; set; } = string.Empty;

        [JsonPropertyName("guid")]
        public string Guid { get; set; } = string.Empty;

        [JsonPropertyName("packageCount")]
        public int PackageCount { get; set; }

        [JsonPropertyName("dependencies")]
        public List<string> Dependencies { get; set; } = new();

        [JsonPropertyName("vulnerabilityCount")]
        public int VulnerabilityCount { get; set; }
    }

    public class PackagesSummary
    {
        [JsonPropertyName("byType")]
        public Dictionary<string, int> ByType { get; set; } = new();

        [JsonPropertyName("total")]
        public int Total { get; set; }

        [JsonPropertyName("uniqueVulnerable")]
        public int UniqueVulnerable { get; set; }

        [JsonPropertyName("detailed")]
        public List<PackageDetail> Detailed { get; set; } = new();
    }

    public class PackageDetail
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("version")]
        public string Version { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty; // NuGet, FirstPartyInternal, etc.

        [JsonPropertyName("usedByProjects")]
        public List<string> UsedByProjects { get; set; } = new();

        [JsonPropertyName("vulnerabilityCount")]
        public int VulnerabilityCount { get; set; }

        [JsonPropertyName("vulnerabilities")]
        public List<VulnerabilityDetail> Vulnerabilities { get; set; } = new();
    }

    public class VulnerabilityDetail
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("severity")]
        public string Severity { get; set; } = string.Empty;

        [JsonPropertyName("summary")]
        public string Summary { get; set; } = string.Empty;

        [JsonPropertyName("details")]
        public string Details { get; set; } = string.Empty;
    }

    public class VulnerabilitiesSummary
    {
        [JsonPropertyName("bySeverity")]
        public Dictionary<string, int> BySeverity { get; set; } = new()
        {
            { "CRITICAL", 0 },
            { "HIGH", 0 },
            { "MEDIUM", 0 },
            { "LOW", 0 }
        };

        [JsonPropertyName("affectedProjects")]
        public Dictionary<string, int> AffectedProjects { get; set; } = new();

        [JsonPropertyName("topVulnerablePackages")]
        public List<VulnerablePackageSummary> TopVulnerablePackages { get; set; } = new();
    }

    public class VulnerablePackageSummary
    {
        [JsonPropertyName("packageName")]
        public string PackageName { get; set; } = string.Empty;

        [JsonPropertyName("version")]
        public string Version { get; set; } = string.Empty;

        [JsonPropertyName("vulnerabilityCount")]
        public int VulnerabilityCount { get; set; }

        [JsonPropertyName("highestSeverity")]
        public string HighestSeverity { get; set; } = string.Empty;

        [JsonPropertyName("affectedProjects")]
        public List<string> AffectedProjects { get; set; } = new();
    }

    public class ScanErrorResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; } = false;

        [JsonPropertyName("message")]
        public string Message { get; set; } = string.Empty;

        [JsonPropertyName("error")]
        public string Error { get; set; } = string.Empty;
    }
}
