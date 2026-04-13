using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.IO;
using System.Threading.Tasks;

public class DependencyNode
{
    [JsonPropertyName("packageName")]
    public string PackageName { get; set; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    [JsonPropertyName("directDependents")]
    public List<string> DirectDependents { get; set; } = new();
}

public class DependencyGraph
{
    [JsonPropertyName("nodes")]
    public Dictionary<string, DependencyNode> Nodes { get; set; } = new();

    [JsonPropertyName("reverseDependencies")]
    public Dictionary<string, List<string>> ReverseDependencies { get; set; } = new();

    [JsonPropertyName("metadata")]
    public Dictionary<string, PackageMetadata> Metadata { get; set; } = new();

    public void AddNode(string packageName, string version)
    {
        var key = $"{packageName}@{version}";
        if (!Nodes.ContainsKey(key))
        {
            Nodes[key] = new DependencyNode { PackageName = packageName, Version = version };
            if (!ReverseDependencies.ContainsKey(key))
                ReverseDependencies[key] = new List<string>();
            if (!Metadata.ContainsKey(key))
                Metadata[key] = new PackageMetadata { PackageName = packageName, Version = version };
        }
    }

    public void AddDependency(string dependentName, string dependentVersion, string dependencyName, string dependencyVersion)
    {
        var dependentKey = $"{dependentName}@{dependentVersion}";
        var dependencyKey = $"{dependencyName}@{dependencyVersion}";

        AddNode(dependentName, dependentVersion);
        AddNode(dependencyName, dependencyVersion);

        if (!Nodes[dependencyKey].DirectDependents.Contains(dependentKey))
            Nodes[dependencyKey].DirectDependents.Add(dependentKey);

        if (!ReverseDependencies[dependentKey].Contains(dependencyKey))
            ReverseDependencies[dependentKey].Add(dependencyKey);
    }

    public List<string> GetDirectDependents(string packageName, string version)
    {
        var key = $"{packageName}@{version}";
        return Nodes.TryGetValue(key, out var node) ? new List<string>(node.DirectDependents) : new();
    }

    public List<string> GetReverseDependencies(string packageName, string version)
    {
        var key = $"{packageName}@{version}";
        return ReverseDependencies.TryGetValue(key, out var deps) ? new List<string>(deps) : new();
    }

    public string ToJson()
    {
        var options = new JsonSerializerOptions { WriteIndented = true };
        return JsonSerializer.Serialize(this, options);
    }
}

public class PackageMetadata
{
    [JsonPropertyName("packageName")]
    public string PackageName { get; set; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    [JsonPropertyName("nugetMetadata")]
    public NuGetMetadata? NuGetMetadata { get; set; }

    [JsonPropertyName("breakingChanges")]
    public BreakingChangeInfo? BreakingChanges { get; set; }
}

public class NuGetMetadata
{
    [JsonPropertyName("versionRange")]
    public string? VersionRange { get; set; }

    [JsonPropertyName("declaredDependencies")]
    public List<string> DeclaredDependencies { get; set; } = new();

    [JsonPropertyName("tags")]
    public List<string> Tags { get; set; } = new();

    [JsonPropertyName("licenseUrl")]
    public string? LicenseUrl { get; set; }
}

public class BreakingChangeInfo
{
    [JsonPropertyName("targetVersion")]
    public string? TargetVersion { get; set; }

    [JsonPropertyName("summary")]
    public string? Summary { get; set; }

    [JsonPropertyName("suggestedCodeChanges")]
    public List<string> SuggestedCodeChanges { get; set; } = new();

    [JsonPropertyName("riskLevel")]
    public string RiskLevel { get; set; } = "medium";
}
