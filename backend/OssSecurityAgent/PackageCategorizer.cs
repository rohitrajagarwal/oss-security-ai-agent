using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using OssSecurityAgent.Models;

namespace OssSecurityAgent
{
    /// <summary>
    /// Categorizes packages as NuGet, FirstParty, ThirdParty, etc.
    /// Uses auto-discovery from .sln and optional .env configuration overrides
    /// </summary>
    public class PackageCategorizer
    {
        private readonly HashSet<string> _firstPartyProjectNames;
        private readonly HashSet<string> _firstPartyPackagePrefixes;
        private readonly HashSet<string> _firstPartyExactPackages;

        public PackageCategorizer()
        {
            _firstPartyProjectNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _firstPartyPackagePrefixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _firstPartyExactPackages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Add project names from solution (auto-discovery)
        /// These project names are automatically considered first-party
        /// </summary>
        public void AddProjectsFromSolution(IEnumerable<string> projectNames)
        {
            foreach (var name in projectNames ?? Enumerable.Empty<string>())
            {
                if (!string.IsNullOrWhiteSpace(name))
                {
                    _firstPartyProjectNames.Add(name);
                    Console.WriteLine($"[PackageCategorizer] Auto-discovered first-party project: {name}");
                }
            }
        }

        /// <summary>
        /// Load optional first-party configuration from .env
        /// Format: "Package1,Package2,Package3"
        /// </summary>
        public void LoadConfigurationFromEnv()
        {
            // Load exact package names
            var exactPackages = Config.Get("FIRST_PARTY_PACKAGES", "");
            if (!string.IsNullOrWhiteSpace(exactPackages))
            {
                foreach (var pkg in exactPackages.Split(','))
                {
                    var trimmed = pkg.Trim();
                    if (!string.IsNullOrWhiteSpace(trimmed))
                    {
                        _firstPartyExactPackages.Add(trimmed);
                        Console.WriteLine($"[PackageCategorizer] Configured first-party package: {trimmed}");
                    }
                }
            }

            // Load prefixes
            var prefixes = Config.Get("FIRST_PARTY_PREFIXES", "");
            if (!string.IsNullOrWhiteSpace(prefixes))
            {
                foreach (var prefix in prefixes.Split(','))
                {
                    var trimmed = prefix.Trim();
                    if (!string.IsNullOrWhiteSpace(trimmed))
                    {
                        _firstPartyPackagePrefixes.Add(trimmed);
                        Console.WriteLine($"[PackageCategorizer] Configured first-party prefix: {trimmed}");
                    }
                }
            }
        }

        /// <summary>
        /// Categorize a package based on name and metadata
        /// </summary>
        public PackageType CategorizePackage(string packageName, string? source = null)
        {
            if (string.IsNullOrWhiteSpace(packageName))
                return PackageType.Unknown;

            // Check if exact match with project name (highest priority)
            if (_firstPartyProjectNames.Contains(packageName))
            {
                return PackageType.FirstPartyInternal;
            }

            // Check if exact match with configured first-party packages
            if (_firstPartyExactPackages.Contains(packageName))
            {
                return PackageType.FirstPartyInternal;
            }

            // Check if matches any first-party prefix
            foreach (var prefix in _firstPartyPackagePrefixes)
            {
                if (packageName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return PackageType.FirstPartyInternal;
                }
            }

            // Check for local file references
            if ((source ?? "").StartsWith("../", StringComparison.OrdinalIgnoreCase) ||
                (source ?? "").StartsWith("..", StringComparison.OrdinalIgnoreCase))
            {
                return PackageType.ThirdPartyLocal;
            }

            // Default: from NuGet (most common open source packages)
            return PackageType.NuGet;
        }

        /// <summary>
        /// Categorize package with additional metadata context
        /// </summary>
        public PackageType CategorizePackage(string packageName, JsonElement? metadata = null)
        {
            string? source = null;

            if (metadata.HasValue && metadata.Value.ValueKind == System.Text.Json.JsonValueKind.Object)
            {
                try
                {
                    if (metadata.Value.TryGetProperty("path", out var pathElem) && 
                        pathElem.ValueKind == System.Text.Json.JsonValueKind.String)
                    {
                        source = pathElem.GetString();
                    }
                }
                catch { }
            }

            return CategorizePackage(packageName, source);
        }

        /// <summary>
        /// Get human-readable source description for package category
        /// </summary>
        public string GetSourceDescription(PackageType type)
        {
            return type switch
            {
                PackageType.NuGet => "Open Source (nuget.org)",
                PackageType.FirstPartyInternal => "First-Party (Internal)",
                PackageType.ThirdPartyLocal => "Third-Party (Local File)",
                PackageType.ThirdPartyCustom => "Third-Party (Custom)",
                PackageType.Unknown => "Unknown Source",
                _ => "Unknown"
            };
        }

        /// <summary>
        /// Get count of packages by type in a collection
        /// </summary>
        public Dictionary<PackageType, int> CountByType(IEnumerable<(string name, PackageType type)> packages)
        {
            return packages
                .GroupBy(p => p.type)
                .ToDictionary(g => g.Key, g => g.Count());
        }

        /// <summary>
        /// Check if package is from known public sources (NuGet)
        /// </summary>
        public bool IsPublicSourcePackage(PackageType type)
        {
            return type == PackageType.NuGet;
        }

        /// <summary>
        /// Check if package is internal to organization
        /// </summary>
        public bool IsFirstPartyPackage(PackageType type)
        {
            return type == PackageType.FirstPartyInternal;
        }

        /// <summary>
        /// Get summary of what's considered first-party
        /// </summary>
        public string GetCategorizationSummary()
        {
            var summary = new System.Text.StringBuilder();
            summary.AppendLine("[PackageCategorizer] First-Party Detection Rules:");
            summary.AppendLine($"  Auto-discovered projects: {_firstPartyProjectNames.Count}");
            if (_firstPartyProjectNames.Count > 0)
            {
                summary.AppendLine($"    {string.Join(", ", _firstPartyProjectNames.Take(5))}");
                if (_firstPartyProjectNames.Count > 5)
                    summary.AppendLine($"    ... and {_firstPartyProjectNames.Count - 5} more");
            }

            summary.AppendLine($"  Configured exact packages: {_firstPartyExactPackages.Count}");
            summary.AppendLine($"  Configured prefixes: {_firstPartyPackagePrefixes.Count}");
            
            return summary.ToString();
        }
    }
}
