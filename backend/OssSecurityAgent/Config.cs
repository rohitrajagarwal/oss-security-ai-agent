using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

/// <summary>
/// Configuration loader for environment variables from .env and api_key.env files.
/// Supports reading model, API, and prompt configurations.
/// </summary>
public static class Config
{
    private static readonly Dictionary<string, string> _envCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    private static bool _loaded = false;

    /// <summary>
    /// Load configuration from .env and api_key.env files
    /// </summary>
    public static void Load(string? basePath = null)
    {
        if (_loaded) return;

        try
        {
            basePath ??= Directory.GetCurrentDirectory();

            // Try to load from basePath, then search up the directory tree
            var pathsToTry = new List<string> { basePath };
            
            // Also try searching up the directory tree for .env files
            var currentDir = new DirectoryInfo(basePath);
            while (currentDir.Parent != null)
            {
                pathsToTry.Add(currentDir.Parent.FullName);
                currentDir = currentDir.Parent;
            }

            // Try to load api_key.env first, then .env from each path
            foreach (var path in pathsToTry)
            {
                var apiKeyEnvPath = Path.Combine(path, "api_key.env");
                var envPath = Path.Combine(path, ".env");

                if (File.Exists(apiKeyEnvPath))
                    ParseEnvFile(apiKeyEnvPath);

                if (File.Exists(envPath))
                    ParseEnvFile(envPath);
            }

            _loaded = true;
        }
        catch { }
    }

    /// <summary>
    /// Parse a KEY=VALUE format file (ignores comments starting with #)
    /// </summary>
    private static void ParseEnvFile(string path)
    {
        try
        {
            if (!File.Exists(path)) return;

            foreach (var line in File.ReadAllLines(path))
            {
                var trimmed = line.Trim();
                
                // Skip empty lines and comments
                if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
                    continue;

                // Parse KEY=VALUE
                var idx = trimmed.IndexOf('=');
                if (idx <= 0) continue;

                var key = trimmed.Substring(0, idx).Trim();
                var value = trimmed.Substring(idx + 1).Trim().Trim('"', '\'');

                _envCache[key] = value;
            }
        }
        catch { }
    }

    /// <summary>
    /// Get a configuration value with optional default
    /// </summary>
    public static string? Get(string key, string? defaultValue = null)
    {
        Load();

        if (_envCache.TryGetValue(key, out var value) && !string.IsNullOrEmpty(value))
            return value;

        var envValue = Environment.GetEnvironmentVariable(key);
        if (!string.IsNullOrEmpty(envValue))
            return envValue;

        return defaultValue;
    }

    /// <summary>
    /// Get a boolean configuration value
    /// </summary>
    public static bool GetBool(string key, bool defaultValue = false)
    {
        var value = Get(key);
        if (bool.TryParse(value, out var result))
            return result;
        return defaultValue;
    }

    /// <summary>
    /// Get an integer configuration value
    /// </summary>
    public static int GetInt(string key, int defaultValue = 0)
    {
        var value = Get(key);
        if (int.TryParse(value, out var result))
            return result;
        return defaultValue;
    }

    /// <summary>
    /// Get a double configuration value
    /// </summary>
    public static double GetDouble(string key, double defaultValue = 0.0)
    {
        var value = Get(key);
        if (double.TryParse(value, out var result))
            return result;
        return defaultValue;
    }

    /// <summary>
    /// Get a comma-separated list as an array
    /// </summary>
    public static string[] GetArray(string key, params string[] defaultValue)
    {
        var value = Get(key);
        if (string.IsNullOrEmpty(value))
            return defaultValue.Length > 0 ? defaultValue : Array.Empty<string>();

        return value.Split(',').Select(s => s.Trim()).Where(s => !string.IsNullOrEmpty(s)).ToArray();
    }

    // Model Configuration Properties
    public static string ModelName => Get("MODEL_NAME", "gpt-4o")!;
    public static string ModelVersion => Get("MODEL_VERSION", "latest")!;
    public static double ModelTemperature => GetDouble("MODEL_TEMPERATURE", 0.1);
    
    /// <summary>
    /// Get the appropriate max tokens parameter and its value.
    /// Returns tuple of (parameterName, value).
    /// Prefers MAX_COMPLETION_TOKENS if present, otherwise uses MODEL_MAX_TOKENS.
    /// </summary>
    public static (string parameterName, int value) GetMaxTokensParameter()
    {
        var maxCompletionTokens = GetInt("MAX_COMPLETION_TOKENS", 0);
        if (maxCompletionTokens > 0)
        {
            return ("max_completion_tokens", maxCompletionTokens);
        }
        
        var modelMaxTokens = GetInt("MODEL_MAX_TOKENS", 300);
        return ("max_tokens", modelMaxTokens);
    }
    
    public static int ModelMaxTokens => GetInt("MODEL_MAX_TOKENS", 300);

    // API Configuration Properties
    public static string ApiUrl => Get("COPILOT_API_URL", "https://api.openai.com/v1")!;
    public static string? ApiKey => Get("COPILOT_API_KEY") ?? Get("OPENAI_API_KEY");
    public static int ApiTimeout => GetInt("API_TIMEOUT", 15);
    public static int PackageFetchTimeout => GetInt("PACKAGE_FETCH_TIMEOUT", 30);
    public static int OsvApiTimeout => GetInt("OSV_API_TIMEOUT", 10) is var timeout && timeout > 0 ? timeout : 10;

    // Prompt Configuration Properties
    public static string SystemPrompt => Get("SYSTEM_PROMPT") ?? throw new InvalidOperationException("SYSTEM_PROMPT environment variable is required");

    // GitHub Configuration
    public static string? GitHubToken => Get("GITHUB_TOKEN");

    public static List<string> GitHubReviewers
    {
        get
        {
            var reviewersStr = Get("GITHUB_REVIEWERS") ?? string.Empty;
            return reviewersStr.Split(',')
                .Select(r => r.Trim())
                .Where(r => !string.IsNullOrEmpty(r))
                .ToList();
        }
    }

    // AI Recommendation Labels
    public static string[] RecommendationLabels => GetArray("AI_RECOMMENDATION_LABELS", "Upgrade", "Consider", "Monitor", "No action");

    // Solution-Level Scanning Configuration
    public static int MaxParallelProjects => GetInt("MAX_PARALLEL_PROJECTS", 5);
    public static string OutputFormat => Get("OUTPUT_FORMAT", "both")!; // json, console, or both
    public static bool ScanSolutionOnly => GetBool("SCAN_SOLUTION_ONLY", false);

    /// <summary>
    /// Verify and log all loaded configuration parameters for debugging
    /// </summary>
    public static void VerifyConfiguration()
    {
        Load();
        
        Console.WriteLine("\n=== Configuration Verification ===\n");
        
        // Model Configuration
        Console.WriteLine("Model Configuration:");
        Console.WriteLine($"  MODEL_NAME: {ModelName}");
        Console.WriteLine($"  MODEL_VERSION: {ModelVersion}");
        Console.WriteLine($"  MODEL_TEMPERATURE: {ModelTemperature}");
        
        var (maxTokensParamName, maxTokensValue) = GetMaxTokensParameter();
        Console.WriteLine($"  MAX_TOKENS_PARAMETER: {maxTokensParamName}");
        Console.WriteLine($"  MAX_TOKENS_VALUE: {maxTokensValue}");
        
        // Check which parameter is present in env
        var maxCompletionTokensEnv = Get("MAX_COMPLETION_TOKENS");
        var modelMaxTokensEnv = Get("MODEL_MAX_TOKENS");
        Console.WriteLine($"  MAX_COMPLETION_TOKENS (in .env): {(string.IsNullOrWhiteSpace(maxCompletionTokensEnv) ? "NOT SET" : maxCompletionTokensEnv)}");
        Console.WriteLine($"  MODEL_MAX_TOKENS (in .env): {(string.IsNullOrWhiteSpace(modelMaxTokensEnv) ? "NOT SET" : modelMaxTokensEnv)}");
        
        // API Configuration
        Console.WriteLine("\nAPI Configuration:");
        Console.WriteLine($"  COPILOT_API_URL: {ApiUrl}");
        Console.WriteLine($"  COPILOT_API_KEY: {(string.IsNullOrWhiteSpace(ApiKey) ? "NOT SET" : "***SET***")}");
        Console.WriteLine($"  API_TIMEOUT: {ApiTimeout}s");
        
        // GitHub Configuration
        Console.WriteLine("\nGitHub Configuration:");
        Console.WriteLine($"  GITHUB_TOKEN: {(string.IsNullOrWhiteSpace(GitHubToken) ? "NOT SET" : "***SET***")}");
        Console.WriteLine($"  GITHUB_REVIEWERS: {(GitHubReviewers.Count > 0 ? string.Join(", ", GitHubReviewers) : "NOT SET")}");
        
        // Summary
        Console.WriteLine("\n=== Verification Summary ===");
        bool isValid = !string.IsNullOrWhiteSpace(ApiKey) && !string.IsNullOrWhiteSpace(ModelName);
        Console.WriteLine($"Configuration Status: {(isValid ? "✓ VALID" : "✗ INVALID")}");
        Console.WriteLine();
    }
}
