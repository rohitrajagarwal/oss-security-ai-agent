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

            // Try to load api_key.env first, then .env
            var apiKeyEnvPath = Path.Combine(basePath, "api_key.env");
            var envPath = Path.Combine(basePath, ".env");

            if (File.Exists(apiKeyEnvPath))
                ParseEnvFile(apiKeyEnvPath);

            if (File.Exists(envPath))
                ParseEnvFile(envPath);

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
    public static string ModelName => Get("MODEL_NAME", "gpt-4.1-nano");
    public static string ModelVersion => Get("MODEL_VERSION", "latest");
    public static double ModelTemperature => GetDouble("MODEL_TEMPERATURE", 0.1);
    public static int ModelMaxTokens => GetInt("MODEL_MAX_TOKENS", 300);

    // API Configuration Properties
    public static string ApiUrl => Get("COPILOT_API_URL", "https://api.openai.com/v1/chat/completions");
    public static string? ApiKey => Get("COPILOT_API_KEY") ?? Get("OPENAI_API_KEY");
    public static int ApiTimeout => GetInt("API_TIMEOUT", 15);
    public static int PackageFetchTimeout => GetInt("PACKAGE_FETCH_TIMEOUT", 30);
    public static int OsvApiTimeout => GetInt("OSV_API_TIMEOUT", 10);

    // Prompt Configuration Properties
    public static string SystemPrompt => Get("SYSTEM_PROMPT") ?? throw new InvalidOperationException("SYSTEM_PROMPT environment variable is required");

    // GitHub Configuration
    public static string? GitHubToken => Get("GITHUB_TOKEN");

    public static string? GitHubRepositoryUrl => Get("GITHUB_REPOSITORY_URL");

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
}
