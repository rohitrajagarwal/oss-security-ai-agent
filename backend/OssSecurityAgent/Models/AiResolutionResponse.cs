using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace OssSecurityAgent.Models
{
    public class SafeOperation
    {
        [JsonPropertyName("action")]
        public string Action { get; set; } = string.Empty;

        [JsonPropertyName("command")]
        public string? Command { get; set; }

        [JsonPropertyName("file")]
        public string? File { get; set; }

        [JsonPropertyName("reasoning")]
        public string Reasoning { get; set; } = string.Empty;
    }

    public class AiResolutionResponse
    {
        [JsonPropertyName("rootCause")]
        public string RootCause { get; set; } = string.Empty;

        [JsonPropertyName("breakingChanges")]
        public List<BreakingChangeReport> BreakingChanges { get; set; } = new();

        [JsonPropertyName("suggestedSafeOperations")]
        public List<SafeOperation> SuggestedSafeOperations { get; set; } = new();

        [JsonPropertyName("strategy")]
        public string Strategy { get; set; } = "ai-analysis";
    }
}
