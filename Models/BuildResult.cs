using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace OssSecurityAgent.Models
{
    public class IterationResult
    {
        [JsonPropertyName("attemptNumber")]
        public int AttemptNumber { get; set; }

        [JsonPropertyName("strategy")]
        public string Strategy { get; set; } = string.Empty;

        [JsonPropertyName("errorLogs")]
        public string ErrorLogs { get; set; } = string.Empty;

        [JsonPropertyName("appliedFix")]
        public string? AppliedFix { get; set; }

        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("timestamp")]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    public class BuildResult
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("iterations")]
        public List<IterationResult> Iterations { get; set; } = new();

        [JsonPropertyName("errorSummary")]
        public string? ErrorSummary { get; set; }

        [JsonPropertyName("totalIterations")]
        public int TotalIterations { get; set; }

        [JsonPropertyName("completedAt")]
        public DateTime CompletedAt { get; set; } = DateTime.UtcNow;

        public void AddIteration(IterationResult iteration)
        {
            Iterations.Add(iteration);
            TotalIterations = Iterations.Count;
        }

        public override string ToString() =>
            $"Build {(Success ? "SUCCEEDED" : "FAILED")} in {Iterations.Count} iteration(s). Error: {ErrorSummary ?? "None"}";
    }
}
