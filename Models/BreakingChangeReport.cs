using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace OssSecurityAgent.Models
{
    public class BreakingChangeReport
    {
        [JsonPropertyName("location")]
        public string Location { get; set; } = string.Empty;

        [JsonPropertyName("affectedCode")]
        public string AffectedCode { get; set; } = string.Empty;

        [JsonPropertyName("oldApi")]
        public string OldApi { get; set; } = string.Empty;

        [JsonPropertyName("newApi")]
        public string NewApi { get; set; } = string.Empty;

        [JsonPropertyName("fixGuidance")]
        public string FixGuidance { get; set; } = string.Empty;

        [JsonPropertyName("severity")]
        public string Severity { get; set; } = "medium";
    }
}
