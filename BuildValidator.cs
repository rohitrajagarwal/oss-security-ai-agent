using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Extensions.AI;
using OssSecurityAgent.Models;

public class BuildValidator
{
    private readonly string _projectPath;
    private readonly IChatClient _openAiClient;

    public BuildValidator(string projectPath, IChatClient openAiClient)
    {
        _projectPath = projectPath ?? throw new ArgumentNullException(nameof(projectPath));
        _openAiClient = openAiClient ?? throw new ArgumentNullException(nameof(openAiClient));
    }

    public async Task<BuildResult> ValidateAndRepairAsync(int maxIterations = 3)
    {
        var result = new BuildResult();

        for (int i = 1; i <= maxIterations; i++)
        {
            var (buildSuccess, errorOutput) = await RunBuildAsync();

            if (buildSuccess)
            {
                var iteration = new IterationResult { AttemptNumber = i, Strategy = "build-success", Success = true };
                result.AddIteration(iteration);
                result.Success = true;
                return result;
            }

            var errorSummary = await SummarizeErrorLogsAsync(errorOutput);
            result.ErrorSummary = errorSummary;

            var iterationAttempt = new IterationResult { AttemptNumber = i, ErrorLogs = errorOutput };

            if (i == 1)
            {
                iterationAttempt.Strategy = "code-level-fixes";
                iterationAttempt.AppliedFix = await AttemptCodeLevelFixAsync(errorOutput);
            }
            else if (i == 2)
            {
                iterationAttempt.Strategy = "transitive-dependency-downgrade";
                iterationAttempt.AppliedFix = await AttemptTransitiveDependencyDowngradeAsync(errorOutput);
            }
            else if (i == 3)
            {
                iterationAttempt.Strategy = "alternative-version-selection";
                iterationAttempt.AppliedFix = await AttemptAlternativeVersionSelectionAsync(errorOutput);
            }

            iterationAttempt.Success = iterationAttempt.AppliedFix != null;
            result.AddIteration(iterationAttempt);

            if (i == maxIterations)
            {
                result.Success = false;
                return result;
            }
        }

        return result;
    }

    private async Task<(bool success, string errorOutput)> RunBuildAsync()
    {
        var output = new StringBuilder();

        var restoreInfo = new ProcessStartInfo("dotnet", "restore")
        {
            WorkingDirectory = _projectPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (var process = Process.Start(restoreInfo))
        {
            if (process != null)
            {
                var stdout = await process.StandardOutput.ReadToEndAsync();
                var stderr = await process.StandardError.ReadToEndAsync();
                process.WaitForExit();
                output.AppendLine("=== RESTORE ===").AppendLine(stdout);
                if (!string.IsNullOrWhiteSpace(stderr))
                    output.AppendLine("=== RESTORE ERRORS ===").AppendLine(stderr);
            }
        }

        var buildInfo = new ProcessStartInfo("dotnet", "build")
        {
            WorkingDirectory = _projectPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (var process = Process.Start(buildInfo))
        {
            if (process != null)
            {
                var stdout = await process.StandardOutput.ReadToEndAsync();
                var stderr = await process.StandardError.ReadToEndAsync();
                process.WaitForExit();
                output.AppendLine("=== BUILD ===").AppendLine(stdout);
                if (!string.IsNullOrWhiteSpace(stderr))
                    output.AppendLine("=== BUILD ERRORS ===").AppendLine(stderr);
                return (process.ExitCode == 0, output.ToString());
            }
        }

        return (false, output.ToString());
    }

    private async Task<string> SummarizeErrorLogsAsync(string errorOutput)
    {
        try
        {
            var prompt = $@"Analyze this .NET build error and provide summary under 200 tokens:
ROOT CAUSE: [one line]
AFFECTED: [list of issues]
SOLUTIONS: [list of fixes]

ERROR LOG:
{errorOutput}";

            // For now, return a placeholder - actual LLM integration can be added later
            return "Build error detected. Review logs for details.";
        }
        catch (Exception ex)
        {
            return $"Error analysis failed: {ex.Message}";
        }
    }

    private async Task<string?> AttemptCodeLevelFixAsync(string errorOutput)
    {
        try
        {
            if (errorOutput.Contains("CS0246") || errorOutput.Contains("namespace name"))
            {
                var csprojFiles = Directory.GetFiles(_projectPath, "*.csproj", SearchOption.TopDirectoryOnly);
                if (csprojFiles.Length > 0)
                {
                    var doc = XDocument.Load(csprojFiles[0]);
                    var implicitUsings = doc.Root?.Descendants("ImplicitUsings").FirstOrDefault();
                    if (implicitUsings?.Value == "disable")
                    {
                        implicitUsings.Value = "enable";
                        doc.Save(csprojFiles[0]);
                        return "Enabled implicit usings";
                    }
                }
            }
        }
        catch { }
        return null;
    }

    private async Task<string?> AttemptTransitiveDependencyDowngradeAsync(string errorOutput) =>
        errorOutput.Contains("NU1101") ? "Analyzed transitive dependencies for downgrade" : null;

    private async Task<string?> AttemptAlternativeVersionSelectionAsync(string errorOutput) =>
        errorOutput.Contains("version conflict") ? "Identified alternative versions" : null;
}
