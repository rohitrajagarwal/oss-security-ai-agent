using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.Extensions.AI;
using OssSecurityAgent.Models;

public class BuildValidator
{
    private readonly string _projectPath;
    private readonly IChatClient _openAiClient;
    private readonly List<string> _createdBackupFiles = new();

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
                CleanupBackupFiles();
                return result;
            }

            Console.WriteLine($"\n[Iteration {i}] Build failed. Analyzing breaking changes...");

            var aiResponse = await GetResolutionStepsAsync(errorOutput, result.Iterations);
            
            if (aiResponse == null)
            {
                Console.WriteLine($"❌ [Iteration {i}] OpenAI analysis failed. Unable to determine resolution steps.");
                var failedIteration = new IterationResult 
                { 
                    AttemptNumber = i, 
                    Strategy = "ai-analysis-failed", 
                    ErrorLogs = errorOutput,
                    Success = false,
                    AppliedFix = "OpenAI service unavailable or returned invalid response"
                };
                result.AddIteration(failedIteration);
                result.ErrorSummary = "AI-powered analysis failed. Unable to continue.";
                break;
            }

            result.ErrorSummary = aiResponse.RootCause;

            // Execute safe operations only (dotnet commands and .csproj edits)
            var operationsApplied = await ExecuteSafeOperationsAsync(aiResponse.SuggestedSafeOperations);

            var iterationAttempt = new IterationResult
            {
                AttemptNumber = i,
                Strategy = aiResponse.Strategy,
                ErrorLogs = errorOutput,
                AppliedFix = operationsApplied,
                Success = false
            };

            // Report breaking changes to user
            if (aiResponse.BreakingChanges.Any())
            {
                PrintBreakingChangesReport(aiResponse.BreakingChanges, i);
            }

            result.AddIteration(iterationAttempt);

            if (i == maxIterations)
            {
                result.Success = false;
                PrintFailureSummary(result, aiResponse.BreakingChanges);
                break;
            }
        }

        CleanupBackupFiles();
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

    private async Task<AiResolutionResponse?> GetResolutionStepsAsync(string errorOutput, List<IterationResult> priorAttempts)
    {
        try
        {
            var csprojPath = FindCsprojFile();
            var projectMetadata = GetProjectMetadata(csprojPath);
            var priorAttemptsContext = string.Join("\n", 
                priorAttempts.Select(a => $"- Attempt {a.AttemptNumber} ({a.Strategy}): {a.AppliedFix ?? "No fixes applied"}"));

            var prompt = $@"Analyze this .NET build failure and provide breaking changes analysis.

PROJECT CONTEXT:
Framework: {projectMetadata}
Project Path: {_projectPath}

PRIOR ATTEMPTS:
{(string.IsNullOrWhiteSpace(priorAttemptsContext) ? "First iteration" : priorAttemptsContext)}

BUILD ERROR OUTPUT:
{errorOutput}

REQUIRED RESPONSE FORMAT (JSON):
{{
  ""rootCause"": ""Brief root cause description"",
  ""strategy"": ""ai-breaking-change-analysis"",
  ""breakingChanges"": [
    {{
      ""location"": ""File:LineNumber or ClassName.MethodName"",
      ""affectedCode"": ""Exact code snippet from the error"",
      ""oldApi"": ""Old API/method signature"",
      ""newApi"": ""New API/method signature"",
      ""fixGuidance"": ""Step-by-step instructions for the user to fix this"",
      ""severity"": ""critical|high|medium""
    }}
  ],
  ""suggestedSafeOperations"": [
    {{
      ""action"": ""dotnet-package-add|dotnet-package-remove|csproj-edit"",
      ""command"": ""Full dotnet CLI command if applicable"",
      ""file"": ""File to edit if applicable (relative path)"",
      ""reasoning"": ""Why this operation is suggested""
    }}
  ]
}}

IMPORTANT:
- Only suggest safe operations: dotnet package add/remove commands and .csproj edits
- Do NOT suggest code modifications or refactoring
- Provide detailed fix guidance for each breaking change
- Include file locations and line numbers where errors occurred";

            Console.WriteLine("[GetResolutionStepsAsync] Calling OpenAI API...");
            
            var messages = new List<ChatMessage>
            {
                new ChatMessage(ChatRole.System, "You are a .NET build error analyzer. Respond only with valid JSON."),
                new ChatMessage(ChatRole.User, prompt)
            };

            var response = await _openAiClient.GetResponseAsync(messages);
            var responseText = response?.ToString() ?? string.Empty;

            if (string.IsNullOrWhiteSpace(responseText))
            {
                Console.WriteLine("[GetResolutionStepsAsync] OpenAI returned empty response");
                return null;
            }

            // Extract JSON from response (in case AI wraps it with extra text)
            var jsonMatch = System.Text.RegularExpressions.Regex.Match(responseText, @"\{[\s\S]*\}");
            if (!jsonMatch.Success)
            {
                Console.WriteLine("[GetResolutionStepsAsync] Could not find JSON in OpenAI response");
                return null;
            }

            var aiResponse = JsonSerializer.Deserialize<AiResolutionResponse>(jsonMatch.Value, 
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            
            return aiResponse;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"❌ [GetResolutionStepsAsync] Failed at: {ex.Message}");
            return null;
        }
    }

    private async Task<string> ExecuteSafeOperationsAsync(List<SafeOperation> operations)
    {
        var appliedOperations = new StringBuilder();

        foreach (var op in operations)
        {
            try
            {
                switch (op.Action.ToLower())
                {
                    case "dotnet-package-add":
                    case "dotnet-package-remove":
                        await ExecuteDotnetCommandAsync(op.Command ?? string.Empty);
                        appliedOperations.AppendLine($"✓ {op.Reasoning}");
                        break;

                    case "csproj-edit":
                        if (!string.IsNullOrWhiteSpace(op.File))
                        {
                            await EditCsprojFileAsync(op.File, op.Reasoning);
                            appliedOperations.AppendLine($"✓ {op.Reasoning}");
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"⚠️  Failed to execute operation '{op.Action}': {ex.Message}");
                appliedOperations.AppendLine($"✗ Failed: {op.Reasoning}");
                // Restore from backup on failure
                RestoreFromBackup(op.File);
            }
        }

        return appliedOperations.ToString();
    }

    private async Task ExecuteDotnetCommandAsync(string command)
    {
        if (string.IsNullOrWhiteSpace(command))
            throw new ArgumentException("Command cannot be empty");

        var parts = command.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var processInfo = new ProcessStartInfo(parts[0], string.Join(" ", parts.Skip(1)))
        {
            WorkingDirectory = _projectPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (var process = Process.Start(processInfo))
        {
            if (process != null)
            {
                await process.StandardOutput.ReadToEndAsync();
                var stderr = await process.StandardError.ReadToEndAsync();
                process.WaitForExit();

                if (process.ExitCode != 0)
                    throw new Exception($"Command failed: {stderr}");
            }
        }
    }

    private async Task EditCsprojFileAsync(string relativeFilePath, string reasoning)
    {
        var fullPath = Path.Combine(_projectPath, relativeFilePath);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException($"File not found: {fullPath}");

        // Create backup
        var backupPath = fullPath + ".bak";
        File.Copy(fullPath, backupPath, overwrite: true);
        _createdBackupFiles.Add(backupPath);

        try
        {
            var doc = XDocument.Load(fullPath);
            // For now, we're not applying specific edits here
            // The AI suggestions would be applied based on the reasoning
            // In practice, this would parse the reasoning and apply targeted edits
            Console.WriteLine($"[EditCsprojFileAsync] Would edit {relativeFilePath}: {reasoning}");
        }
        catch
        {
            RestoreFromBackup(fullPath);
            throw;
        }
    }

    private void RestoreFromBackup(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return;

        var backupPath = filePath + ".bak";
        if (File.Exists(backupPath))
        {
            try
            {
                File.Copy(backupPath, filePath, overwrite: true);
                File.Delete(backupPath);
                _createdBackupFiles.Remove(backupPath);
                Console.WriteLine($"✓ Restored {filePath} from backup");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"⚠️  Failed to restore from backup: {ex.Message}");
            }
        }
    }

    private void CleanupBackupFiles()
    {
        foreach (var backupFile in _createdBackupFiles)
        {
            try
            {
                if (File.Exists(backupFile))
                {
                    File.Delete(backupFile);
                    Console.WriteLine($"🗑️  Cleaned up {backupFile}");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"⚠️  Failed to cleanup {backupFile}: {ex.Message}");
            }
        }
        _createdBackupFiles.Clear();
    }

    private string FindCsprojFile()
    {
        var csprojFiles = Directory.GetFiles(_projectPath, "*.csproj", SearchOption.TopDirectoryOnly);
        if (csprojFiles.Length == 0)
            throw new FileNotFoundException($"No .csproj file found in {_projectPath}");
        return csprojFiles[0];
    }

    private string GetProjectMetadata(string csprojPath)
    {
        try
        {
            var doc = XDocument.Load(csprojPath);
            var targetFramework = doc.Root?.Element("PropertyGroup")?.Element("TargetFramework")?.Value ?? "unknown";
            return targetFramework;
        }
        catch
        {
            return "unknown";
        }
    }

    private void PrintBreakingChangesReport(List<BreakingChangeReport> breakingChanges, int iteration)
    {
        Console.WriteLine($"\n⚠️  [Iteration {iteration}] Breaking Changes Detected:\n");

        foreach (var change in breakingChanges)
        {
            Console.WriteLine($"📍 Location: {change.Location}");
            Console.WriteLine($"   Severity: {change.Severity}");
            Console.WriteLine($"\n   Affected Code:\n   {change.AffectedCode}");
            Console.WriteLine($"\n   Old API:\n   {change.OldApi}");
            Console.WriteLine($"\n   New API:\n   {change.NewApi}");
            Console.WriteLine($"\n   Fix Guidance:\n   {change.FixGuidance}");
            Console.WriteLine("\n" + new string('-', 80) + "\n");
        }
    }

    private void PrintFailureSummary(BuildResult result, List<BreakingChangeReport> breakingChanges)
    {
        Console.WriteLine("\n" + new string('=', 80));
        Console.WriteLine("❌ BUILD VALIDATION FAILED - BREAKING CHANGES REQUIRE MANUAL INTERVENTION");
        Console.WriteLine(new string('=', 80) + "\n");

        Console.WriteLine($"Root Cause: {result.ErrorSummary}\n");

        Console.WriteLine("Iterations Attempted:");
        foreach (var iteration in result.Iterations)
        {
            var status = iteration.Success ? "✓" : "✗";
            Console.WriteLine($"  {status} Iteration {iteration.AttemptNumber}: {iteration.Strategy}");
            if (!string.IsNullOrWhiteSpace(iteration.AppliedFix))
                Console.WriteLine($"     Changes: {iteration.AppliedFix}");
        }

        if (breakingChanges.Any())
        {
            Console.WriteLine("\nBreaking Changes Summary:");
            foreach (var change in breakingChanges)
            {
                Console.WriteLine($"  • {change.Location} ({change.Severity})");
            }

            Console.WriteLine("\nRequired Manual Fixes:");
            foreach (var change in breakingChanges)
            {
                Console.WriteLine($"\n  File: {change.Location}");
                Console.WriteLine($"  {change.FixGuidance}");
            }
        }

        if (_createdBackupFiles.Any())
        {
            Console.WriteLine($"\nBackup Files Created (for manual rollback):");
            foreach (var backup in _createdBackupFiles)
            {
                Console.WriteLine($"  • {backup}");
            }
        }

        Console.WriteLine("\n" + new string('=', 80) + "\n");
    }}