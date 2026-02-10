using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;

public class GitOperations
{
    private readonly string _repoPath;

    public GitOperations(string repoPath)
    {
        _repoPath = repoPath ?? throw new ArgumentNullException(nameof(repoPath));
    }

    public async Task<(bool success, string output)> CreateBranchAsync(string branchName)
    {
        return await RunGitCommandAsync("checkout", "-b", branchName);
    }

    public async Task<(bool success, string output)> AddChangesAsync(string pattern)
    {
        return await RunGitCommandAsync("add", pattern);
    }

    public async Task<(bool success, string output)> CommitAsync(string message)
    {
        return await RunGitCommandAsync("commit", "-m", message);
    }

    public async Task<(bool success, string output)> PushBranchAsync(string branchName, int maxRetries = 3)
    {
        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            var (success, output) = await RunGitCommandAsync("push", "origin", branchName);
            if (success)
                return (true, output);

            if (attempt < maxRetries)
            {
                Console.WriteLine($"⏳ Push failed (attempt {attempt}/{maxRetries}), retrying...");
                await Task.Delay(2000);
            }
        }

        return (false, "Push failed after 3 retries");
    }

    public async Task<string> GetCurrentBranchAsync()
    {
        var (success, output) = await RunGitCommandAsync("rev-parse", "--abbrev-ref", "HEAD");
        return success ? output.Trim() : string.Empty;
    }

    public async Task<string> GetRepositoryUrlAsync()
    {
        var (success, output) = await RunGitCommandAsync("config", "--get", "remote.origin.url");
        return success ? output.Trim() : string.Empty;
    }

    public async Task<(bool success, string output)> CheckoutBranchAsync(string branchName)
    {
        return await RunGitCommandAsync("checkout", branchName);
    }

    public async Task<(bool success, string output)> ResetHardAsync()
    {
        return await RunGitCommandAsync("reset", "--hard", "HEAD");
    }

    public async Task<(bool success, string output)> CleanAsync()
    {
        return await RunGitCommandAsync("clean", "-fd");
    }

    private async Task<(bool success, string output)> RunGitCommandAsync(params string[] args)
    {
        var processInfo = new ProcessStartInfo("git")
        {
            WorkingDirectory = _repoPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var arg in args)
        {
            processInfo.ArgumentList.Add(arg);
        }

        using (var process = Process.Start(processInfo))
        {
            if (process == null)
                return (false, "Failed to start git process");

            var stdout = await process.StandardOutput.ReadToEndAsync();
            var stderr = await process.StandardError.ReadToEndAsync();
            process.WaitForExit();

            return (process.ExitCode == 0, process.ExitCode == 0 ? stdout : stderr);
        }
    }
}
