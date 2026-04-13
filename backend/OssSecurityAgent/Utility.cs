
class Utility
{

    private static string? GetArgument(string[] args, string flag)
    {
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i].Equals(flag, StringComparison.OrdinalIgnoreCase))
            {
                return args[i + 1];
            }
        }
        return null;
    }
    public static string? ParseRepoPath(string[] args)
    {
       // 2. Parse the --repo argument
        string? repoPath = GetArgument(args, "--repo");

        // 3. Validate Input
        if (string.IsNullOrWhiteSpace(repoPath))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("Error: Missing required argument '--repo'.");
            Console.ResetColor();
            Console.WriteLine("Usage: dotnet run -- --repo <path-to-project>");
            return "";
        }

        if (!Directory.Exists(repoPath))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Error: Directory not found: {repoPath}");
            Console.ResetColor();
            return "";
        }

        return repoPath;
    }


}