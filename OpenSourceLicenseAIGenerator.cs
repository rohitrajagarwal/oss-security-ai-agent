using System;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.IO.Compression;
using System.Xml.Linq;
using System.Threading;

public static class OpenSourceLicenseAIGenerator
{
    private static string TrimSuffix(this string str, string suffix)
    {
        if (str.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            return str.Substring(0, str.Length - suffix.Length);
        return str;
    }

    private static bool IsHtmlContent(string content)
    {
        var s = content.TrimStart();
        return s.StartsWith("<!DOCTYPE html", StringComparison.OrdinalIgnoreCase) ||
               s.StartsWith("<html", StringComparison.OrdinalIgnoreCase) ||
               s.Contains("<body", StringComparison.OrdinalIgnoreCase) ||
               s.Contains("<div", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<(List<string> githubUrls, string? licenseUrl)> FetchGitHubUrlsFromNugetAsync(string packageName, string packageVersion, HttpClient http)
    {
        var githubUrls = new List<string>();
        string? licenseUrl = null;
        try
        {
            var registrationUrl = $"https://api.nuget.org/v3/registration5-semver2/{packageName.ToLower()}/{packageVersion}.json";
            var response = await http.GetAsync(registrationUrl);
            if (!response.IsSuccessStatusCode)
                return (githubUrls, licenseUrl);

            var json = await response.Content.ReadAsStringAsync();
            try
            {
                using var doc = JsonDocument.Parse(json);
                void Search(JsonElement el)
                {
                    if (el.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var prop in el.EnumerateObject())
                        {
                            var name = prop.Name ?? string.Empty;
                            if (string.Equals(name, "repositoryUrl", StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(name, "projectUrl", StringComparison.OrdinalIgnoreCase))
                            {
                                var v = prop.Value.GetString();
                                if (!string.IsNullOrWhiteSpace(v) && v.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                                    githubUrls.Add(v);
                            }
                            else if (string.Equals(name, "licenseUrl", StringComparison.OrdinalIgnoreCase))
                            {
                                var v = prop.Value.GetString();
                                if (!string.IsNullOrWhiteSpace(v))
                                {
                                    licenseUrl = v;
                                    if (packageName == "Microsoft.CSharp")
                                        Console.WriteLine($"[DEBUG NuGet] Found licenseUrl for {packageName}: {v}");
                                    if (v.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                                        githubUrls.Add(v);
                                }
                            }

                            Search(prop.Value);
                        }
                    }
                    else if (el.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var item in el.EnumerateArray()) Search(item);
                    }
                }

                Search(doc.RootElement);
            }
            catch { }
        }
        catch { }

        return (githubUrls.Distinct(StringComparer.OrdinalIgnoreCase).ToList(), licenseUrl);
    }
    
    private static async Task<string?> FetchPackageLicenseAsync(string packageName, string packageVersion)
    {
        var handler = new HttpClientHandler { AllowAutoRedirect = true };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        
        if (packageName == "Microsoft.CSharp")
            Console.WriteLine($"[DEBUG] FetchPackageLicense called for {packageName} {packageVersion}");
        
        var spdxIdentifiers = new[] { "MIT", "Apache-2.0", "GPL", "BSD", "ISC", "Apache", "GPL-3.0", "LGPL", "MPL" };
        
        try
        {
            var nupkgUrl = $"https://api.nuget.org/v3-flatcontainer/{packageName.ToLower()}/{packageVersion}/{packageName.ToLower()}.{packageVersion}.nupkg";
            var nupkgData = await http.GetByteArrayAsync(nupkgUrl);
            
            using var ms = new MemoryStream(nupkgData);
            using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
            
            var allLicenseFiles = zip.Entries.Where(e =>
            {
                var name = System.IO.Path.GetFileNameWithoutExtension(e.Name).ToUpperInvariant();
                var ext = System.IO.Path.GetExtension(e.Name).ToUpperInvariant();
                return (name == "LICENSE" || name == "LICENCE" || name == "COPYING") && 
                       (ext == "" || ext == ".TXT" || ext == ".MD");
            }).ToList();
            
            if (packageName == "Microsoft.CSharp")
                Console.WriteLine($"[DEBUG] Found {allLicenseFiles.Count} license files in nupkg");

            if (allLicenseFiles.Any())
            {
                using var reader = new StreamReader(allLicenseFiles[0].Open());
                var text = await reader.ReadToEndAsync();
                if (!string.IsNullOrWhiteSpace(text) && !IsHtmlContent(text))
                    return text.Trim();
            }

            var nuspecFile = zip.Entries.FirstOrDefault(e => e.Name.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase));
            string? spdxIdentifier = null;
            
            if (nuspecFile != null)
            {
                using var reader = new StreamReader(nuspecFile.Open());
                var nuspecContent = await reader.ReadToEndAsync();
                
                try
                {
                    var nuspecXml = XDocument.Parse(nuspecContent);
                    var ns = nuspecXml.Root?.Name.NamespaceName ?? "";
                    
                    var githubUrls = new List<string>();
                    
                    string? nugetLicenseUrl = null;
                    List<string> nugetApiUrls = new List<string>();
                    try
                    {
                        if (packageName == "Microsoft.CSharp")
                            Console.WriteLine($"[DEBUG] Calling FetchGitHubUrlsFromNugetAsync");
                        var nugetResult = await FetchGitHubUrlsFromNugetAsync(packageName, packageVersion, http);
                        nugetApiUrls = nugetResult.githubUrls;
                        nugetLicenseUrl = nugetResult.licenseUrl;
                        if (packageName == "Microsoft.CSharp")
                            Console.WriteLine($"[DEBUG] FetchGitHubUrlsFromNugetAsync returned: {nugetApiUrls.Count} urls, licenseUrl={nugetLicenseUrl}");
                    }
                    catch (Exception ex)
                    {
                        if (packageName == "Microsoft.CSharp")
                            Console.WriteLine($"[DEBUG] FetchGitHubUrlsFromNugetAsync failed: {ex.Message}");
                    }
                    githubUrls.AddRange(nugetApiUrls);
                    
                    var projectUrl = nuspecXml.Descendants(XName.Get("projectUrl", ns)).FirstOrDefault()?.Value ??
                                    nuspecXml.Descendants(XName.Get("projectUrl", "")).FirstOrDefault()?.Value;
                    if (!string.IsNullOrWhiteSpace(projectUrl) && projectUrl.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                        githubUrls.Add(projectUrl);
                    
                    var repoUrl = nuspecXml.Descendants(XName.Get("repository", ns)).FirstOrDefault()?.Value ??
                                 nuspecXml.Descendants(XName.Get("repository", "")).FirstOrDefault()?.Value;
                    if (!string.IsNullOrWhiteSpace(repoUrl) && repoUrl.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                        githubUrls.Add(repoUrl);
                    
                    var repoUrlAttr = nuspecXml.Descendants(XName.Get("repository", ns)).FirstOrDefault()?.Attribute("url")?.Value ??
                                     nuspecXml.Descendants(XName.Get("repository", "")).FirstOrDefault()?.Attribute("url")?.Value;
                    if (!string.IsNullOrWhiteSpace(repoUrlAttr) && repoUrlAttr.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                        githubUrls.Add(repoUrlAttr);
                    
                    // STEP 1: Try each GitHub repository URL found
                    foreach (var url in githubUrls.Where(u => !string.IsNullOrWhiteSpace(u)))
                    {
                        var licenseFromGithub = await FetchGithubLicenseAsync(url, http);
                        if (!string.IsNullOrWhiteSpace(licenseFromGithub) && !IsHtmlContent(licenseFromGithub))
                            return licenseFromGithub;
                    }

                    // STEP 2: If no repository link found, try licenseUrl from NuGet registration JSON
                    if (!string.IsNullOrWhiteSpace(nugetLicenseUrl))
                    {
                        Console.WriteLine($"[DEBUG STEP2] nugetLicenseUrl: {nugetLicenseUrl}");
                        if (nugetLicenseUrl.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                        {
                            Console.WriteLine($"[DEBUG STEP2] URL contains github.com, calling FetchGithubLicenseAsync");
                            var licenseFromGithubUrl = await FetchGithubLicenseAsync(nugetLicenseUrl, http);
                            if (!string.IsNullOrWhiteSpace(licenseFromGithubUrl) && !IsHtmlContent(licenseFromGithubUrl))
                                return licenseFromGithubUrl;
                        }
                        else
                        {
                            try
                            {
                                Console.WriteLine($"[DEBUG STEP2] URL does not contain github.com, following redirect");
                                // Use GET request to follow redirects and get final location
                                var request = new HttpRequestMessage(HttpMethod.Get, nugetLicenseUrl);
                                var response = await http.SendAsync(request);
                                var finalUrl = response.RequestMessage?.RequestUri?.ToString() ?? nugetLicenseUrl;
                                Console.WriteLine($"[DEBUG STEP2] After redirect: {finalUrl}");
                                
                                // If redirect led to GitHub, use GitHub handler
                                if (finalUrl.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                                {
                                    Console.WriteLine($"[DEBUG STEP2] Redirected to github.com, calling FetchGithubLicenseAsync");
                                    var licenseFromGithub = await FetchGithubLicenseAsync(finalUrl, http);
                                    if (!string.IsNullOrWhiteSpace(licenseFromGithub) && !IsHtmlContent(licenseFromGithub))
                                        return licenseFromGithub;
                                }
                                else if (response.IsSuccessStatusCode)
                                {
                                    // Otherwise fetch content if successful
                                    var fetched = await response.Content.ReadAsStringAsync();
                                    if (!string.IsNullOrWhiteSpace(fetched) && fetched.Length > 100 && !IsHtmlContent(fetched))
                                        return fetched.Trim();
                                }
                            }
                            catch { }
                        }
                    }
                    
                    // STEP 3: Try <licenseUrl> tag from nuspec
                    var licenseUrlElement = nuspecXml.Descendants(XName.Get("licenseUrl", ns)).FirstOrDefault() ??
                                           nuspecXml.Descendants(XName.Get("licenseUrl", "")).FirstOrDefault();
                    if (licenseUrlElement != null)
                    {
                        var licenseUrlValue = licenseUrlElement.Value?.Trim();
                        if (!string.IsNullOrWhiteSpace(licenseUrlValue) && licenseUrlValue.StartsWith("http"))
                        {
                            if (packageName == "Microsoft.CSharp")
                                Console.WriteLine($"[DEBUG STEP3] Found licenseUrl in nuspec: {licenseUrlValue}");
                            
                            if (licenseUrlValue.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                            {
                                var licenseFromGithub = await FetchGithubLicenseAsync(licenseUrlValue, http);
                                if (!string.IsNullOrWhiteSpace(licenseFromGithub) && !IsHtmlContent(licenseFromGithub))
                                    return licenseFromGithub;
                            }
                            else
                            {
                                try
                                {
                                    // Follow redirects and check if final URL is GitHub
                                    var request = new HttpRequestMessage(HttpMethod.Get, licenseUrlValue);
                                    var response = await http.SendAsync(request);
                                    var finalUrl = response.RequestMessage?.RequestUri?.ToString() ?? licenseUrlValue;
                                    
                                    if (packageName == "Microsoft.CSharp")
                                        Console.WriteLine($"[DEBUG STEP3] After redirect: {finalUrl}");
                                    
                                    if (finalUrl.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                                    {
                                        var licenseFromGithub = await FetchGithubLicenseAsync(finalUrl, http);
                                        if (!string.IsNullOrWhiteSpace(licenseFromGithub) && !IsHtmlContent(licenseFromGithub))
                                            return licenseFromGithub;
                                    }
                                    else if (response.IsSuccessStatusCode)
                                    {
                                        var fetched = await response.Content.ReadAsStringAsync();
                                        if (!string.IsNullOrWhiteSpace(fetched) && fetched.Length > 100 && !IsHtmlContent(fetched))
                                            return fetched.Trim();
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                    
                    // STEP 4: Try <license> tag (new format - can be inline or URL)
                    var licenseElement = nuspecXml.Descendants(XName.Get("license", ns)).FirstOrDefault() ??
                                        nuspecXml.Descendants(XName.Get("license", "")).FirstOrDefault();
                    if (licenseElement != null)
                    {
                        var licenseText = licenseElement.Value?.Trim();
                        if (!string.IsNullOrWhiteSpace(licenseText))
                        {
                            if (licenseText.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                            {
                                if (licenseText.Contains("github.com", StringComparison.OrdinalIgnoreCase))
                                {
                                    var licenseFromGithub = await FetchGithubLicenseAsync(licenseText, http);
                                    if (!string.IsNullOrWhiteSpace(licenseFromGithub) && !IsHtmlContent(licenseFromGithub))
                                        return licenseFromGithub;
                                }
                                else
                                {
                                    try
                                    {
                                        var fetched = await http.GetStringAsync(licenseText);
                                        if (!string.IsNullOrWhiteSpace(fetched) && fetched.Length > 100 && !IsHtmlContent(fetched))
                                            return fetched.Trim();
                                    }
                                    catch { }
                                }
                            }
                            else if (licenseText.Length > 100)
                            {
                                return licenseText;
                            }
                            else
                            {
                                spdxIdentifier = licenseText;
                            }
                        }
                    }
                    
                    if (!string.IsNullOrWhiteSpace(spdxIdentifier))
                        return spdxIdentifier;
                }
                catch { }
            }
        }
        catch { }
        
        return null;
    }

    private static async Task<string?> FetchGithubLicenseAsync(string repoUrl, HttpClient http)
    {
        try
        {
            var githubToken = Environment.GetEnvironmentVariable("GITHUB_TOKEN") ?? 
                            GetApiKeyFromEnvFile("GITHUB_TOKEN");
            
            // Check if URL is already a raw GitHub file URL (raw.githubusercontent.com)
            if (repoUrl.Contains("raw.githubusercontent.com"))
            {
                try
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, repoUrl);
                    if (!string.IsNullOrWhiteSpace(githubToken))
                        request.Headers.Add("Authorization", $"token {githubToken}");
                    
                    var response = await http.SendAsync(request);
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        if (!string.IsNullOrWhiteSpace(content))
                            return content.Trim();
                    }
                }
                catch { }
                return null;
            }
            
            // Check if URL is a GitHub web URL pointing to a file (github.com/.../.../.../blob/...)
            var blobMatch = System.Text.RegularExpressions.Regex.Match(repoUrl, @"github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$");
            if (blobMatch.Success)
            {
                // Simply append ?raw=true to get raw content directly
                var rawUrl = repoUrl + "?raw=true";
                Console.WriteLine($"[DEBUG] Fetching blob URL with ?raw=true: {rawUrl}");
                try
                {
                    var request = new HttpRequestMessage(HttpMethod.Get, rawUrl);
                    if (!string.IsNullOrWhiteSpace(githubToken))
                        request.Headers.Add("Authorization", $"token {githubToken}");
                    
                    var response = await http.SendAsync(request);
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        Console.WriteLine($"[DEBUG] Blob URL response: {response.StatusCode}, content length: {content?.Length ?? 0}");
                        if (!string.IsNullOrWhiteSpace(content))
                            return content.Trim();
                    }
                    else
                    {
                        Console.WriteLine($"[DEBUG] Blob URL failed: {response.StatusCode}");
                    }
                }
                catch (Exception ex) 
                { 
                    Console.WriteLine($"[DEBUG] Blob URL error: {ex.Message}");
                }
            }
            
            // Otherwise, treat as repository URL and search for license files
            var match = System.Text.RegularExpressions.Regex.Match(repoUrl, @"github\.com/([^/]+)/([^/?\#]+)");
            if (match.Success)
            {
                var owner = match.Groups[1].Value;
                var repo = match.Groups[2].Value.TrimEnd('/').TrimSuffix(".git");
                
                var licenseFileNames = new[] 
                { 
                    "LICENSE", 
                    "License.txt",
                    "LICENSE.txt", 
                    "license.txt",
                    "LICENSE.TXT",
                    "LICENSE.md", 
                    "License.md",
                    "license.md",
                    "license",
                    "LICENCE", 
                    "LICENCE.txt",
                    "licence.txt",
                    "COPYING", 
                    "COPYING.md",
                    "COPYING.txt",
                    "copying.txt",
                    "LICENSE.rst",
                    "license.rst",
                    "license-information.md",
                    "LICENSE-INFORMATION.md"
                };
                
                var branches = new[] { "main", "master", "develop", "dev" };
                
                foreach (var branch in branches)
                {
                    foreach (var fileName in licenseFileNames)
                    {
                        var licenseUrl = $"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{fileName}";
                        try
                        {
                            var request = new HttpRequestMessage(HttpMethod.Get, licenseUrl);
                            if (!string.IsNullOrWhiteSpace(githubToken))
                            {
                                request.Headers.Add("Authorization", $"token {githubToken}");
                            }
                            
                            var response = await http.SendAsync(request);
                            if (response.IsSuccessStatusCode)
                            {
                                var content = await response.Content.ReadAsStringAsync();
                                if (!string.IsNullOrWhiteSpace(content))
                                    return content.Trim();
                            }
                        }
                        catch { }
                    }
                }
            }
        }
        catch { }
        
        return null;
    }
    
    private static string? GetApiKeyFromEnvFile(string key)
    {
        try
        {
            var envFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "api_key.env");
            if (!File.Exists(envFilePath))
                envFilePath = Path.Combine(Directory.GetCurrentDirectory(), "api_key.env");
            
            if (File.Exists(envFilePath))
            {
                var lines = File.ReadAllLines(envFilePath);
                var line = lines.FirstOrDefault(l => l.StartsWith($"{key}="));
                if (!string.IsNullOrEmpty(line))
                {
                    var parts = line.Split('=', 2);
                    if (parts.Length == 2)
                        return parts[1].Trim();
                }
            }
        }
        catch { }
        return null;
    }

    public static async Task<string> GenerateWithAIAsync(string repoPath)
    {
        if (string.IsNullOrWhiteSpace(repoPath) || !Directory.Exists(repoPath))
            throw new ArgumentException("repoPath must be a valid directory");

        var projFiles = Directory.GetFiles(repoPath, "*.csproj", SearchOption.AllDirectories);
        if (projFiles.Length == 0)
            throw new InvalidOperationException("No .csproj files found under repoPath");

        var packages = SecurityAgentTools.GetProjectDependencies(projFiles[0])
                        .Select(p => (name: p.packageName, version: p.version))
                        .Distinct()
                        .OrderBy(p => p.name, StringComparer.OrdinalIgnoreCase)
                        .ToList();

        if (!packages.Any())
            throw new InvalidOperationException("No packages discovered by GetProjectDependencies");

        Console.WriteLine("Fetching license texts from NuGet packages...");
        var licenseMap = new Dictionary<string, string>();
        using (var semaphore = new SemaphoreSlim(3))
        {
            var tasks = packages.Select(async pkg =>
            {
                await semaphore.WaitAsync();
                try
                {
                    var licenseText = await FetchPackageLicenseAsync(pkg.name, pkg.version);
                    if (!string.IsNullOrWhiteSpace(licenseText))
                    {
                        var key = $"{pkg.name} {pkg.version}";
                        licenseMap[key] = licenseText.Trim();
                        Console.WriteLine($"  ✓ Fetched license for {pkg.name} {pkg.version}");
                    }
                    else
                    {
                        licenseMap[$"{pkg.name} {pkg.version}"] = "LICENSE TEXT NOT FOUND";
                        Console.WriteLine($"  ✗ No license found for {pkg.name} {pkg.version}");
                    }
                }
                catch (Exception ex)
                {
                    licenseMap[$"{pkg.name} {pkg.version}"] = "LICENSE TEXT NOT FOUND";
                    Console.WriteLine($"  ✗ Error fetching {pkg.name} {pkg.version}: {ex.Message}");
                }
                finally
                {
                    semaphore.Release();
                }
            });
            
            await Task.WhenAll(tasks);
        }

        var docBuilder = new StringBuilder();
        docBuilder.AppendLine("THIRD-PARTY SOFTWARE NOTICES AND INFORMATION");
        docBuilder.AppendLine();
        docBuilder.AppendLine("Do Not Translate or Localize");
        docBuilder.AppendLine();
        docBuilder.AppendLine("This project incorporates components from the projects listed below. The original copyright notices and the licenses under which Microsoft or the applicable third party licensed such components to you are set forth below. Microsoft reserves all rights not expressly granted herein, whether by implication, estoppel or otherwise.");
        docBuilder.AppendLine();

        var licensesDir = Path.Combine(repoPath, "licenses");
        Directory.CreateDirectory(licensesDir);

        foreach (var (pkgVersion, licenseText) in licenseMap)
        {
            docBuilder.AppendLine(pkgVersion);
            docBuilder.AppendLine(licenseText);
            docBuilder.AppendLine();
        }

        var fileName = $"open-source-license-{DateTime.UtcNow:yyyyMMddHHmmss}.txt";
        var outPath = Path.Combine(licensesDir, fileName);
        await File.WriteAllTextAsync(outPath, docBuilder.ToString(), Encoding.UTF8);

        return outPath;
    }
}
