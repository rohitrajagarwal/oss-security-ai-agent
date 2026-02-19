using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.AI;

/// <summary>
/// Factory for creating IChatClient instances based on available configuration
/// </summary>
public class ChatClientFactory
{
    public IChatClient? CreateChatClient()
    {
        // Load configuration from environment
        Config.Load();

        var apiKey = Config.ApiKey;
        var apiUrl = Config.ApiUrl;
        var modelName = Config.ModelName;

        // If no API key is available, return null (chat client is optional)
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return null;
        }

        try
        {
            // Extract base URL if full endpoint is provided
            // If ApiUrl ends with /chat/completions, use the base URL instead
            var baseUrl = apiUrl;
            if (baseUrl?.EndsWith("/chat/completions") == true)
            {
                baseUrl = baseUrl.Substring(0, baseUrl.Length - "/chat/completions".Length);
            }
            
            var client = new OpenAiCompatibleChatClient(baseUrl ?? "https://api.openai.com/v1", apiKey, modelName ?? "gpt-4");
            return client;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Failed to create chat client: {ex.Message}");
            return null;
        }
    }
}

/// <summary>
/// A simple OpenAI-compatible IChatClient implementation
/// </summary>
public class OpenAiCompatibleChatClient : IChatClient
{
    private readonly string _apiUrl;
    private readonly string _apiKey;
    private readonly string _modelName;
    private readonly HttpClient _httpClient;

    public OpenAiCompatibleChatClient(string apiUrl, string apiKey, string modelName)
    {
        _apiUrl = apiUrl.TrimEnd('/');
        _apiKey = apiKey;
        _modelName = modelName;
        _httpClient = new HttpClient();
    }

    public async Task<ChatResponse> CompleteAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        try
        {
            var messageList = messages.ToList();
            var request = new
            {
                model = _modelName,
                messages = messageList.Select(m => new
                {
                    role = m.Role == ChatRole.User ? "user" : m.Role == ChatRole.System ? "system" : "assistant",
                    content = m.ToString() // ChatMessage toString gives the content
                }),
                temperature = 0.1,
                max_tokens = 2000
            };

            var requestJson = System.Text.Json.JsonSerializer.Serialize(request);
            var content = new StringContent(requestJson, System.Text.Encoding.UTF8, "application/json");

            _httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _apiKey);

            var response = await _httpClient.PostAsync($"{_apiUrl}/chat/completions", content, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                Console.Error.WriteLine($"OpenAI API error: {response.StatusCode} - {errorContent}");
                return new ChatResponse(new ChatMessage(ChatRole.Assistant, $"Error: {response.StatusCode}"));
            }

            var responseContent = await response.Content.ReadAsStringAsync(cancellationToken);
            var responseData = System.Text.Json.JsonDocument.Parse(responseContent);
            var root = responseData.RootElement;

            if (root.TryGetProperty("choices", out var choicesElement) &&
                choicesElement.GetArrayLength() > 0)
            {
                var firstChoice = choicesElement[0];
                if (firstChoice.TryGetProperty("message", out var messageElement) &&
                    messageElement.TryGetProperty("content", out var textElement))
                {
                    var text = textElement.GetString() ?? string.Empty;
                    return new ChatResponse(new ChatMessage(ChatRole.Assistant, text));
                }
            }

            return new ChatResponse(new ChatMessage(ChatRole.Assistant, "No response from API"));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed to get response from OpenAI: {ex.Message}");
            return new ChatResponse(new ChatMessage(ChatRole.Assistant, $"Error: {ex.Message}"));
        }
    }

    public async IAsyncEnumerable<ChatResponseUpdate> CompleteStreamingAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // Streaming not implemented for now
        yield break;
    }

    public async Task<ChatResponse> GetResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, CancellationToken cancellationToken = default)
    {
        return await CompleteAsync(messages, options, cancellationToken);
    }

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(IEnumerable<ChatMessage> messages, ChatOptions? options = null, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // Streaming not implemented for now
        yield break;
    }

    public object? GetService(Type serviceType, object? serviceKey = null)
    {
        return null;
    }

    public void Dispose()
    {
        _httpClient?.Dispose();
    }
}

