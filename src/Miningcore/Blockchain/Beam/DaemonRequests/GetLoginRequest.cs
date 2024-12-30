using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.DaemonRequests;

public class GetLoginRequest
{
    [JsonProperty("id")]
    public string Id { get; set; } = "login";
    
    [JsonProperty("method")]
    public string Method { get; set; } = "login";
    
    [JsonProperty("api_key")]
    public string ApiKey { get; set; }
    
    [JsonProperty("jsonrpc")]
    public string JsonRpc { get; set; } = "2.0";
}