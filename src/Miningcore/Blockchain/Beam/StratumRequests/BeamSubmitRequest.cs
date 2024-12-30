using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.StratumRequests;

public class BeamSubmitRequest
{
    [JsonProperty("id")]
    public string Id { get; set; }
    
    [JsonProperty("method")]
    public string Method { get; set; } = "solution";
    
    [JsonProperty("nonce")]
    public string Nonce { get; set; }

    [JsonProperty("output")]
    public string Output { get; set; }
    
    [JsonProperty("jsonrpc")]
    public string Jsonrpc { get; set; } = "2.0";
}