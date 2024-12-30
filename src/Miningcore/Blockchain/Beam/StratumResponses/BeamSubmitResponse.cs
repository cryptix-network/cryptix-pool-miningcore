using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.StratumResponses;

public class BeamSubmitResponse : BeamResponseBase
{
    [JsonProperty("id")]
    public string Id { get; set; }
    
    [JsonProperty("method")]
    public string Method { get; set; } = "result";
    
    [JsonProperty("blockhash", NullValueHandling = NullValueHandling.Ignore)]
    public string BlockHash { get; set; } 
}