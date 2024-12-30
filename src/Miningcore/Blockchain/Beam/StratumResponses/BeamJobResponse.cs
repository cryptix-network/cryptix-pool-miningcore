using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.StratumResponses;

public class BeamJobResponse : BeamResponseBase
{
    [JsonProperty("id")]
    public string Id { get; set; }
    
    [JsonProperty("height")]
    public ulong Height { get; set; }
    
    [JsonProperty("difficulty")]
    public long Difficulty { get; set; }
    
    [JsonProperty("input")]
    public string Input { get; set; }
    
    [JsonProperty("nonceprefix", NullValueHandling = NullValueHandling.Ignore)]
    public string Nonceprefix { get; set; } = null;
    
    [JsonProperty("method")]
    public string Method { get; set; } = "job";
}