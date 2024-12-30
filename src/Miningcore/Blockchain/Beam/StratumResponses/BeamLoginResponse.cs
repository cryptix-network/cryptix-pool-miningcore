using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.StratumResponses;

public class BeamLoginResponse : BeamResponseBase
{
    [JsonProperty("id")]
    public string Id { get; set; } = "login";
    
    [JsonProperty("nonceprefix", NullValueHandling = NullValueHandling.Ignore)]
    public string Nonceprefix { get; set; } = null;
    
    [JsonProperty("forkheight", NullValueHandling = NullValueHandling.Ignore)]
    public ulong? Forkheight { get; set; }
    
    [JsonProperty("forkheight2", NullValueHandling = NullValueHandling.Ignore)]
    public ulong? Forkheight2 { get; set; }
    
    [JsonProperty("method")]
    public string Method { get; set; } = "result";
}