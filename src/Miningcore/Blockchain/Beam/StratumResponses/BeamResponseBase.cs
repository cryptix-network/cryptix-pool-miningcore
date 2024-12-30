using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.StratumResponses;

public class BeamResponseBase
{
    [JsonProperty("code", NullValueHandling = NullValueHandling.Ignore)]
    public short? Code { get; set; }
    
    [JsonProperty("description", NullValueHandling = NullValueHandling.Ignore)]
    public string Description { get; set; }
}