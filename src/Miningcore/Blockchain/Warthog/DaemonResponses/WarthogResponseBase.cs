using Newtonsoft.Json;

namespace Miningcore.Blockchain.Warthog.DaemonResponses;

public class WarthogResponseBase
{
    [JsonProperty("code", NullValueHandling = NullValueHandling.Ignore)]
    public short? Code { get; set; }
    
    [JsonProperty("error", NullValueHandling = NullValueHandling.Ignore)]
    public string Error { get; set; }
}