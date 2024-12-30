using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.DaemonResponses;

public class GetBalanceResponse
{
    [JsonProperty("current_height")]
    public ulong Height { get; set; }
    
    [JsonProperty("available")]
    public ulong Balance { get; set; }
    
    [JsonProperty("is_in_sync")]
    public bool IsInSync { get; set; }
}