using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.DaemonResponses;

public class GetBlockHeaderResponse
{
    [JsonProperty("block_hash")]
    public string BlockHash { get; set; }
    
    public string Chainwork { get; set; }
    public string Definition { get; set; }
    public double Difficulty { get; set; }
    public ulong Height { get; set; }
    public string Kernels { get; set; }
    
    [JsonProperty("packed_difficulty")]
    public long PackedDifficulty { get; set; }
    
    public string Pow { get; set; }
    
    [JsonProperty("previous_block")]
    public string PreviousBlock { get; set; }

    [JsonProperty("rules_hash")]
    public string RulesHash { get; set; }
    
    public ulong Timestamp { get; set; }
}