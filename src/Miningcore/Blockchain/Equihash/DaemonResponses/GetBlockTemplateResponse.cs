using Newtonsoft.Json;

namespace Miningcore.Blockchain.Equihash.DaemonResponses;

public class EquihashCoinbaseTransaction
{
    public string Data { get; set; }
    public string Hash { get; set; }
    public decimal Fee { get; set; }
    public int SigOps { get; set; }
    public ulong FoundersReward { get; set; }
    public bool Required { get; set; }

    // "depends":[ ],
}

public class EquihashBlockTemplate : Bitcoin.DaemonResponses.BlockTemplate
{
    public string[] Capabilities { get; set; }

    [JsonProperty("coinbasetxn")]
    public EquihashCoinbaseTransaction CoinbaseTx { get; set; }

    public string LongPollId { get; set; }
    public ulong MinTime { get; set; }
    public ulong SigOpLimit { get; set; }
    public ulong SizeLimit { get; set; }
    public string[] Mutable { get; set; }

    public ZCashBlockSubsidy Subsidy { get; set; }

    [JsonProperty("finalsaplingroothash")]
    public string FinalSaplingRootHash { get; set; }
    
    // Veruscoin
    [JsonProperty("merged_bits")]
    public string MergedBits { get; set; } = null;
    
    [JsonProperty("mergeminebits")]
    public string MergeMineBits { get; set; } = null;
    
    [JsonProperty("solution")]
    public string Solution { get; set; } = null;
    
    [JsonProperty("nonce")]
    public string Nonce { get; set; } = null;
}
