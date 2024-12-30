using Newtonsoft.Json;

namespace Miningcore.Blockchain.Cryptonote.DaemonResponses;

public class GetBalanceResponse
{
    public decimal Balance { get; set; }

    [JsonProperty("unlocked_balance")]
    public decimal UnlockedBalance { get; set; }
}

public class BalanceAsset
{
    [JsonProperty("asset_type")]
    public string Asset { get; set; } = null;

    public decimal Balance { get; set; }

    [JsonProperty("unlocked_balance")]
    public decimal UnlockedBalance { get; set; }
}

public class GetBalancesResponse
{
    public BalanceAsset[] Balances { get; set; }
}