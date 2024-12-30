using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.DaemonRequests;

public class SendTransactionRequest
{
    public string From { get; set; }
    public string Address { get; set; }
    public ulong Value { get; set; }
    
    // Always in BEAM groth, optional. Omit for default fee.
    [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
    public ulong? Fee { get; set; }
    
    // asset id to send, optional. Present starting from v5.0 and can be used only after Fork 2.
    // Omit or set to 0 for BEAM transaction.
    // If asset_id is non-zero assets must be enabled (--enable_assets) or method would fail.
    [JsonProperty("asset_id")]
    public ulong AssetId { get; set; } = 0;
    
    // Since v6.0 offline addresses by default start the regular online transaction.
    // Specify "offline":true" to start an offline transaction.
    // Applied only for offline addresses and ignored for all other address types.
    public bool Offline { get; set; } = false;
}