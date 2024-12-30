using Newtonsoft.Json;

namespace Miningcore.Blockchain.Beam.DaemonResponses;

public class SendTransactionResponse
{
    [JsonProperty("txId")]
    public string TxId { get; set; }
}