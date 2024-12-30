using System.Text.Json.Serialization;

namespace Miningcore.Blockchain.Warthog.DaemonResponses;

public class WarthogWalletData
{
    public string Address { get; set; }

    [JsonPropertyName("privKey")]
    public string PrivateKey { get; set; }

    [JsonPropertyName("pubKey")]
    public string PublicKey { get; set; }
}

public class WarthogWalletResponse : WarthogResponseBase
{
    public WarthogWalletData Data { get; set; }
}
