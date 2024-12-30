namespace Miningcore.Blockchain.Kaspa;

public class KaspaStratumMethods
{
    /// <summary>
    /// Used to subscribe to work from a server, required before all other communication.
    /// </summary>
    public const string Subscribe = "mining.subscribe";
    
    /// <summary>
    /// Used to authorize a worker, required before any shares can be submitted.
    /// </summary>
    public const string Authorize = "mining.authorize";

    /// <summary>
    /// Used to push new work to the miner.
    /// </summary>
    public const string MiningNotify = "mining.notify";

    /// <summary>
    /// Used to submit shares
    /// </summary>
    public const string SubmitShare = "mining.submit";

    /// <summary>
    /// Used to signal the miner to stop submitting shares under the new difficulty.
    /// </summary>
    public const string SetDifficulty = "mining.set_difficulty";
    
    /// <summary>
    /// Used to subscribe to work from a server, required before all other communication.
    /// </summary>
    public const string ExtraNonceSubscribe = "mining.extranonce.subscribe";

    /// <summary>
    /// Used to subscribe to work from a server, required before all other communication.
    /// </summary>
    public const string SetExtraNonce = "set_extranonce";
}