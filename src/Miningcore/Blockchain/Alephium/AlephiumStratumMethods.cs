namespace Miningcore.Blockchain.Alephium;

public class AlephiumStratumMethods
{
    /// <summary>
    /// Should be first connection message sent by miner. (majority of miners go straight to mining.authorize though)
    /// </summary>
    public const string Hello = "mining.hello";

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
    /// There are cases when a miner struggles to find a solution in a reasonable time so it may trigger the timeout imposed by the server in case of no communications (the server, in fact, may think the client got disconnected).
    /// To mitigate the problem a new method mining.noop (with no additional parameters) may be requested by the client.
    /// </summary>
    public const string Noop = "mining.noop";

    /// <summary>
    /// Used to signal the miner to stop submitting shares under the new difficulty.
    /// </summary>
    public const string SetDifficulty = "mining.set_difficulty";

    /// <summary>
    /// This call simply dumps transactions used for given job. Thanks to this, miners now have
    /// everything needed to reconstruct source block template used by the pool and they can
    /// check if pool isn't doing something nasty
    /// </summary>
    public const string GetTransactions = "mining.get_transactions";

    /// <summary>
    /// Used to subscribe to work from a server, required before all other communication.
    /// </summary>
    public const string SetExtraNonce = "mining.set_extranonce";

    /// <summary>
    /// Ignored
    /// </summary>
    public const string SubmitHashrate = "alph_submitHashrate";

    /// <summary>
    /// Not supported but added for handling responses
    /// </summary>
    public const string SetGzip = "connection.set_gzip";
}