using Miningcore.Mining;

namespace Miningcore.Blockchain.Progpow;

public class ProgpowWorkerContext : WorkerContextBase
{
    /// <summary>
    /// Usually a wallet address
    /// </summary>
    public override string Miner { get; set; }

    /// <summary>
    /// Arbitrary worker identififer for miners using multiple rigs
    /// </summary>
    public override string Worker { get; set; }

    /// <summary>
    /// Unique value assigned per worker
    /// </summary>
    public string ExtraNonce1 { get; set; }

    private List<ProgpowWorkerJob> ValidJobs { get; } = new();

    public void AddJob(ProgpowWorkerJob job)
    {
        ValidJobs.Insert(0, job);

        while(ValidJobs.Count > 4)
            ValidJobs.RemoveAt(ValidJobs.Count - 1);
    }

    public ProgpowWorkerJob FindJob(string jobId)
    {
        return ValidJobs.FirstOrDefault(x => x.Id == jobId);
    }
}