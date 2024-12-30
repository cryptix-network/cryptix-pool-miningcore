using System.Globalization;
using Autofac;
using Miningcore.Blockchain.Bitcoin;
using Miningcore.Blockchain.Bitcoin.Configuration;
using Miningcore.Blockchain.Nexa.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Contracts;
using Miningcore.Crypto;
using Miningcore.Extensions;
using Miningcore.Messaging;
using Miningcore.Notifications.Messages;
using Miningcore.Rpc;
using Miningcore.Stratum;
using Miningcore.Time;
using Newtonsoft.Json;
using NLog;
using BlockTemplate = Miningcore.Blockchain.Bitcoin.DaemonResponses.BlockTemplate;

namespace Miningcore.Blockchain.Nexa;

public class NexaJobManager : BitcoinJobManagerBase<NexaJob>
{
    public NexaJobManager(
        IComponentContext ctx,
        IMasterClock clock,
        IMessageBus messageBus,
        IExtraNonceProvider extraNonceProvider) :
        base(ctx, clock, messageBus, extraNonceProvider)
    {
    }

    private BitcoinTemplate coin;
    private string poolAddress;
    private BlockTemplate blockTemplate;


    private object[] GetMiningCandidateParams()
    {
        return new object[]
        {
            null,
            poolAddress,
        };
    }

    private async Task<RpcResponse<MiningCandidate>> GetMiningCandidateAsync(CancellationToken ct)
    {
        var result = await rpc.ExecuteAsync<MiningCandidate>(logger,
            NexaCommands.GetMiningCandidate, ct, GetMiningCandidateParams());

        return result;
    }

    private static RpcResponse<MiningCandidate> GetMiningCandidateFromJson(string json)
    {
        var result = JsonConvert.DeserializeObject<RpcResponse<MiningCandidate>>(json);

        return result;
    }

    private async Task<RpcResponse<BlockTemplate>> GetBlockTemplateAsync(CancellationToken ct)
    {
        var result = await rpc.ExecuteAsync<BlockTemplate>(logger,
            BitcoinCommands.GetBlockTemplate, ct, extraPoolConfig?.GBTArgs ?? (object) GetBlockTemplateParams());

        return result;
    }

    private static NexaJob CreateJob()
    {
        return new NexaJob();
    }

    protected override void PostChainIdentifyConfigure()
    {
        base.PostChainIdentifyConfigure();

        if(poolConfig.EnableInternalStratum == true && coin.HeaderHasherValue is IHashAlgorithmInit hashInit)
        {
            if(!hashInit.DigestInit(poolConfig))
                logger.Error(() => $"{hashInit.GetType().Name} initialization failed");
        }
    }

    protected override async Task<(bool IsNew, bool Force)> UpdateJob(CancellationToken ct, bool forceUpdate, string via = null, string json = null)
    {
        try
        {
            if(forceUpdate)
                lastJobRebroadcast = clock.Now;

            var response = string.IsNullOrEmpty(json) ?
                await GetMiningCandidateAsync(ct) :
                GetMiningCandidateFromJson(json);

            // may happen if daemon is currently not connected to peers
            if(response.Error != null)
            {
                logger.Warn(() => $"Unable to update job. GetMiningCandidate failed. Daemon responded with: {response.Error.Message} Code {response.Error.Code}");
                return (false, forceUpdate);
            }

            var miningCandidate = response.Response;
            var job = currentJob;

            var isNew = job == null ||
                (miningCandidate != null &&
                    (job.MiningCandidate.HeaderCommitment != miningCandidate.HeaderCommitment ||
                        miningCandidate.Id > job.MiningCandidate?.Id));

            if(isNew)
            {
                var gbtResponse = await GetBlockTemplateAsync(ct);
                if(gbtResponse.Error != null)
                {
                    logger.Warn(() => $"Unable to update job. GetBlockTemplate failed. Daemon responded with: {gbtResponse.Error.Message} Code {gbtResponse.Error.Code}");
                    return (false, forceUpdate);
                }
                blockTemplate = gbtResponse.Response;
                messageBus.NotifyChainHeight(poolConfig.Id, blockTemplate.Height, poolConfig.Template);
            }

            if(isNew || forceUpdate)
            {
                job = CreateJob();

                job.Init(miningCandidate, blockTemplate, NextJobId(),
                    poolConfig, clock, ShareMultiplier, coin.HeaderHasherValue);

                lock(jobLock)
                {
                    validJobs.Insert(0, job);

                    // trim active jobs
                    while(validJobs.Count > maxActiveJobs)
                        validJobs.RemoveAt(validJobs.Count - 1);
                }

                if(isNew)
                {
                    if(via != null)
                        logger.Info(() => $"Detected new block {blockTemplate.Height} [{via}]");
                    else
                        logger.Info(() => $"Detected new block {blockTemplate.Height}");

                    // update stats
                    BlockchainStats.LastNetworkBlockTime = clock.Now;
                    BlockchainStats.BlockHeight = blockTemplate.Height;
                    BlockchainStats.NetworkDifficulty = job.Difficulty;
                    BlockchainStats.NextNetworkTarget = blockTemplate.Target;
                    BlockchainStats.NextNetworkBits = blockTemplate.Bits;
                }

                else
                {
                    if(via != null)
                        logger.Debug(() => $"Template update {blockTemplate?.Height} [{via}]");
                    else
                        logger.Debug(() => $"Template update {blockTemplate?.Height}");
                }

                currentJob = job;
            }

            return (isNew, forceUpdate);
        }

        catch(OperationCanceledException)
        {
            // ignored
        }

        catch(Exception ex)
        {
            logger.Error(ex, () => $"Error during {nameof(UpdateJob)}");
        }

        return (false, forceUpdate);
    }

    protected override object GetJobParamsForStratum(bool isNew)
    {
        var job = currentJob;
        return job?.GetJobParams();
    }

    #region API-Surface

    public override void Configure(PoolConfig pc, ClusterConfig cc)
    {
        poolAddress = pc.Address;
        coin = pc.Template.As<BitcoinTemplate>();
        extraPoolConfig = pc.Extra.SafeExtensionDataAs<BitcoinPoolConfigExtra>();

        if(extraPoolConfig?.MaxActiveJobs.HasValue == true)
            maxActiveJobs = extraPoolConfig.MaxActiveJobs.Value;

        base.Configure(pc, cc);
    }

    public object[] GetSubscriberData(StratumConnection worker)
    {
        Contract.RequiresNonNull(worker);

        var context = worker.ContextAs<BitcoinWorkerContext>();

        // assign unique ExtraNonce1 to worker (miner)
        context.ExtraNonce1 = extraNonceProvider.Next();

        // setup response data
        var responseData = new object[]
        {
            context.ExtraNonce1,
            BitcoinConstants.ExtranoncePlaceHolderLength - ExtranonceBytes,
        };

        return responseData;
    }

    public async ValueTask<Share> SubmitShareAsync(StratumConnection worker, object submission,
        CancellationToken ct)
    {
        Contract.RequiresNonNull(worker);
        Contract.RequiresNonNull(submission);

        if(submission is not object[] submitParams)
            throw new StratumException(StratumError.Other, "invalid params");

        var context = worker.ContextAs<BitcoinWorkerContext>();

        var workerValue = (submitParams[0] as string)?.Trim();
        var jobId = submitParams[1] as string;
        var extraNonce1 = submitParams[2] as string;
        //var nTime = submitParams[3] as string; // not really required
        var nonce = submitParams[4] as string;

        if(string.IsNullOrEmpty(workerValue))
            throw new StratumException(StratumError.Other, "missing or invalid workername");

        if(extraNonce1 != context.ExtraNonce1)
            throw new StratumException(StratumError.Other, "invalid extranonce");

        NexaJob job;

        lock(jobLock)
        {
            job = validJobs.FirstOrDefault(x => x.JobId == jobId);
        }

        if(job == null)
            throw new StratumException(StratumError.JobNotFound, "job not found");

        // validate & process
        var (share, args) = job.ProcessShare(worker, nonce, extraNonce1);

        // enrich share with common data
        share.PoolId = poolConfig.Id;
        share.IpAddress = worker.RemoteEndpoint.Address.ToString();
        share.Miner = context.Miner;
        share.Worker = context.Worker;
        share.UserAgent = context.UserAgent;
        share.Source = clusterConfig.ClusterName;
        share.Created = clock.Now;

        // if block candidate, submit & check if accepted by network
        if(share.IsBlockCandidate)
        {
            logger.Info(() => $"Submitting block {share.BlockHeight}");

            var acceptResponse = await SubmitBlockAsync(share, args, ct);

            // is it still a block candidate?
            share.IsBlockCandidate = acceptResponse.Accepted;
            share.BlockHash = acceptResponse.BlockHash;

            if(share.IsBlockCandidate)
            {
                logger.Info(() => $"Daemon accepted block {share.BlockHeight} [{share.BlockHash}] submitted by {context.Miner}");

                OnBlockFound();

                // persist the coinbase transaction-hash to allow the payment processor
                // to verify later on that the pool has received the reward for the block
                share.TransactionConfirmationData = acceptResponse.CoinbaseTx;
            }

            else
            {
                // clear fields that no longer apply
                share.TransactionConfirmationData = null;
            }
        }

        return share;
    }

    public double ShareMultiplier => coin.ShareMultiplier;

    protected new record SubmitResult(bool Accepted, string BlockHash, string CoinbaseTx);

    protected async Task<SubmitResult> SubmitBlockAsync(Share share, object args, CancellationToken ct)
    {
        var rawSubmitRes = await rpc.ExecuteAsync<object>(logger, NexaCommands.SubmitMiningSolution, ct, payload: args);

        // TODO: maybe refactor this. Try to deserialize first and if there is an error, treat the response as a string

        var rawSubmitString = rawSubmitRes?.Response.ToString();
        string submitError = null;
        SubmitMiningSolution submitResult = null;
        if(string.IsNullOrEmpty(rawSubmitString) || rawSubmitRes.Error != null || rawSubmitString == "id not found (stale candidate)")
        {
            submitError = rawSubmitRes?.Error?.Message ??
                rawSubmitRes?.Error?.Code.ToString(CultureInfo.InvariantCulture) ??
                rawSubmitString ??
                "unknown error";
        }
        else
        {
            submitResult = JsonConvert.DeserializeObject<SubmitMiningSolution>(rawSubmitString);
            if(!string.IsNullOrEmpty(submitResult.Result))
            {
                submitError = submitResult.Result;
            }
        }

        if(!string.IsNullOrEmpty(submitError))
        {
            logger.Warn(() => $"Block {share.BlockHeight} submission failed with: {submitError}");
            messageBus.SendMessage(new AdminNotification("Block submission failed", $"Pool {poolConfig.Id} {(!string.IsNullOrEmpty(share.Source) ? $"[{share.Source.ToUpper()}] " : string.Empty)}failed to submit block {share.BlockHeight}: {submitError}"));
            return new SubmitResult(false, null, null);
        }


        var blockResult = await rpc.ExecuteAsync<Block>(logger, BitcoinCommands.GetBlock, ct, new object[] { submitResult?.Hash });
        var block = blockResult?.Response;

        var accepted = blockResult != null && blockResult.Error == null;

        if(!accepted)
        {
            logger.Warn(() => $"Block {share.BlockHeight} submission failed for pool {poolConfig.Id} because block was not found after submission");
            messageBus.SendMessage(new AdminNotification($"[{share.PoolId.ToUpper()}]-[{share.Source}] Block submission failed", $"[{share.PoolId.ToUpper()}]-[{share.Source}] Block {share.BlockHeight} submission failed for pool {poolConfig.Id} because block was not found after submission"));
        }

        return new SubmitResult(accepted, block?.Hash, block?.Transactions.FirstOrDefault());
    }

    #endregion // API-Surface
}
