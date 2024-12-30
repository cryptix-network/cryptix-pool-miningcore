using System;
using System.Net.Http;
using System.Text.RegularExpressions;
using Autofac;
using AutoMapper;
using Grpc.Core;
using Grpc.Net.Client;
using Miningcore.Blockchain.Kaspa.Configuration;
using Miningcore.Configuration;
using Miningcore.Extensions;
using Miningcore.Messaging;
using Miningcore.Mining;
using Miningcore.Payments;
using Miningcore.Persistence;
using Miningcore.Persistence.Model;
using Miningcore.Persistence.Repositories;
using Miningcore.Time;
using Miningcore.Util;
using Block = Miningcore.Persistence.Model.Block;
using Contract = Miningcore.Contracts.Contract;
using static Miningcore.Util.ActionUtils;
using kaspaWalletd = Miningcore.Blockchain.Kaspa.KaspaWalletd;
using kaspad = Miningcore.Blockchain.Kaspa.Kaspad;

namespace Miningcore.Blockchain.Kaspa;

[CoinFamily(CoinFamily.Kaspa)]
public class KaspaPayoutHandler : PayoutHandlerBase,
    IPayoutHandler
{
    public KaspaPayoutHandler(
        IComponentContext ctx,
        IConnectionFactory cf,
        IMapper mapper,
        IShareRepository shareRepo,
        IBlockRepository blockRepo,
        IBalanceRepository balanceRepo,
        IPaymentRepository paymentRepo,
        IMasterClock clock,
        IMessageBus messageBus) :
        base(cf, mapper, shareRepo, blockRepo, balanceRepo, paymentRepo, clock, messageBus)
    {
        Contract.RequiresNonNull(ctx);
        Contract.RequiresNonNull(balanceRepo);
        Contract.RequiresNonNull(paymentRepo);

        this.ctx = ctx;
    }

    protected readonly IComponentContext ctx;
    protected kaspad.KaspadRPC.KaspadRPCClient rpc;
    protected kaspaWalletd.KaspaWalletdRPC.KaspaWalletdRPCClient walletRpc;
    private string network;
    private KaspaPoolConfigExtra extraPoolConfig;
    private KaspaPaymentProcessingConfigExtra extraPoolPaymentProcessingConfig;
    private bool supportsMaxFee = false;

    protected override string LogCategory => "Kaspa Payout Handler";
    
    #region IPayoutHandler
    
    public virtual async Task ConfigureAsync(ClusterConfig cc, PoolConfig pc, CancellationToken ct)
    {
        Contract.RequiresNonNull(pc);

        poolConfig = pc;
        clusterConfig = cc;
        extraPoolConfig = pc.Extra.SafeExtensionDataAs<KaspaPoolConfigExtra>();
        extraPoolPaymentProcessingConfig = pc.PaymentProcessing.Extra.SafeExtensionDataAs<KaspaPaymentProcessingConfigExtra>();
        
        logger = LogUtil.GetPoolScopedLogger(typeof(KaspaPayoutHandler), pc);
        
        // extract standard daemon endpoints
        var daemonEndpoints = pc.Daemons
            .Where(x => string.IsNullOrEmpty(x.Category))
            .ToArray();
        
        // extract wallet daemon endpoints
        var walletDaemonEndpoints = pc.Daemons
            .Where(x => x.Category?.ToLower() == KaspaConstants.WalletDaemonCategory)
            .ToArray();

        if(walletDaemonEndpoints.Length == 0)
            throw new PaymentException("Wallet-RPC daemon is not configured (Daemon configuration for kaspa-pools require an additional entry of category 'wallet' pointing to the wallet daemon)");

        rpc = KaspaClientFactory.CreateKaspadRPCClient(daemonEndpoints, extraPoolConfig?.ProtobufDaemonRpcServiceName ?? KaspaConstants.ProtobufDaemonRpcServiceName);
        walletRpc = KaspaClientFactory.CreateKaspaWalletdRPCClient(walletDaemonEndpoints, extraPoolConfig?.ProtobufWalletRpcServiceName ?? KaspaConstants.ProtobufWalletRpcServiceName);
        
        // we need a stream to communicate with Kaspad
        var stream = rpc.MessageStream(null, null, ct);
        
        var request = new kaspad.KaspadMessage();
        request.GetCurrentNetworkRequest = new kaspad.GetCurrentNetworkRequestMessage();
        await Guard(() => stream.RequestStream.WriteAsync(request),
            ex=> throw new PaymentException($"Error writing a request in the communication stream '{ex.GetType().Name}' : {ex}"));
        await foreach (var currentNetwork in stream.ResponseStream.ReadAllAsync(ct))
        {
            if(!string.IsNullOrEmpty(currentNetwork.GetCurrentNetworkResponse.Error?.Message))
                throw new PaymentException($"Daemon reports: {currentNetwork.GetCurrentNetworkResponse.Error?.Message}");
            
            network = currentNetwork.GetCurrentNetworkResponse.CurrentNetwork;
            break;
        }
        await stream.RequestStream.CompleteAsync();

        var callGetVersion = walletRpc.GetVersionAsync(new kaspaWalletd.GetVersionRequest());
        var walletVersion = await Guard(() => callGetVersion.ResponseAsync,
            ex=> logger.Debug(ex));
        callGetVersion.Dispose();

        if(!string.IsNullOrEmpty(walletVersion?.Version))
        {
            logger.Info(() => $"[{LogCategory}] Wallet version: {walletVersion.Version}");

            if(!string.IsNullOrEmpty(extraPoolPaymentProcessingConfig?.VersionEnablingMaxFee))
            {
                logger.Info(() => $"[{LogCategory}] Wallet daemon version which enables MaxFee: {extraPoolPaymentProcessingConfig.VersionEnablingMaxFee}");

                string walletVersionNumbersOnly = Regex.Replace(walletVersion.Version, "[^0-9.]", "");
                string[] walletVersionNumbers = walletVersionNumbersOnly.Split(".");

                string versionEnablingMaxFeeNumbersOnly = Regex.Replace(extraPoolPaymentProcessingConfig.VersionEnablingMaxFee, "[^0-9.]", "");
                string[] versionEnablingMaxFeeNumbers = versionEnablingMaxFeeNumbersOnly.Split(".");

                // update supports max fee
                if(walletVersionNumbers.Length >= 3 && versionEnablingMaxFeeNumbers.Length >= 3)
                    supportsMaxFee = ((Convert.ToUInt32(walletVersionNumbers[0]) > Convert.ToUInt32(versionEnablingMaxFeeNumbers[0])) || (Convert.ToUInt32(walletVersionNumbers[0]) == Convert.ToUInt32(versionEnablingMaxFeeNumbers[0]) && Convert.ToUInt32(walletVersionNumbers[1]) > Convert.ToUInt32(versionEnablingMaxFeeNumbers[1])) || (Convert.ToUInt32(walletVersionNumbers[0]) == Convert.ToUInt32(versionEnablingMaxFeeNumbers[0]) && Convert.ToUInt32(walletVersionNumbers[1]) == Convert.ToUInt32(versionEnablingMaxFeeNumbers[1]) && Convert.ToUInt32(walletVersionNumbers[2]) >= Convert.ToUInt32(versionEnablingMaxFeeNumbers[2])));
            }
        }
    }
    
    public virtual async Task<Block[]> ClassifyBlocksAsync(IMiningPool pool, Block[] blocks, CancellationToken ct)
    {
        Contract.RequiresNonNull(poolConfig);
        Contract.RequiresNonNull(blocks);

        if(blocks.Length == 0)
            return blocks;

        var coin = poolConfig.Template.As<KaspaCoinTemplate>();
        var pageSize = 100;
        var pageCount = (int) Math.Ceiling(blocks.Length / (double) pageSize);
        var result = new List<Block>();
        // KAS minimum confirmation can change over time so please always aknowledge all those different changes very wisely: https://github.com/kaspanet/rusty-kaspa/blob/master/wallet/core/src/utxo/settings.rs
        int minConfirmations = extraPoolPaymentProcessingConfig?.MinimumConfirmations ?? (network == "mainnet" ? 120 : 110);

        // we need a stream to communicate with Kaspad
        var stream = rpc.MessageStream(null, null, ct);

        for(var i = 0; i < pageCount; i++)
        {
            // get a page full of blocks
            var page = blocks
                .Skip(i * pageSize)
                .Take(pageSize)
                .ToArray();
    
            for(var j = 0; j < page.Length; j++)
            {
                var block = page[j];

                // There is a case scenario:
                // https://github.com/blackmennewstyle/miningcore/issues/191
                // Sadly miners can submit different solutions which will produce the exact same blockHash for the same block
                // We must handle that case carefully here, otherwise we will overpay our miners.
                // Only one of these blocks must will be confirmed, the others will all become Orphans
                uint totalDuplicateBlockBefore = await cf.Run(con => blockRepo.GetPoolDuplicateBlockBeforeCountByPoolHeightAndHashNoTypeAndStatusAsync(con, poolConfig.Id, Convert.ToInt64(block.BlockHeight), block.Hash, new[]
                {
                    BlockStatus.Confirmed,
                    BlockStatus.Orphaned,
                    BlockStatus.Pending
                }, block.Created));

                var request = new kaspad.KaspadMessage();
                request.GetBlockRequest = new kaspad.GetBlockRequestMessage
                {
                    Hash = block.Hash,
                    IncludeTransactions = true,
                };
                await Guard(() => stream.RequestStream.WriteAsync(request),
                    ex=> logger.Debug(ex));
                await foreach (var blockInfo in stream.ResponseStream.ReadAllAsync(ct))
                {
                    // We lost that battle
                    if(!string.IsNullOrEmpty(blockInfo.GetBlockResponse.Error?.Message))
                    {
                        result.Add(block);

                        block.Status = BlockStatus.Orphaned;
                        block.Reward = 0;

                        logger.Info(() => $"[{LogCategory}] Block {block.BlockHeight} classified as orphaned because it's not the chain");

                        messageBus.NotifyBlockUnlocked(poolConfig.Id, block, coin);
                    }
                    // multiple blocks with the exact same height & hash recorded in the database
                    else if(totalDuplicateBlockBefore > 0)
                    {
                        result.Add(block);

                        block.Status = BlockStatus.Orphaned;
                        block.Reward = 0;

                        logger.Info(() => $"[{LogCategory}] Block {block.BlockHeight} [{block.Hash}] classified as orphaned because we already have in the database {totalDuplicateBlockBefore} block(s) with the same height and hash");

                        messageBus.NotifyBlockUnlocked(poolConfig.Id, block, coin);
                    }
                    else
                    {
                        logger.Info(() => $"[{LogCategory}] Block {block.BlockHeight} uses a custom minimum confirmations calculation [{minConfirmations}]");

                        var requestConfirmations = new kaspad.KaspadMessage();
                        requestConfirmations.GetBlocksRequest = new kaspad.GetBlocksRequestMessage
                        {
                            LowHash = (string) block.Hash,
                            IncludeBlocks = false,
                            IncludeTransactions = false,
                        };
                        await Guard(() => stream.RequestStream.WriteAsync(requestConfirmations),
                            ex=> logger.Debug(ex));
                        await foreach (var responseConfirmations in stream.ResponseStream.ReadAllAsync(ct))
                        {
                            logger.Debug(() => $"[{LogCategory}] Block {block.BlockHeight} [{responseConfirmations.GetBlocksResponse.BlockHashes.Count}]");

                            block.ConfirmationProgress = Math.Min(1.0d, (double) responseConfirmations.GetBlocksResponse.BlockHashes.Count / minConfirmations);
                            break;
                        }

                        result.Add(block);

                        messageBus.NotifyBlockConfirmationProgress(poolConfig.Id, block, coin);
                        
                        // matured and spendable?
                        if(block.ConfirmationProgress >= 1)
                        {
                            
                            // KASPA block reward calculation is a complete nightmare: https://wiki.kaspa.org/en/merging-and-rewards
                            decimal blockReward = 0.0m;
                            
                            var childrenProvideRewards = false;
                            
                            // First: We need the parse the children(s) related to the block reward, because in GhostDAG the child(s) reward(s) the parent
                            foreach(var childrenHash in blockInfo.GetBlockResponse.Block.VerboseData.ChildrenHashes)
                            {
                                logger.Debug(() => $"[{LogCategory}] Block {block.BlockHeight} contains child: {childrenHash}");

                                var requestChildren = new kaspad.KaspadMessage();
                                requestChildren.GetBlockRequest = new kaspad.GetBlockRequestMessage
                                {
                                    Hash = childrenHash,
                                    IncludeTransactions = true,
                                };
                                await Guard(() => stream.RequestStream.WriteAsync(requestChildren),
                                    ex=> logger.Debug(ex));
                                await foreach (var responseChildren in stream.ResponseStream.ReadAllAsync(ct))
                                {
                                    // we only need the transaction(s) related to the block reward
                                    var childrenBlockRewardTransactions = responseChildren.GetBlockResponse.Block.Transactions
                                        .Where(x => x.Inputs.Count < 1)
                                        .ToList();
                                    
                                    if(childrenBlockRewardTransactions.Count > 0)
                                    {
                                        // We need to know if our initial blockHah is in the redMerges
                                        var mergeSetRedsHashess = responseChildren.GetBlockResponse.Block.VerboseData.MergeSetRedsHashes
                                            .Where(x => x.Contains((string) block.Hash))
                                            .ToList();

                                        // We need to know if our initial blockHah is in the redMerges
                                        var mergeSetBluesHashes = responseChildren.GetBlockResponse.Block.VerboseData.MergeSetBluesHashes
                                            .Where(x => x.Contains((string) block.Hash))
                                            .ToList();
                                        
                                        if(mergeSetRedsHashess.Count > 0)
                                        {
                                            logger.Debug(() => $"[{LogCategory}] Block {block.BlockHeight} - block child {responseChildren.GetBlockResponse.Block.Header.DaaScore} [{childrenHash}] provides {FormatAmount(0.0m)}");
                                        }
                                        else if(mergeSetBluesHashes.Count > 0 && responseChildren.GetBlockResponse.Block.VerboseData.IsChainBlock)
                                        {
                                            var childrenPosition = responseChildren.GetBlockResponse.Block.VerboseData.MergeSetBluesHashes.IndexOf((string) block.Hash);
                                            
                                            // Are those rewards going to the pool wallet?
                                            if(childrenBlockRewardTransactions.First().Outputs[childrenPosition].VerboseData.ScriptPublicKeyAddress == poolConfig.Address)
                                            {
                                                childrenProvideRewards = true;

                                                logger.Debug(() => $"[{LogCategory}] Block {block.BlockHeight} - block child {responseChildren.GetBlockResponse.Block.Header.DaaScore} [{childrenHash}] provides {FormatAmount((decimal) (childrenBlockRewardTransactions.First().Outputs[childrenPosition].Amount / KaspaConstants.SmallestUnit))} => {coin.Symbol} address: {childrenBlockRewardTransactions.First().Outputs[childrenPosition].VerboseData.ScriptPublicKeyAddress} [{poolConfig.Address}]");
                                                blockReward += (decimal) (childrenBlockRewardTransactions.First().Outputs[childrenPosition].Amount / KaspaConstants.SmallestUnit);
                                            }
                                            else
                                                logger.Debug(() => $"[{LogCategory}] Block {block.BlockHeight} - block child {responseChildren.GetBlockResponse.Block.Header.DaaScore} [{childrenHash}] provides {FormatAmount(0.0m)}");
                                            
                                        }
                                        else
                                            logger.Debug(() => $"[{LogCategory}] Block {block.BlockHeight} - block child {responseChildren.GetBlockResponse.Block.Header.DaaScore} [{childrenHash}] provides {FormatAmount(0.0m)}");
                                    }
                                    else
                                        logger.Warn(() => $"[{LogCategory}] Block {block.BlockHeight} - block child {responseChildren.GetBlockResponse.Block.Header.DaaScore} [{childrenHash}] does not contain transaction(s) related to the block reward, block maybe will not be unlocked :'(");

                                    break;
                                }
                            }
                            
                            // Hold on, we still have one more thing to check
                            if(blockInfo.GetBlockResponse.Block.VerboseData.IsChainBlock && childrenProvideRewards == false)
                            {
                                // we only need the transaction(s) related to the block reward
                                var blockRewardTransactions = blockInfo.GetBlockResponse.Block.Transactions
                                    .Where(x => x.Inputs.Count < 1)
                                    .ToList();
                                
                                if(blockRewardTransactions.Count > 0)
                                {
                                    // We only need the transactions for the pool wallet
                                    var amounts = blockRewardTransactions.First().Outputs
                                        .Where(x => x.VerboseData.ScriptPublicKeyAddress == poolConfig.Address)
                                        .ToList();

                                    if(amounts.Count > 0)
                                    {
                                        var totalAmount = amounts
                                            .Sum(x => (x.Amount / KaspaConstants.SmallestUnit));
                                        
                                        logger.Debug(() => $"[{LogCategory}] Block {block.BlockHeight} contains: {FormatAmount(totalAmount)}");
                                        blockReward += (decimal) totalAmount;
                                    }
                                    else
                                        logger.Warn(() => $"[{LogCategory}] Block {block.BlockHeight} coinbase transaction(s) provide(s) {FormatAmount(0.0m)}");
                                }
                                else
                                    logger.Warn(() => $"[{LogCategory}] Block {block.BlockHeight} does not contain transaction(s) related to the block reward, block maybe will not be unlocked :'(");
                            }
                            
                            if(blockReward > 0)
                            {
                                block.Status = BlockStatus.Confirmed;
                                block.ConfirmationProgress = 1;

                                // reset block reward
                                block.Reward = blockReward;

                                logger.Info(() => $"[{LogCategory}] Unlocked block {block.BlockHeight} worth {FormatAmount(block.Reward)}");
                                messageBus.NotifyBlockUnlocked(poolConfig.Id, block, coin);
                            }
                            else
                            {
                                logger.Warn(() => $"[{LogCategory}] Block {block.BlockHeight} does not receive any block reward :'(");
                                
                                block.Status = BlockStatus.Orphaned;
                                block.Reward = 0;

                                logger.Info(() => $"[{LogCategory}] Block {block.BlockHeight} classified as orphaned because no reward has been found");

                                messageBus.NotifyBlockUnlocked(poolConfig.Id, block, coin);
                            }
                        }
                    }
                    break;
                }
            }
        }
        await stream.RequestStream.CompleteAsync();

        return result.ToArray();
    }
    
    public virtual async Task PayoutAsync(IMiningPool pool, Balance[] balances, CancellationToken ct)
    {
        Contract.RequiresNonNull(balances);
        
        // build args
        var amounts = balances
            .Where(x => x.Amount > 0)
            .OrderBy(x => x.Updated)
            .ThenByDescending(x => x.Amount)
            .ToDictionary(x => x.Address, x => x.Amount);

        if(amounts.Count == 0)
            return;

        var balancesTotal = amounts.Sum(x => x.Value);
        
        logger.Info(() => $"[{LogCategory}] Paying {FormatAmount(balancesTotal)} to {balances.Length} addresses");
        
        logger.Info(() => $"[{LogCategory}] Validating addresses...");
        var coin = poolConfig.Template.As<KaspaCoinTemplate>();
        foreach(var pair in amounts)
        {
            logger.Debug(() => $"[{LogCategory}] Address {pair.Key} with amount [{FormatAmount(pair.Value)}]");
            var (kaspaAddressUtility, errorKaspaAddressUtility) = KaspaUtils.ValidateAddress(pair.Key, network, coin);

            if(errorKaspaAddressUtility != null)
                logger.Warn(()=> $"[{LogCategory}] Address {pair.Key} is not valid : {errorKaspaAddressUtility}");
        }
        
        var callGetBalance = walletRpc.GetBalanceAsync(new kaspaWalletd.GetBalanceRequest());
        var walletBalances = await Guard(() => callGetBalance.ResponseAsync,
            ex=> logger.Debug(ex));
        callGetBalance.Dispose();
        
        var walletBalancePending = (decimal) (walletBalances?.Pending == null ? 0 : walletBalances?.Pending) / KaspaConstants.SmallestUnit;
        var walletBalanceAvailable = (decimal) (walletBalances?.Available == null ? 0 : walletBalances?.Available) / KaspaConstants.SmallestUnit;
        
        logger.Info(() => $"[{LogCategory}] Current wallet balance - Total: [{FormatAmount(walletBalancePending + walletBalanceAvailable)}] - Pending: [{FormatAmount(walletBalancePending)}] - Available: [{FormatAmount(walletBalanceAvailable)}]");

        // bail if balance does not satisfy payments
        if(walletBalanceAvailable < balancesTotal)
        {
            logger.Warn(() => $"[{LogCategory}] Wallet balance currently short of {FormatAmount(balancesTotal - walletBalanceAvailable)}. Will try again");
            return;
        }

        var txFailures = new List<Tuple<KeyValuePair<string, decimal>, Exception>>();
        var successBalances = new Dictionary<Balance, string>();

        // Payments on KASPA are a bit tricky, it does not have a strong multi-recipient method, the only way is to create unsigned transactions, signed them and then broadcast them, let's do this!
        foreach (var amount in amounts)
        {
            kaspaWalletd.CreateUnsignedTransactionsResponse unsignedTransaction;
            kaspaWalletd.SignResponse signedTransaction;

            // use a common id for all log entries related to this transfer
            var transferId = CorrelationIdGenerator.GetNextId();

            logger.Info(()=> $"[{LogCategory}] [{transferId}] Sending {FormatAmount(amount.Value)} to {amount.Key}");

            logger.Info(()=> $"[{LogCategory}] [{transferId}] 1/3 Create an unsigned transaction");

            var createUnsignedTransactionsRequest = new kaspaWalletd.CreateUnsignedTransactionsRequest
            {
                Address = amount.Key.ToLower(),
                Amount = (ulong) (amount.Value * KaspaConstants.SmallestUnit),
                UseExistingChangeAddress = false,
                IsSendAll = false
            };

            if(supportsMaxFee)
            {
                ulong maxFee = extraPoolPaymentProcessingConfig?.MaxFee ?? 20000;

                logger.Info(()=> $"[{LogCategory}] Max fee: {maxFee} SOMPI");

                createUnsignedTransactionsRequest.FeePolicy = new kaspaWalletd.FeePolicy
                {
                    MaxFee = maxFee
                };
            }

            var callUnsignedTransaction = walletRpc.CreateUnsignedTransactionsAsync(createUnsignedTransactionsRequest);

            unsignedTransaction = await Guard(() => callUnsignedTransaction.ResponseAsync, ex =>
            {
                txFailures.Add(Tuple.Create(amount, ex));
            });
            callUnsignedTransaction.Dispose();

            logger.Debug(()=> $"[{LogCategory}] [{transferId}] {(unsignedTransaction?.UnsignedTransactions == null ? 0 : unsignedTransaction?.UnsignedTransactions.Count)} unsigned transaction(s) created");

            // we have transactions to sign
            if(unsignedTransaction?.UnsignedTransactions.Count > 0)
            {
                logger.Info(()=> $"[{LogCategory}] [{transferId}] 2/3 Sign {unsignedTransaction.UnsignedTransactions.Count} unsigned transaction(s)");

                var signRequest = new kaspaWalletd.SignRequest
                {
                    Password = extraPoolPaymentProcessingConfig?.WalletPassword ?? null
                };
                signRequest.UnsignedTransactions.Add(unsignedTransaction.UnsignedTransactions);

                var callSignedTransaction = walletRpc.SignAsync(signRequest);
                signedTransaction = await Guard(() => callSignedTransaction.ResponseAsync, ex =>
                {
                    txFailures.Add(Tuple.Create(amount, ex));
                });
                callSignedTransaction.Dispose();

                logger.Debug(()=> $"[{LogCategory}] [{transferId}] {(signedTransaction?.SignedTransactions == null ? 0 : signedTransaction?.SignedTransactions.Count)} signed transaction(s) created");

                // we have transactions to broadcast
                if(signedTransaction?.SignedTransactions.Count > 0)
                {
                    var broadcastRequest = new kaspaWalletd.BroadcastRequest();
                    kaspaWalletd.BroadcastResponse broadcastTransaction;

                    logger.Info(()=> $"[{LogCategory}] [{transferId}] 3/3 Broadcast {signedTransaction.SignedTransactions.Count} signed transaction(s)");

                    broadcastRequest.Transactions.Add(signedTransaction.SignedTransactions);
                    var callBroadcast = walletRpc.BroadcastAsync(broadcastRequest);
                    broadcastTransaction = await Guard(() => callBroadcast.ResponseAsync,
                        ex=> logger.Warn(ex));
                    callBroadcast.Dispose();

                    logger.Debug(()=> $"[{LogCategory}] {(broadcastTransaction?.TxIDs == null ? 0 : broadcastTransaction?.TxIDs.Count)} transaction ID(s) returned");

                    if(broadcastTransaction?.TxIDs.Count > 0)
                    {
                        var txId = broadcastTransaction?.TxIDs.First();

                        logger.Info(() => $"[{LogCategory}] [{amount.Key} - {FormatAmount(amount.Value)}] Payment transaction id: {txId}");

                        successBalances.Add(new Balance
                        {
                            PoolId = poolConfig.Id,
                            Address = amount.Key,
                            Amount = amount.Value,
                        }, txId);
                    }
                }
            }
        }

        if(successBalances.Any())
        {
            await PersistPaymentsAsync(successBalances);

            NotifyPayoutSuccess(poolConfig.Id, successBalances.Keys.ToArray(), successBalances.Values.ToArray(), null);
        }

        if(txFailures.Any())
        {
            var failureBalances = txFailures.Select(x=> new Balance { Amount = x.Item1.Value }).ToArray();
            var error = string.Join(", ", txFailures.Select(x => $"{x.Item1.Key} {FormatAmount(x.Item1.Value)}: {x.Item2.Message}"));

            logger.Error(()=> $"[{LogCategory}] Failed to transfer the following balances: {error}");

            NotifyPayoutFailure(poolConfig.Id, failureBalances, error, null);
        }
    }

    public override double AdjustShareDifficulty(double difficulty)
    {
        var coin = poolConfig.Template.As<KaspaCoinTemplate>();

        switch(coin.Symbol)
        {
            case "SPR":

                return difficulty * SpectreConstants.Pow2xDiff1TargetNumZero * (double) SpectreConstants.MinHash;
            default:

                return difficulty * KaspaConstants.Pow2xDiff1TargetNumZero * (double) KaspaConstants.MinHash;
        }
    }

    public double AdjustBlockEffort(double effort)
    {
        var coin = poolConfig.Template.As<KaspaCoinTemplate>();

        switch(coin.Symbol)
        {
            case "SPR":

                return effort * SpectreConstants.Pow2xDiff1TargetNumZero * (double) SpectreConstants.MinHash;
            default:

                return effort * KaspaConstants.Pow2xDiff1TargetNumZero * (double) KaspaConstants.MinHash;
        }
    }
    
    #endregion // IPayoutHandler

    private class PaymentException : Exception
    {
        public PaymentException(string msg) : base(msg)
        {
        }
    }
}