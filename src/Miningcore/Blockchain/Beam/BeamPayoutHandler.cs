using System.Data;
using Autofac;
using AutoMapper;
using Miningcore.Blockchain.Beam.Configuration;
using Miningcore.Blockchain.Beam.DaemonRequests;
using Miningcore.Blockchain.Beam.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Extensions;
using Miningcore.Messaging;
using Miningcore.Mining;
using Miningcore.Native;
using Miningcore.Payments;
using Miningcore.Persistence;
using Miningcore.Persistence.Model;
using Miningcore.Persistence.Repositories;
using Miningcore.Rest;
using Miningcore.Rpc;
using Miningcore.Time;
using Miningcore.Util;
using Newtonsoft.Json;
using Contract = Miningcore.Contracts.Contract;
using Newtonsoft.Json.Linq;

namespace Miningcore.Blockchain.Beam;

[CoinFamily(CoinFamily.Beam)]
public class BeamPayoutHandler : PayoutHandlerBase,
    IPayoutHandler
{
    public BeamPayoutHandler(
        IComponentContext ctx,
        IConnectionFactory cf,
        IMapper mapper,
        IShareRepository shareRepo,
        IBlockRepository blockRepo,
        IBalanceRepository balanceRepo,
        IPaymentRepository paymentRepo,
        IMasterClock clock,
        IHttpClientFactory httpClientFactory,
        IMessageBus messageBus) :
        base(cf, mapper, shareRepo, blockRepo, balanceRepo, paymentRepo, clock, messageBus)
    {
        Contract.RequiresNonNull(ctx);
        Contract.RequiresNonNull(balanceRepo);
        Contract.RequiresNonNull(paymentRepo);

        this.ctx = ctx;
        this.httpClientFactory = httpClientFactory;
    }

    private readonly IComponentContext ctx;
    private IHttpClientFactory httpClientFactory;
    private SimpleRestClient restClient;
    private RpcClient rpcClientWallet;
    private BeamPoolConfigExtra extraPoolConfig;
    private string network;

    protected override string LogCategory => "Beam Payout Handler";
    
    private async Task<(bool IsValid, bool IsOffline)> ValidateAddress(string address, CancellationToken ct)
    {
        if(string.IsNullOrEmpty(address))
            return (false, false);
        
        var IsOffline = false;
        var request = new ValidateAddressRequest
        {
            Address = address
        };
        
        // address validation
        var responseWalletRpc = await rpcClientWallet.ExecuteAsync<ValidateAddressResponse>(logger, BeamWalletCommands.ValidateAddress, ct, request);
        
        // Beam wallets come with a lot of flavors
        // I tried to enable payments for most of them but there could be some margin for errors
        // https://github.com/BeamMW/beam/wiki/Beam-wallet-protocol-API-v7.1#create_address
        if (!responseWalletRpc.Response?.IsValid == false)
            return (false, IsOffline);
        
        if (responseWalletRpc.Response?.Type.ToLower() == "max_privacy")
        {
            logger.Warn(() => $"Worker {address} uses a 'Max Privacy' wallet, intended to be used only one time");
        }
        
        else if (responseWalletRpc.Response?.Type.ToLower() == "offline")
        {
            IsOffline = true;
            logger.Info(() => $"Worker {address} uses an 'Offline' wallet. Number of offline payments left: {responseWalletRpc.Response?.Payments}");
            return (responseWalletRpc.Response?.Payments > 0, IsOffline);
        }

        return (responseWalletRpc.Response?.IsValid == true, IsOffline);
    }

    private async Task<bool> EnsureBalance(decimal requiredAmount, BeamCoinTemplate coin, CancellationToken ct)
    {
        var response = await rpcClientWallet.ExecuteAsync<GetBalanceResponse>(logger, BeamWalletCommands.GetBalance, ct, new {});
        
        if(response.Error != null)
        {
            logger.Error(() => $"[{LogCategory}] Daemon command '{BeamWalletCommands.GetBalance}' returned error: {response.Error.Message} code {response.Error.Code}");
            return false;
        }

        var balance = response.Response.Balance / BeamConstants.SmallestUnit;

        if(balance < requiredAmount)
        {
            logger.Info(() => $"[{LogCategory}] {FormatAmount(requiredAmount)} required for payment, but only have {FormatAmount(balance)} available yet. Will try again.");
            return false;
        }

        logger.Info(() => $"[{LogCategory}] Current balance is {FormatAmount(balance)}");
        return true;
    }

    private async Task<string> PayoutAsync(Balance balance, CancellationToken ct)
    {
        // send transaction
        logger.Info(() => $"[{LogCategory}] Sending {FormatAmount(balance.Amount)} to {balance.Address}");

        var amount = (ulong) Math.Floor(balance.Amount * BeamConstants.SmallestUnit);
        
        var (IsValid, IsOffline) = await ValidateAddress(balance.Address, ct);

        var request = new SendTransactionRequest
        {
            From = poolConfig.Address,
            Address = balance.Address,
            Value = amount,
            Offline = IsOffline
        };
        
        // send command
        var response = await rpcClientWallet.ExecuteAsync<SendTransactionResponse>(logger, BeamWalletCommands.SendTransaction, ct, request);
        
        if(response.Error != null)
            throw new Exception($"{BeamWalletCommands.SendTransaction} returned error: {response.Error.Message} code {response.Error.Code}");
        
        var txHash = response.Response.TxId;
        logger.Info(() => $"[{LogCategory}] Payment transaction id: {txHash}");

        // update db
        await PersistPaymentsAsync(new[] { balance }, txHash);

        // done
        return txHash;
    }

    #region IPayoutHandler

    public virtual async Task ConfigureAsync(ClusterConfig cc, PoolConfig pc, CancellationToken ct)
    {
        Contract.RequiresNonNull(pc);

        poolConfig = pc;
        clusterConfig = cc;
        extraPoolConfig = pc.Extra.SafeExtensionDataAs<BeamPoolConfigExtra>();

        logger = LogUtil.GetPoolScopedLogger(typeof(BeamPayoutHandler), pc);

        // configure standard daemon
        var jsonSerializerSettings = ctx.Resolve<JsonSerializerSettings>();
        
        // configure explorer daemon
        var daemonEndpoints = pc.Daemons
            .Where(x => x.Category?.ToLower() == BeamConstants.ExplorerDaemonCategory)
            .ToArray();
            
        restClient = new SimpleRestClient(httpClientFactory, "http://" + daemonEndpoints.First().Host.ToString() + ":" + daemonEndpoints.First().Port.ToString() + "/");
        
        // configure wallet daemon
        var walletDaemonEndpoints = pc.Daemons
            .Where(x => x.Category?.ToLower() == BeamConstants.WalletDaemonCategory)
            .Select(x =>
            {
                if(string.IsNullOrEmpty(x.HttpPath))
                    x.HttpPath = BeamConstants.WalletDaemonRpcLocation;

                return x;
            })
            .ToArray();

        rpcClientWallet = new RpcClient(walletDaemonEndpoints.First(), jsonSerializerSettings, messageBus, pc.Id);
        
        // method available only since wallet API v6.1, so upgrade your node in order to enjoy that feature
        // https://github.com/BeamMW/beam/wiki/Beam-wallet-protocol-API-v6.1
        var responseNetwork = await rpcClientWallet.ExecuteAsync<GetVersionResponse>(logger, BeamWalletCommands.GetVersion, ct, new {});
        if(responseNetwork.Error != null)
        {
            network = responseNetwork.Response?.Network;
        }
        
        else
        {
            network = "N/A [>= wallet API v6.1]";
        }
    }

    public async Task<Block[]> ClassifyBlocksAsync(IMiningPool pool, Block[] blocks, CancellationToken ct)
    {
        Contract.RequiresNonNull(poolConfig);
        Contract.RequiresNonNull(blocks);

        var coin = poolConfig.Template.As<BeamCoinTemplate>();
        var pageSize = 100;
        var pageCount = (int) Math.Ceiling(blocks.Length / (double) pageSize);
        var result = new List<Block>();
        var lastBlock = await restClient.Get<GetStatusResponse>(BeamExplorerCommands.GetStatus, ct);

        for(var i = 0; i < pageCount; i++)
        {
            // get a page full of blocks
            var page = blocks
                .Skip(i * pageSize)
                .Take(pageSize)
                .ToArray();

            // NOTE: beam-node does not support batch-requests???
            for(var j = 0; j < page.Length; j++)
            {
                var block = page[j];
                
                var request = new GetBlockHeaderRequest
                {
                    Height = block.BlockHeight
                };
                
                var rpcResult = await rpcClientWallet.ExecuteAsync<GetBlockHeaderResponse>(logger, BeamWalletCommands.GetBlockHeaders, ct, request);

                if(rpcResult.Error != null)
                {
                    logger.Debug(() => $"[{LogCategory}] Daemon reports error '{rpcResult.Error.Message}' (Code {rpcResult.Error.Code}) for block {block.BlockHeight}");
                    continue;
                }

                // update progress
                block.ConfirmationProgress = Math.Min(1.0d, (double) (lastBlock.Height - block.BlockHeight) / BeamConstants.PayoutMinBlockConfirmations);
                result.Add(block);

                messageBus.NotifyBlockConfirmationProgress(poolConfig.Id, block, coin);
                
                // Be aware for BEAM, the block verification and confirmation must be performed with `block.Hash` if the socket did not return a `Nonceprefix` after login
                bool IsOrphaned = (!string.IsNullOrEmpty(block.Hash)) ? (!string.IsNullOrEmpty(rpcResult.Response?.Pow) && rpcResult.Response?.Pow.Contains(block.Hash) == false) : (!string.IsNullOrEmpty(rpcResult.Response?.BlockHash) && rpcResult.Response?.BlockHash == block.TransactionConfirmationData);

                // orphaned?
                if(IsOrphaned)
                {
                    block.Hash = null;
                    block.Status = BlockStatus.Orphaned;
                    block.Reward = 0;

                    messageBus.NotifyBlockUnlocked(poolConfig.Id, block, coin);
                    continue;
                }

                // matured and spendable?
                if((lastBlock.Height - block.BlockHeight) >= BeamConstants.PayoutMinBlockConfirmations)
                {
                    block.Hash = (!string.IsNullOrEmpty(block.Hash)) ? rpcResult.Response?.BlockHash : null;
                    block.Status = BlockStatus.Confirmed;
                    block.ConfirmationProgress = 1;
                    
                    // Better way of calculating blockReward
                    var maturedBlock = await restClient.Get<GetBlockResponse>(BeamExplorerCommands.GetBlock + block.BlockHeight, ct);
                    
                    block.Reward = (decimal) maturedBlock.Subsidy / BeamConstants.SmallestUnit;

                    logger.Info(() => $"[{LogCategory}] Unlocked block {block.BlockHeight} worth {FormatAmount(block.Reward)}");

                    messageBus.NotifyBlockUnlocked(poolConfig.Id, block, coin);
                }
            }
        }

        return result.ToArray();
    }

    public async Task PayoutAsync(IMiningPool pool, Balance[] balances, CancellationToken ct)
    {
        Contract.RequiresNonNull(balances);

        var coin = poolConfig.Template.As<BeamCoinTemplate>();
        var infoResponse = await restClient.Get<GetStatusResponse>(BeamExplorerCommands.GetStatus, ct);

        if (infoResponse.PeersCount < 3)
        {
            logger.Warn(() => $"[{LogCategory}] Payout aborted. Not enough peers (4 required)");
            return;
        }
        
        // ensure there's enough balance
        if(!await EnsureBalance(balances.Sum(x => x.Amount), coin, ct))
            return;
        
        var txHashes = new List<string>();

        foreach(var balance in balances)
        {
            try
            {
                var txHash = await PayoutAsync(balance, ct);
                txHashes.Add(txHash);
            }

            catch(Exception ex)
            {
                logger.Error(ex);

                NotifyPayoutFailure(poolConfig.Id, new[] { balance }, ex.Message, null);
            }
        }

        if(txHashes.Any())
            NotifyPayoutSuccess(poolConfig.Id, balances, txHashes.ToArray(), null);
    }

    public double AdjustBlockEffort(double effort)
    {
        return effort;
    }

    #endregion // IPayoutHandler
}