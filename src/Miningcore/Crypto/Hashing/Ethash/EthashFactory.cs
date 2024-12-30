using System.Collections.Concurrent;
using Autofac;

namespace Miningcore.Crypto.Hashing.Ethash;

public static class EthashFactory
{
    private static readonly ConcurrentDictionary<string, IEthashLight> cacheFull = new();

    public static IEthashLight GetEthash(string symbol, IComponentContext ctx, string name)
    {
        if(string.IsNullOrEmpty(symbol) || string.IsNullOrEmpty(name))
            return null;

        // check cache
        if(cacheFull.TryGetValue(symbol, out var result))
            return result;

        result = ctx.ResolveNamed<IEthashLight>(name);

        cacheFull.TryAdd(symbol, result);

        return result;
    }
}