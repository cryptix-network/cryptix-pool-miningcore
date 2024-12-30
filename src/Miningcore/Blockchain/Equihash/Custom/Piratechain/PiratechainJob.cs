using Miningcore.Extensions;
using NBitcoin;

namespace Miningcore.Blockchain.Equihash.Custom.Piratechain;

public class PiratechainJob : EquihashJob
{
    protected override byte[] SerializeBlock(Span<byte> header, Span<byte> coinbase, Span<byte> solution)
    {
        var transactionCount = (uint) BlockTemplate.Transactions.Length + 1; // +1 for prepended coinbase tx
        var rawTransactionBuffer = BuildRawTransactionBuffer();

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            bs.ReadWrite(header);
            bs.ReadWrite(solution);

            var txCount = transactionCount.ToString();
            if (Math.Abs(txCount.Length % 2) == 1)
                txCount = "0" + txCount;

            if (transactionCount < 0xfd)
            {
                var simpleVarIntBytes = (Span<byte>) txCount.HexToByteArray();

                bs.ReadWrite(simpleVarIntBytes);
            }
            else if (transactionCount <= 0x7fff)
            {
                if (txCount.Length == 2)
                    txCount = "00" + txCount;

                var complexHeader = (Span<byte>) new byte[] { 0xFD };
                var complexVarIntBytes = (Span<byte>) txCount.HexToReverseByteArray();

                // concat header and varInt
                Span<byte> complexHeaderVarIntBytes = stackalloc byte[complexHeader.Length + complexVarIntBytes.Length];
                complexHeader.CopyTo(complexHeaderVarIntBytes);
                complexVarIntBytes.CopyTo(complexHeaderVarIntBytes[complexHeader.Length..]);

                bs.ReadWrite(complexHeaderVarIntBytes);
            }

            bs.ReadWrite(coinbase);
            bs.ReadWrite(rawTransactionBuffer);

            return stream.ToArray();
        }
    }
}