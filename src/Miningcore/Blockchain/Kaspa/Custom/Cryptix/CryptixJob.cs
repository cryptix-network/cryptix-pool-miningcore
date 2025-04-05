using System;
using System.IO;
using System.Linq;
using System.Numerics;
using Miningcore.Contracts;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.Algorithms;
using Miningcore.Extensions;
using Miningcore.Native;
using Miningcore.Stratum;
using Miningcore.Util;
using NBitcoin;
using kaspad = Miningcore.Blockchain.Kaspa.Kaspad;

namespace Miningcore.Blockchain.Kaspa.Custom.Cryptix;

public class CryptixJob : KaspaJob
{

    // === CONFIG ===

    // Shares per Second
    private DateTime _lastShareTime = DateTime.MinValue;

    private const int MaxSharesPerSecond = 3; // 3 Shares per Second allowed for every worker

    // Share Values Check
    private Dictionary<string, HashSet<string>> _userShares = new Dictionary<string, HashSet<string>>();
    private Dictionary<string, DateTime> _userLastShareTime = new Dictionary<string, DateTime>();
    private const int MaxStoredShares = 100; // Save last 100 Shares for comparing

    // Hashers
    protected Blake3 blake3Hasher;
    protected Sha3_256 sha3_256Hasher;

    private static HashSet<string> AcceptedHashes = new HashSet<string>();

    public CryptixJob(IHashAlgorithm customBlockHeaderHasher, IHashAlgorithm customCoinbaseHasher, IHashAlgorithm customShareHasher)
        : base(customBlockHeaderHasher, customCoinbaseHasher, customShareHasher)
    {

         this.sha3_256Hasher = new Sha3_256();
         this.blake3Hasher = new Blake3();
    }

    protected override Span<byte> ComputeCoinbase(Span<byte> prePowHash, Span<byte> data)
    {
        byte[] sha3Hash = new byte[32];
        data.Slice(0, 32).CopyTo(sha3Hash);

        ushort[][] matrix = GenerateMatrix(prePowHash);

        // Nibbles
        byte[] nibbles = new byte[64];
        for (int i = 0; i < 32; i++)
        {
            nibbles[2 * i] = (byte)(data[i] >> 4);
            nibbles[2 * i + 1] = (byte)(data[i] & 0x0F);
        }

        byte[] product = new byte[32];
        byte[] nibbleProduct = new byte[32];

        for (int i = 0; i < 32; i++)
        {
            uint sum1 = 0, sum2 = 0, sum3 = 0, sum4 = 0;

            for (int j = 0; j < 64; j++)
            {
                uint elem = nibbles[j];
                sum1 += ((uint)matrix[2 * i][j]) * elem;
                sum2 += ((uint)matrix[2 * i + 1][j]) * elem;
                sum3 += ((uint)matrix[i + 2][j]) * elem;
                sum4 += ((uint)matrix[i + 3][j]) * elem;
            }

            // Rotate helpers
            static uint RotateLeft(uint value, int bits) => (value << bits) | (value >> (32 - bits));
            static uint RotateRight(uint value, int bits) => (value >> bits) | (value << (32 - bits));

            // A Nibble
            byte aNibble = (byte)(
                (sum1 & 0xF)
                ^ ((sum2 >> 4) & 0xF)
                ^ ((sum3 >> 8) & 0xF)
                ^ ((sum1 * 0xABCD >> 12) & 0xF)
                ^ ((sum1 * 0x1234 >> 8) & 0xF)
                ^ ((sum2 * 0x5678 >> 16) & 0xF)
                ^ ((sum3 * 0x9ABC >> 4) & 0xF)
                ^ ((RotateLeft(sum1, 3) & 0xF) ^ (RotateRight(sum3, 5) & 0xF))
            );

            // B Nibble
            byte bNibble = (byte)(
                (sum2 & 0xF)
                ^ ((sum1 >> 4) & 0xF)
                ^ ((sum4 >> 8) & 0xF)
                ^ ((sum2 * 0xDCBA >> 14) & 0xF)
                ^ ((sum2 * 0x8765 >> 10) & 0xF)
                ^ ((sum1 * 0x4321 >> 6) & 0xF)
                ^ ((RotateLeft(sum4, 2) ^ RotateRight(sum1, 1)) & 0xF)
            );

            // C Nibble
            byte cNibble = (byte)(
                (sum3 & 0xF)
                ^ ((sum2 >> 4) & 0xF)
                ^ ((sum2 >> 8) & 0xF)
                ^ ((sum3 * 0xF135 >> 10) & 0xF)
                ^ ((sum3 * 0x2468 >> 12) & 0xF)
                ^ ((sum4 * 0xACEF >> 8) & 0xF)
                ^ ((sum2 * 0x1357 >> 4) & 0xF)
                ^ ((RotateLeft(sum3, 5) & 0xF) ^ (RotateRight(sum1, 7) & 0xF))
            );

            // D Nibble
            byte dNibble = (byte)(
                (sum1 & 0xF)
                ^ ((sum4 >> 4) & 0xF)
                ^ ((sum1 >> 8) & 0xF)
                ^ ((sum4 * 0x57A3 >> 6) & 0xF)
                ^ ((sum3 * 0xD4E3 >> 12) & 0xF)
                ^ ((sum1 * 0x9F8B >> 10) & 0xF)
                ^ ((RotateLeft(sum4, 4) ^ (sum1 + sum2)) & 0xF)
            );

            nibbleProduct[i] = (byte)((cNibble << 4) | dNibble);
            product[i] = (byte)((aNibble << 4) | bNibble);
        }

        // Final XOR
        for (int i = 0; i < 32; i++)
        {
            product[i] ^= data[i];
            nibbleProduct[i] ^= data[i];
        }

        
        byte[] productBeforeOct = (byte[])product.Clone();

        // ** Octonion **
        long[] octonion_result = new long[8];
        OctonionHash(product, octonion_result);

        for (int i = 0; i < 32; i++) {
            long oct_value = octonion_result[i / 8];
            
            byte oct_value_u8 = (byte)((oct_value >> (8 * (i % 8))) & 0xFF);
            
            product[i] ^= oct_value_u8;
        }
                    
        // **Non-Linear S-Box**
        byte[] sbox = new byte[256];

        for (int i = 0; i < 256; i++)
        {
            byte i_u8 = (byte)i;
            
            byte[] sourceArray;
            byte rotateLeftVal, rotateRightVal;

            if (i_u8 < 16)
            {
                sourceArray = product;
                rotateLeftVal = (byte)((nibbleProduct[3] ^ 0x4F) * 3 % 256);
                rotateRightVal = (byte)((sha3Hash[2] ^ 0xD3) * 5 % 256);
            }
            else if (i_u8 < 32)
            {
                sourceArray = sha3Hash;
                rotateLeftVal = (byte)((product[7] ^ 0xA6) * 2 % 256);
                rotateRightVal = (byte)((nibbleProduct[5] ^ 0x5B) * 7 % 256);
            }
            else if (i_u8 < 48)
            {
                sourceArray = nibbleProduct;
                rotateLeftVal = (byte)((productBeforeOct[1] ^ 0x9C) * 9 % 256);
                rotateRightVal = (byte)((product[0] ^ 0x8E) * 3 % 256);
            }
            else if (i_u8 < 64)
            {
                sourceArray = sha3Hash;
                rotateLeftVal = (byte)((product[6] ^ 0x71) * 4 % 256);
                rotateRightVal = (byte)((productBeforeOct[3] ^ 0x2F) * 5 % 256);
            }
            else if (i_u8 < 80)
            {
                sourceArray = productBeforeOct;
                rotateLeftVal = (byte)((nibbleProduct[4] ^ 0xB2) * 3 % 256);
                rotateRightVal = (byte)((sha3Hash[7] ^ 0x6D) * 7 % 256);
            }
            else if (i_u8 < 96)
            {
                sourceArray = sha3Hash;
                rotateLeftVal = (byte)((product[0] ^ 0x58) * 6 % 256);
                rotateRightVal = (byte)((nibbleProduct[1] ^ 0xEE) * 9 % 256);
            }
            else if (i_u8 < 112)
            {
                sourceArray = product;
                rotateLeftVal = (byte)((productBeforeOct[2] ^ 0x37) * 2 % 256);
                rotateRightVal = (byte)((sha3Hash[6] ^ 0x44) * 6 % 256);
            }
            else if (i_u8 < 128)
            {
                sourceArray = sha3Hash;
                rotateLeftVal = (byte)((product[5] ^ 0x1A) * 5 % 256);
                rotateRightVal = (byte)((sha3Hash[4] ^ 0x7C) * 8 % 256);
            }
            else if (i_u8 < 144)
            {
                sourceArray = productBeforeOct;
                rotateLeftVal = (byte)((nibbleProduct[3] ^ 0x93) * 7 % 256);
                rotateRightVal = (byte)((product[2] ^ 0xAF) * 3 % 256);
            }
            else if (i_u8 < 160)
            {
                sourceArray = sha3Hash;
                rotateLeftVal = (byte)((product[7] ^ 0x29) * 9 % 256);
                rotateRightVal = (byte)((nibbleProduct[5] ^ 0xDC) * 2 % 256);
            }
            else if (i_u8 < 176)
            {
                sourceArray = nibbleProduct;
                rotateLeftVal = (byte)((productBeforeOct[1] ^ 0x4E) * 4 % 256);
                rotateRightVal = (byte)((sha3Hash[0] ^ 0x8B) * 3 % 256);
            }
            else if (i_u8 < 192)
            {
                sourceArray = sha3Hash;
                rotateLeftVal = (byte)((nibbleProduct[6] ^ 0xF3) * 5 % 256);
                rotateRightVal = (byte)((productBeforeOct[3] ^ 0x62) * 8 % 256);
            }
            else if (i_u8 < 208)
            {
                sourceArray = productBeforeOct;
                rotateLeftVal = (byte)((product[4] ^ 0xB7) * 6 % 256);
                rotateRightVal = (byte)((product[7] ^ 0x15) * 2 % 256);
            }
            else if (i_u8 < 224)
            {
                sourceArray = sha3Hash;
                rotateLeftVal = (byte)((product[0] ^ 0x2D) * 8 % 256);
                rotateRightVal = (byte)((productBeforeOct[1] ^ 0xC8) * 7 % 256);
            }
            else if (i_u8 < 240)
            {
                sourceArray = product;
                rotateLeftVal = (byte)((productBeforeOct[2] ^ 0x6F) * 3 % 256);
                rotateRightVal = (byte)((nibbleProduct[6] ^ 0x99) * 9 % 256);
            }
            else
            {
                sourceArray = sha3Hash;
                rotateLeftVal = (byte)((nibbleProduct[5] ^ 0xE1) * 7 % 256);
                rotateRightVal = (byte)((sha3Hash[4] ^ 0x3B) * 5 % 256);
            }

            byte value = 
                (i_u8 < 16) ? (byte)((product[i_u8 % 32] * 0x03 + i_u8 * 0xAA) & 0xFF) :
                (i_u8 < 32) ? (byte)((sha3Hash[(i_u8 - 16) % 32] * 0x05 + (i_u8 - 16) * 0xBB) & 0xFF) :
                (i_u8 < 48) ? (byte)((productBeforeOct[(i_u8 - 32) % 32] * 0x07 + (i_u8 - 32) * 0xCC) & 0xFF) :
                (i_u8 < 64) ? (byte)((nibbleProduct[(i_u8 - 48) % 32] * 0x0F + (i_u8 - 48) * 0xDD) & 0xFF) :
                (i_u8 < 80) ? (byte)((product[(i_u8 - 64) % 32] * 0x11 + (i_u8 - 64) * 0xEE) & 0xFF) :
                (i_u8 < 96) ? (byte)((sha3Hash[(i_u8 - 80) % 32] * 0x13 + (i_u8 - 80) * 0xFF) & 0xFF) :
                (i_u8 < 112) ? (byte)((productBeforeOct[(i_u8 - 96) % 32] * 0x17 + (i_u8 - 96) * 0x11) & 0xFF) :
                (i_u8 < 128) ? (byte)((nibbleProduct[(i_u8 - 112) % 32] * 0x19 + (i_u8 - 112) * 0x22) & 0xFF) :
                (i_u8 < 144) ? (byte)((product[(i_u8 - 128) % 32] * 0x1D + (i_u8 - 128) * 0x33) & 0xFF) :
                (i_u8 < 160) ? (byte)((sha3Hash[(i_u8 - 144) % 32] * 0x1F + (i_u8 - 144) * 0x44) & 0xFF) :
                (i_u8 < 176) ? (byte)((productBeforeOct[(i_u8 - 160) % 32] * 0x23 + (i_u8 - 160) * 0x55) & 0xFF) :
                (i_u8 < 192) ? (byte)((nibbleProduct[(i_u8 - 176) % 32] * 0x29 + (i_u8 - 176) * 0x66) & 0xFF) :
                (i_u8 < 208) ? (byte)((product[(i_u8 - 192) % 32] * 0x2F + (i_u8 - 192) * 0x77) & 0xFF) :
                (i_u8 < 224) ? (byte)((sha3Hash[(i_u8 - 208) % 32] * 0x31 + (i_u8 - 208) * 0x88) & 0xFF) :
                (i_u8 < 240) ? (byte)((productBeforeOct[(i_u8 - 224) % 32] * 0x37 + (i_u8 - 224) * 0x99) & 0xFF) :
                            (byte)((nibbleProduct[(i_u8 - 240) % 32] * 0x3F + (i_u8 - 240) * 0xAA) & 0xFF);
                            
            int rotateLeftShift = (product[(i + 1) % 32] + i) % 8;
            int rotateRightShift = (sha3Hash[(i + 2) % 32] + i) % 8;

            int rotationLeft = (rotateLeftVal << rotateLeftShift) | (rotateLeftVal >> (8 - rotateLeftShift));
            int rotationRight = (rotateRightVal >> rotateRightShift) | (rotateRightVal << (8 - rotateRightShift));

            rotationLeft &= 0xFF;
            rotationRight &= 0xFF;

            int index = (i + rotationLeft + rotationRight) % 32;
            
            sbox[i] = (byte)(sourceArray[index] ^ value);
        }

        // Update Sbox Values
        int index_update = (productBeforeOct[2] % 8) + 1;
        int iterations = 1 + (product[index_update] % 2);

        for (int j = 0; j < iterations; j++) {
            byte[] temp_sbox = (byte[])sbox.Clone();

            for (int i = 0; i < 256; i++) {
                byte value = temp_sbox[i];

                byte rotate_left_shift = (byte)((product[(i + 1) % product.Length] + i + (i * 3)) % 8);
                byte rotate_right_shift = (byte)((sha3Hash[(i + 2) % sha3Hash.Length] + i + (i * 5)) % 8);

                byte rotated_value = RotateLeftu8(value, rotate_left_shift);
                rotated_value |= RotateRightu8(value, rotate_right_shift);

                byte base_value = (byte)((i + (product[(i * 3) % product.Length] ^ sha3Hash[(i * 7) % sha3Hash.Length])) & 0xFF);
                base_value ^= 0xA5;

                byte shifted_value = RotateLeftu8(base_value, (byte)(i % 8));
                byte xor_value = (byte)(shifted_value ^ 0x55);

                value ^= rotated_value;
                value ^= xor_value;

                temp_sbox[i] = value;
            }

            sbox = (byte[])temp_sbox.Clone();
        }
    
        // Blake3 Chaining
        int index_blake = (productBeforeOct[5] % 8) + 1;  
        int iterations_blake = 1 + (product[index_blake] % 3);

        byte[] b3_hash_array = (byte[])product.Clone();
        Span<byte> output = stackalloc byte[32];

        for (int j = 0; j < iterations_blake; j++) {
            // BLAKE3 Hashing
            blake3Hasher.Digest(b3_hash_array, output);
            b3_hash_array = output.ToArray();
        }  

        // Apply S-Box to the product with XOR
        for (int i = 0; i < 32; i++) {
            byte[] ref_array = (i * 31 % 4) switch {
                0 => nibbleProduct,
                1 => sha3Hash,
                2 => product,
                _ => productBeforeOct,
            };

            int byte_val = ref_array[(i * 13) % ref_array.Length];

            int index_end = (byte_val + product[(i * 31) % product.Length] 
                            + sha3Hash[(i * 19) % sha3Hash.Length] 
                            + i * 41) % 256;

            b3_hash_array[i] ^= sbox[index_end]; 
        }

        // return
        return new Span<byte>(b3_hash_array);
    }
    

 protected override Share ProcessShareInternal(StratumConnection worker, string nonce)
    {
        var context = worker.ContextAs<KaspaWorkerContext>();

        BlockTemplate.Header.Nonce = Convert.ToUInt64(nonce, 16);

        var prePowHashBytes = SerializeHeader(BlockTemplate.Header, true);
        var coinbaseBytes = SerializeCoinbase(prePowHashBytes, BlockTemplate.Header.Timestamp, BlockTemplate.Header.Nonce);

        Span<byte> sha3_hash = stackalloc byte[32];
        coinbaseBytes.CopyTo(sha3_hash);

        byte first_byte = sha3_hash[0];
        byte iteration_count = (byte)((first_byte % 2) + 1);

        for (byte i = 0; i < iteration_count; ++i)
        {
            sha3_256Hasher.Digest(sha3_hash, sha3_hash);

            if ((sha3_hash[1] % 4) == 0)
            {
                byte repeat = (byte)((sha3_hash[2] % 4) + 1);
                for (byte j = 0; j < repeat; ++j)
                {
                    byte target_byte = (byte)((sha3_hash[1] + i) % 32);
                    byte xor_value = (byte)(sha3_hash[i % 16] ^ 0xA5);
                    sha3_hash[target_byte] ^= xor_value;

                    byte rotation_byte = sha3_hash[i % 32];
                    byte rotation_amount = (byte)(((sha3_hash[1] + sha3_hash[3]) % 4) + 2);
                    sha3_hash[target_byte] = (rotation_byte % 2 == 0)
                        ? RotateLeft(sha3_hash[target_byte], rotation_amount)
                        : RotateRight(sha3_hash[target_byte], rotation_amount);

                    byte shift_amount = (byte)(((sha3_hash[5] + sha3_hash[1]) % 3) + 1);
                    sha3_hash[target_byte] ^= RotateLeft(sha3_hash[target_byte], shift_amount);
                }
            }
            else if ((sha3_hash[3] % 3) == 0)
            {
                byte repeat = (byte)((sha3_hash[4] % 5) + 1);
                for (byte j = 0; j < repeat; ++j)
                {
                    byte target_byte = (byte)((sha3_hash[6] + i) % 32);
                    byte xor_value = (byte)(sha3_hash[i % 16] ^ 0x55);
                    sha3_hash[target_byte] ^= xor_value;

                    byte rotation_byte = sha3_hash[i % 32];
                    byte rotation_amount = (byte)(((sha3_hash[7] + sha3_hash[2]) % 6) + 1);
                    sha3_hash[target_byte] = (rotation_byte % 2 == 0)
                        ? RotateLeft(sha3_hash[target_byte], rotation_amount)
                        : RotateRight(sha3_hash[target_byte], rotation_amount);

                    byte shift_amount = (byte)(((sha3_hash[1] + sha3_hash[3]) % 4) + 1);
                    sha3_hash[target_byte] ^= RotateLeft(sha3_hash[target_byte], shift_amount);
                }
            }
            else if ((sha3_hash[2] % 6) == 0)
            {
                byte repeat = (byte)((sha3_hash[6] % 4) + 1);
                for (byte j = 0; j < repeat; ++j)
                {
                    byte target_byte = (byte)((sha3_hash[10] + i) % 32);
                    byte xor_value = (byte)(sha3_hash[i % 16] ^ 0xFF);
                    sha3_hash[target_byte] ^= xor_value;

                    byte rotation_byte = sha3_hash[i % 32];
                    byte rotation_amount = (byte)(((sha3_hash[7] + sha3_hash[7]) % 7) + 1);
                    sha3_hash[target_byte] = (rotation_byte % 2 == 0)
                        ? RotateLeft(sha3_hash[target_byte], rotation_amount)
                        : RotateRight(sha3_hash[target_byte], rotation_amount);

                    byte shift_amount = (byte)(((sha3_hash[3] + sha3_hash[5]) % 5) + 2);
                    sha3_hash[target_byte] ^= RotateLeft(sha3_hash[target_byte], shift_amount);
                }
            }
            else if ((sha3_hash[7] % 5) == 0)
            {
                byte repeat = (byte)((sha3_hash[8] % 4) + 1);
                for (byte j = 0; j < repeat; ++j)
                {
                    byte target_byte = (byte)((sha3_hash[25] + i) % 32);
                    byte xor_value = (byte)(sha3_hash[i % 16] ^ 0x66);
                    sha3_hash[target_byte] ^= xor_value;

                    byte rotation_byte = sha3_hash[i % 32];
                    byte rotation_amount = (byte)(((sha3_hash[1] + sha3_hash[3]) % 4) + 2);
                    sha3_hash[target_byte] = (rotation_byte % 2 == 0)
                        ? RotateLeft(sha3_hash[target_byte], rotation_amount)
                        : RotateRight(sha3_hash[target_byte], rotation_amount);

                    byte shift_amount = (byte)(((sha3_hash[1] + sha3_hash[3]) % 4) + 1);
                    sha3_hash[target_byte] ^= RotateLeft(sha3_hash[target_byte], shift_amount);
                }
            }
            else if ((sha3_hash[8] % 7) == 0)
            {
                byte repeat = (byte)((sha3_hash[9] % 5) + 1);
                for (byte j = 0; j < repeat; ++j)
                {
                    byte target_byte = (byte)((sha3_hash[30] + i) % 32);
                    byte xor_value = (byte)(sha3_hash[i % 16] ^ 0x77);
                    sha3_hash[target_byte] ^= xor_value;

                    byte rotation_byte = sha3_hash[i % 32];
                    byte rotation_amount = (byte)(((sha3_hash[2] + sha3_hash[5]) % 5) + 1);
                    sha3_hash[target_byte] = (rotation_byte % 2 == 0)
                        ? RotateLeft(sha3_hash[target_byte], rotation_amount)
                        : RotateRight(sha3_hash[target_byte], rotation_amount);

                    byte shift_amount = (byte)(((sha3_hash[7] + sha3_hash[9]) % 6) + 2);
                    sha3_hash[target_byte] ^= RotateLeft(sha3_hash[target_byte], shift_amount);
                }
            }
        }

        Span<byte> hashCoinbaseBytes = stackalloc byte[32];
        shareHasher.Digest(ComputeCoinbase(prePowHashBytes, sha3_hash), hashCoinbaseBytes);

        var targetHashCoinbaseBytes = new Target(new BigInteger(hashCoinbaseBytes.ToNewReverseArray(), true, true));
        var hashCoinbaseBytesValue = targetHashCoinbaseBytes.ToUInt256();

        // Nonce and Diff Check 
        
        bool isHighDiffEnabled = false;
        bool isNonceSpamCheckEnabled = false;
        bool isDuplicateShareCheckEnabled = false;
        
        string contextKey = context.ToString(); 

        var shareDiff = (double)new BigRational(KaspaConstants.Diff1b, targetHashCoinbaseBytes.ToBigInteger()) * shareMultiplier;

        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;

        var isBlockCandidate = hashCoinbaseBytesValue <= blockTargetValue;

        // ---------------------------
        // → PER-USER SHARE TRACKING
        // ---------------------------

        if (!_userLastShareTime.ContainsKey(contextKey))
        {
            _userLastShareTime[contextKey] = DateTime.MinValue;
            _userShares[contextKey] = new HashSet<string>();
        }

        var lastShareTime = _userLastShareTime[contextKey];

        // ---------------------------
        // → NONCE SPAM CHECK
        // ---------------------------

        if (isNonceSpamCheckEnabled && DateTime.Now - lastShareTime < TimeSpan.FromSeconds(1.0 / MaxSharesPerSecond))
        {
            throw new StratumException(StratumError.LowDifficultyShare, "Nonce Spam Share detected. Too many requests.");
        }

        _userLastShareTime[contextKey] = DateTime.Now;

        // ---------------------------
        // → DUPLICATE SHARE CHECK
        // ---------------------------

        string shareIdentifier = BitConverter.ToString(hashCoinbaseBytesValue.ToBytes()).Replace("-", "").ToLower();

        if (isDuplicateShareCheckEnabled && _userShares[contextKey].Contains(shareIdentifier))
        {
            throw new StratumException(StratumError.LowDifficultyShare, "Duplicate share detected. Already submitted.");
        }

        if (_userShares[contextKey].Count >= MaxStoredShares)
        {
            _userShares[contextKey].Remove(_userShares[contextKey].First());
        }

        _userShares[contextKey].Add(shareIdentifier);

        // ---------------------------
        // → DIFFICULTY VALIDATION
        // ---------------------------

        // Min Diff
        if(!isBlockCandidate && ratio < 0.99)
        {
            // check if share matched the previous difficulty from before a vardiff retarget
            if(context.VarDiff?.LastUpdate != null && context.PreviousDifficulty.HasValue)
            {
                ratio = shareDiff / context.PreviousDifficulty.Value;

                if(ratio < 0.99)
                    throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");

                // use previous difficulty
                stratumDifficulty = context.PreviousDifficulty.Value;
            }

            else
                throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");
        }

        // Max Diff
        const double MAX_RATIO = 99999999999;

        if (!isBlockCandidate && ratio > MAX_RATIO && isHighDiffEnabled)
        {
            if (hashCoinbaseBytesValue <= blockTargetValue)
            {
                throw new StratumException(StratumError.LowDifficultyShare, $"Fake high difficulty share (ratio: {ratio}, shareDiff: {shareDiff})");
            }

            if (context.VarDiff?.LastUpdate != null && context.PreviousDifficulty.HasValue)
            {
                ratio = shareDiff / context.PreviousDifficulty.Value;

                if (ratio > MAX_RATIO)
                {
                    throw new StratumException(StratumError.LowDifficultyShare, $"Fake high difficulty share (ratio: {ratio}, shareDiff: {shareDiff})");
                }

                stratumDifficulty = context.PreviousDifficulty.Value;
            }
            else
            {
                throw new StratumException(StratumError.LowDifficultyShare, $"Fake high difficulty share (ratio: {ratio}, shareDiff: {shareDiff})");
            }
        }

        // ---------------------------
        // → RESULT OBJECT
        // ---------------------------

        var result = new Share
        {
            BlockHeight = (long)BlockTemplate.Header.DaaScore,
            NetworkDifficulty = Difficulty,
            Difficulty = context.Difficulty / shareMultiplier
        };

        if (isBlockCandidate)
        {
            var hashBytes = SerializeHeader(BlockTemplate.Header, false);

            result.IsBlockCandidate = true;
            result.BlockHash = hashBytes.ToHexString();
        }

        return result;

    }

    // Helpers Rotate
    private byte RotateLeft(byte value, byte shiftAmount)
    {
        return (byte)((value << shiftAmount) | (value >> (8 - shiftAmount)));
    }

    private byte RotateRight(byte value, byte shiftAmount)
    {
        return (byte)((value >> shiftAmount) | (value << (8 - shiftAmount)));
    }

    // Octonion
    public static void OctonionMultiply(long[] a, long[] b, long[] result)
    {
        long[] res = new long[8];

    // e0
    res[0] = WrappingMul(a[0], b[0])
            .WrappingSub(WrappingMul(a[1], b[1]))
            .WrappingSub(WrappingMul(a[2], b[2]))
            .WrappingSub(WrappingMul(a[3], b[3]))
            .WrappingSub(WrappingMul(a[4], b[4]))
            .WrappingSub(WrappingMul(a[5], b[5]))
            .WrappingSub(WrappingMul(a[6], b[6]))
            .WrappingSub(WrappingMul(a[7], b[7]));

    // e1
    res[1] = WrappingMul(a[0], b[1])
            .WrappingAdd(WrappingMul(a[1], b[0]))
            .WrappingAdd(WrappingMul(a[2], b[3]))
            .WrappingSub(WrappingMul(a[3], b[2]))
            .WrappingAdd(WrappingMul(a[4], b[5]))
            .WrappingSub(WrappingMul(a[5], b[4]))
            .WrappingSub(WrappingMul(a[6], b[7]))
            .WrappingAdd(WrappingMul(a[7], b[6]));

    // e2
    res[2] = WrappingMul(a[0], b[2])
            .WrappingSub(WrappingMul(a[1], b[3]))
            .WrappingAdd(WrappingMul(a[2], b[0]))
            .WrappingAdd(WrappingMul(a[3], b[1]))
            .WrappingAdd(WrappingMul(a[4], b[6]))
            .WrappingSub(WrappingMul(a[5], b[7]))
            .WrappingAdd(WrappingMul(a[6], b[4]))
            .WrappingSub(WrappingMul(a[7], b[5]));

    // e3
    res[3] = WrappingMul(a[0], b[3])
            .WrappingAdd(WrappingMul(a[1], b[2]))
            .WrappingSub(WrappingMul(a[2], b[1]))
            .WrappingAdd(WrappingMul(a[3], b[0]))
            .WrappingAdd(WrappingMul(a[4], b[7]))
            .WrappingAdd(WrappingMul(a[5], b[6]))
            .WrappingSub(WrappingMul(a[6], b[5]))
            .WrappingAdd(WrappingMul(a[7], b[4]));

    // e4
    res[4] = WrappingMul(a[0], b[4])
            .WrappingSub(WrappingMul(a[1], b[5]))
            .WrappingSub(WrappingMul(a[2], b[6]))
            .WrappingSub(WrappingMul(a[3], b[7]))
            .WrappingAdd(WrappingMul(a[4], b[0]))
            .WrappingAdd(WrappingMul(a[5], b[1]))
            .WrappingAdd(WrappingMul(a[6], b[2]))
            .WrappingAdd(WrappingMul(a[7], b[3]));

    // e5
    res[5] = WrappingMul(a[0], b[5])
            .WrappingAdd(WrappingMul(a[1], b[4]))
            .WrappingSub(WrappingMul(a[2], b[7]))
            .WrappingAdd(WrappingMul(a[3], b[6]))
            .WrappingSub(WrappingMul(a[4], b[1]))
            .WrappingAdd(WrappingMul(a[5], b[0]))
            .WrappingAdd(WrappingMul(a[6], b[3]))
            .WrappingAdd(WrappingMul(a[7], b[2]));

    // e6
    res[6] = WrappingMul(a[0], b[6])
            .WrappingAdd(WrappingMul(a[1], b[7]))
            .WrappingAdd(WrappingMul(a[2], b[4]))
            .WrappingSub(WrappingMul(a[3], b[5]))
            .WrappingSub(WrappingMul(a[4], b[2]))
            .WrappingAdd(WrappingMul(a[5], b[3]))
            .WrappingAdd(WrappingMul(a[6], b[0]))
            .WrappingAdd(WrappingMul(a[7], b[1]));

    // e7
    res[7] = WrappingMul(a[0], b[7])
            .WrappingSub(WrappingMul(a[1], b[6]))
            .WrappingAdd(WrappingMul(a[2], b[5]))
            .WrappingAdd(WrappingMul(a[3], b[4]))
            .WrappingSub(WrappingMul(a[4], b[3]))
            .WrappingAdd(WrappingMul(a[5], b[2]))
            .WrappingAdd(WrappingMul(a[6], b[1]))
            .WrappingAdd(WrappingMul(a[7], b[0]));

        for (int i = 0; i < 8; i++)
        {
            result[i] = res[i];
        }
    }
    
      public static void OctonionHash(byte[] inputHash, long[] oct)
    {
        for (int i = 0; i < 8; i++)
        {
            oct[i] = (long)inputHash[i];
        }

        for (int i = 8; i < 32; i++)
        {
            long[] rotation = new long[8];
            for (int j = 0; j < 8; j++)
            {
                rotation[j] = (long)inputHash[(i + j) % 32];
            }

            long[] result = new long[8];
            OctonionMultiply(oct, rotation, result);

            for (int j = 0; j < 8; j++)
            {
                oct[j] = result[j];
            }
        }
    }

    // Helpers

    public static long WrappingAdd(long a, long b)
    {
        unchecked
        {
            return a + b;
        }
    }

    public static long WrappingSub(long a, long b)
    {
        unchecked
        {
            return a - b;
        }
    }

    public static long WrappingMul(long a, long b)
    {
        unchecked
        {
            return a * b;
        }
    }

    public static byte WrappingAdd8(byte a, byte b)
    {
        return (byte)((a + b) & 0xFF);
    }

    public static byte WrappingMul8(byte a, byte b)
    {
        return (byte)((a * b) & 0xFF);
    }

    byte RotateLeftu8(byte value, byte shift) {
        return (byte)((value << shift) | (value >> (8 - shift)));
    }


    byte RotateRightu8(byte value, byte shift) {
        return (byte)((value >> shift) | (value << (8 - shift)));
    }

    /*
    // Sinusoidal Multiply (Tested in Testnet due to architecture rounding errors)
    static void SinusoidalMultiply(byte sinusIn, ref byte sinusOut) {
        byte left = (byte)((sinusIn >> 4) & 0x0F);
        byte right = (byte)(sinusIn & 0x0F);

        for (int i = 0; i < 16; i++) {
            byte temp = right;
            right = (byte)((left ^ ((right * 31 + 13) & 0xFF) ^ (right >> 3) ^ (right * 5)) & 0x0F);
            left = temp;
        }

        byte complexOp = (byte)((left * right + 97) & 0xFF);
        byte nonlinearOp = (byte)((complexOp ^ (right >> 4) ^ (left * 11)) & 0xFF);

        ushort sinusInU16 = (ushort)sinusIn;
        float angle = (sinusInU16 % 360) * (float)(Math.PI / 180.0f);
        float sinValue = (float)Math.Sin(angle);
        byte sinLookup = (byte)(Math.Abs(sinValue) * 255.0f);

        byte modulatedValue = (byte)((sinLookup ^ (sinLookup >> 3) ^ (sinLookup << 1) ^ 0xA5) & 0xFF);
        byte sboxVal = (byte)((modulatedValue ^ (modulatedValue >> 4)) * 43 + 17);
        byte obfuscated = (byte)(((sboxVal >> 2) | (sboxVal << 6)) ^ 0xF3 ^ 0xA5);

        sinusOut = (byte)((obfuscated ^ (sboxVal * 7) ^ nonlinearOp + 0xF1) & 0xFF);
    }
    */

    /*
    // Complex Lookup Table
    static uint ChaoticRandom(uint x) {
        for (int i = 0; i < 5; i++) {
            x = ((x * 3646246005U) << 13) | (x >> (32 - 13));
            x ^= 0xA5A5A5A5;
        }
        return x;
    }


    static List<uint> PrimeFactors(uint n) {
        var factors = new List<uint>();
        uint i = 2;
        while (i * i <= n) {
            while (n % i == 0) {
                factors.Add(i);
                n /= i;
            }
            i += 1;
        }
        if (n > 1) {
            factors.Add(n);
        }
        return factors;
    }

    static uint SerialDependency(uint x, byte rounds) {
        for (int i = 0; i < rounds; i++) {
            x = ((x * 3 + 5) << 7) | (x >> (32 - 7));
            x ^= ChaoticRandom(x);
        }
        return x;
    }

    static byte UnpredictableDepth(uint x) {
        uint noise = ChaoticRandom(x) & 0xF;
        return (byte)(10 + noise);
    }

    static byte RecursiveMultiplicationWithRandomness(byte dynLutInput) {
        byte depth = UnpredictableDepth(dynLutInput);
        return (byte)(SerialDependency(dynLutInput, depth) & 0xFF);
    }

    static byte RecursiveMultiplicationWithFactors(byte dynLutInput, byte depth) {
        uint result = dynLutInput;

        for (int i = 0; i < depth; i++) {
            var factors = PrimeFactors(result);
            foreach (var factor in factors) {
                result = (result * factor) & 0xFFFFFFF;
            }
            result = (result * 3893621) & 0xFFFFFFF;
        }

        return (byte)(result & 0xFF);
    }

    static byte DynamicDepthMultiplication(byte dynLutInput) {
        return RecursiveMultiplicationWithRandomness(dynLutInput);
    }

    static byte ComplexLookupTable(byte dynLutInput) {
        return DynamicDepthMultiplication(dynLutInput);
    }

    // Method to process the complex lookup table on an array
    static void ProcessComplexLookupTable(byte[] input, byte[] output, int numElements) {
        for (int i = 0; i < numElements; i++) {
            output[i] = ComplexLookupTable(input[i]);
        }
    }
    */

}
public static class OctonionMathExtensions
{
    public static long WrappingAdd(this long a, long b)
    {
        unchecked
        {
            return a + b;
        }
    }

    public static long WrappingSub(this long a, long b)
    {
        unchecked
        {
            return a - b;
        }
    }

    public static long WrappingMul(long a, long b)
    {
        unchecked
        {
            return a * b;
        }
    }

    public static byte WrappingAdd8(byte a, byte b)
    {
        return (byte)((a + b) & 0xFF);
    }

    public static byte WrappingMul8(byte a, byte b)
    {
        return (byte)((a * b) & 0xFF);
    }
}