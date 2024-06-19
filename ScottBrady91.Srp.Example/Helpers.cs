using System;
using System.Globalization;
using System.Linq;
using Org.BouncyCastle.Math;
using System.Text;
using System.Security.Cryptography;

// ReSharper disable InconsistentNaming

namespace SRP
{
    public static class Helpers
    {
        public static byte[] ToBytes(this string hex)
        {
            var hexAsBytes = new byte[hex.Length / 2];

            for (var i = 0; i < hex.Length; i += 2)
            {
                hexAsBytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            return hexAsBytes;
        }

        // both unsigned and big endian
        public static BigInteger ToSrpBigInt(this byte[] bytes)
        {
            return new BigInteger(1, bytes, false);
        }

        // Add padding character back to hex before parsing
        public static BigInteger ToSrpBigInt(this string hex)
        {
            return new BigInteger(hex, 16);
        }

        public static BigInteger Computek(BigInteger g, BigInteger N ,Func<byte[], byte[]> H)
        {
            // k = H(N, g)
            var NBytes = N.ToByteArrayUnsigned().Reverse().ToArray();
            var gBytes = PadBytes(g.ToByteArrayUnsigned().Reverse().ToArray(), NBytes.Length);

            var k = H(NBytes.Concat(gBytes).ToArray());

            return new BigInteger(1, k, true);
        }

        public static BigInteger Computeu(Func<byte[], byte[]> H, BigInteger A, BigInteger B) 
        {
            return H(A.ToByteArrayUnsigned().Reverse().ToArray()
                    .Concat(B.ToByteArrayUnsigned().Reverse().ToArray())
                    .ToArray())
                    .ToSrpBigInt();
        }

        public static BigInteger ComputeClientProof(
            BigInteger N,
            BigInteger g,
            BigInteger s,
            string I,
            Func<byte[], byte[]> H,
            BigInteger A,
            BigInteger B,
            BigInteger K)
        {
            var nhash = H(N.ToByteArrayUnsigned().Reverse().ToArray());
            var ghash = H(g.ToByteArrayUnsigned().Reverse().ToArray());
            for (int i = 0; i < 20; ++i)
            {
                nhash[i] ^= ghash[i];
            }

            var ihash = H(Encoding.UTF8.GetBytes(I));

            // M1 = H( A | B | S )
            return H(nhash.Concat(ihash)
                    .Concat(s.ToByteArrayUnsigned().Reverse().ToArray())
                    .Concat(A.ToByteArrayUnsigned().Reverse().ToArray())
                    .Concat(B.ToByteArrayUnsigned().Reverse().ToArray())
                    .Concat(K.ToByteArrayUnsigned().Reverse().ToArray())
                    .ToArray())
                .ToSrpBigInt();
        }

        public static BigInteger ComputeServerProof(BigInteger N, Func<byte[], byte[]> H, BigInteger A, BigInteger M1, BigInteger S)
        {
            // M2 = H( A | M1 | S )
            return H(A.ToByteArrayUnsigned().Reverse().ToArray()
                    .Concat(M1.ToByteArrayUnsigned().Reverse().ToArray())
                    .Concat(S.ToByteArrayUnsigned().Reverse().ToArray())
                    .ToArray())
                .ToSrpBigInt();
        }

        public static byte[] PadBytes(byte[] bytes, int length)
        {
            var paddedBytes = new byte[length];
            Array.Copy(bytes, 0, paddedBytes, length - bytes.Length, bytes.Length);

            return paddedBytes;
        }
        public static BigInteger ComputeWoWKey(Func<byte[], byte[]> H, BigInteger S)
        {
            var vk = new byte[40];
            byte[] t1 = new byte[16];
            var t = S.ToByteArrayUnsigned().Reverse().ToArray();
            for (int i = 0; i < 16; i++)
            {
                t1[i] = t[i * 2];
            }

            var hash = H(t1);
            for (int i = 0; i < 20; i++)
            {
                vk[i * 2] = hash[i];
            }
            for (int i = 0; i < 16; ++i)
            {
                t1[i] = t[i * 2 + 1];
            }
            hash = H(t1);

            for (int i = 0; i < 20; ++i)
            {
                vk[i * 2 + 1] = hash[i];
            }
            return vk.ToSrpBigInt();
        }
    }
}