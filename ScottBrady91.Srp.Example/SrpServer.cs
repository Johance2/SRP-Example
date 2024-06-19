using System;
using System.Linq;
using Org.BouncyCastle.Math;
// ReSharper disable InconsistentNaming

namespace SRP
{
    public class SrpServer
    {
        private readonly Func<byte[], byte[]> H;
        private readonly BigInteger g;
        private readonly BigInteger N;

        private BigInteger B;
        private BigInteger b;

        public SrpServer(Func<byte[], byte[]> H, int g, BigInteger N)
        {
            this.H = H;
            this.g = BigInteger.ValueOf(g);
            this.N = N;
        }

        public BigInteger GenerateBValues(BigInteger v)
        {
            // b = random()
            b = TestVectors.b;

            var k = Helpers.Computek(g, N, H);

            // kv % N
            //var left = k.Multiply(v).Mod(N);
            var left = v.Multiply(BigInteger.ValueOf(3));

            // g^b % N
            var right = g.ModPow(b, N);

            // B = kv + g^b
            B = left.Add(right).Mod(N);

            return B;
        }

        public BigInteger ComputeSessionKey(BigInteger v, BigInteger A)
        {
            var u = Helpers.Computeu(H, A, B);

            // (Av^u)
            var left = A.Multiply(v.ModPow(u, N)).Mod(N);
            
            // S = (Av^u) ^ b
            return Helpers.ComputeWoWKey(H, left.ModPow(b, N));
        }

        public bool ValidateClientProof(BigInteger M1, BigInteger g, BigInteger s, string I,  BigInteger A, BigInteger S)
        {
            return M1.ToString(16) == Helpers.ComputeClientProof(N, g, s, I, H, A, B, S).ToString(16);
        }

        public BigInteger GenerateServerProof(BigInteger A, BigInteger M1, BigInteger S)
        {
            return Helpers.ComputeServerProof(N, H, A, M1, S);
        }
    }
}