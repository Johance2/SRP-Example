using System;
using System.Linq;
using Org.BouncyCastle.Math;
using System.Text;

// ReSharper disable InconsistentNaming
namespace SRP
{
    public class SrpClient
    {
        private readonly Func<byte[], byte[]> H;
        private readonly BigInteger g;
        private readonly BigInteger N;

        private BigInteger A;
        private BigInteger a;

        public SrpClient(Func<byte[], byte[]> H, int g, BigInteger N)
        {
            this.H = H;
            this.g = BigInteger.ValueOf(g);
            this.N = N;
        }
        public SrpClient(int g, BigInteger N)
        {
            this.H = TestVectors.H;
            this.g = BigInteger.ValueOf(g);
            this.N = N;
        }

        public BigInteger GenerateVerifier(string I, string P, byte[] s)
        {
            // x = H(s | H(I | ":" | P))
            var x = GeneratePrivateKey(I, P, s);

            // v = g^x
            var v = g.ModPow(x, N);

            return v;
        }

        public BigInteger GenerateAValues()
        {
            // a = random()
            a = TestVectors.a;

            // A = g^a
            A = g.ModPow(a, N);

            return A;
        }

        public BigInteger ComputeSessionKey(string I, string P, byte[] s, BigInteger B)
        {
            var u = Helpers.Computeu(H, A, B);
            var x = GeneratePrivateKey(I, P, s);
            //var k = Helpers.Computek(g, N, H);
            var k = BigInteger.ValueOf(3);

            // (a + ux)
            var exp = a.Add(u.Multiply(x));

            // (B - kg ^ x)
            var val = mod(B.Subtract((g.ModPow(x, N).Multiply(k).Mod(N))), N);

            // S = (B - kg ^ x) ^ (a + ux)
            return Helpers.ComputeWoWKey(H, val.ModPow(exp, N));
        }

        public BigInteger GenerateClientProof(string I, BigInteger s, BigInteger B, BigInteger S)
        {
            return Helpers.ComputeClientProof(N, g, s, I, H, A, B, S);
        }

        public bool ValidateServerProof(BigInteger M2, BigInteger M1, BigInteger S)
        {
            return M2.ToString(16) == Helpers.ComputeServerProof(N, H, A, M1, S).ToString(16);
        }

        private BigInteger GeneratePrivateKey(string I, string P, byte[] s)
        {
            // x = H(s | H(I | ":" | P))
            var x = H(s.Concat(H(Encoding.UTF8.GetBytes(I + ":" + P))).ToArray());

            return x.ToSrpBigInt();
        }

        private static BigInteger mod(BigInteger x, BigInteger m)
        {
            return x.Mod(m).Add(m).Mod(m);
        }
    }
}