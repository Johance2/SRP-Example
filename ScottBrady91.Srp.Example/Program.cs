using System;
using System.Linq;
using Org.BouncyCastle.Math;

// ReSharper disable InconsistentNaming

namespace SRP
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine($"N:{TestVectors.N.ToString(16)}");
            var client = new SrpClient(TestVectors.H, TestVectors.g, TestVectors.N);
            var server = new SrpServer(TestVectors.H, TestVectors.g, TestVectors.N);

            // generate password verifier to store 
            BigInteger v = client.GenerateVerifier(TestVectors.I, TestVectors.P, TestVectors.s);
            Console.WriteLine($"v:{v.ToString(16)}");
            Console.WriteLine($"expected_v:{TestVectors.expected_v.ToString(16)}");
            if (v.ToString(16) != TestVectors.expected_v.ToString(16)) throw new Exception();

            var A = client.GenerateAValues();
            Console.WriteLine($"A:{A.ToString(16)}");
            Console.WriteLine($"expected_A:{TestVectors.expected_A.ToString(16)}");
            if (A.ToString(16) != TestVectors.expected_A.ToString(16)) throw new Exception();

            var B = server.GenerateBValues(v);
            Console.WriteLine($"B:{B.ToString(16)}");
            Console.WriteLine($"expected_B:{TestVectors.expected_B.ToString(16)}");
            //if (B.ToString(16)!= TestVectors.expected_B.ToString(16)) throw new Exception();

            var clientS = client.ComputeSessionKey(TestVectors.I, TestVectors.P, TestVectors.s, B);
            var serverS = server.ComputeSessionKey(v, A);
            Console.WriteLine($"serverS:{serverS.ToString(16)}");
            if (clientS.ToString(16) != serverS.ToString(16) /*|| clientS != TestVectors.expected_S*/) throw new Exception();

            var M1 = client.GenerateClientProof(TestVectors.I, TestVectors.s.ToSrpBigInt(), B, clientS);

            Console.WriteLine($"Client:{M1.ToString(16)}");
            if (!server.ValidateClientProof(M1, BigInteger.ValueOf(TestVectors.g), TestVectors.s.ToSrpBigInt(), TestVectors.I, A, serverS)) throw new Exception();

            var M2 = server.GenerateServerProof(A, M1, serverS);
            if (!client.ValidateServerProof(M2, M1, clientS)) throw new Exception();

            Console.WriteLine("SRP success!");
        }
    }
}
