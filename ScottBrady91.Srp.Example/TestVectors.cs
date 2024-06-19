// ReSharper disable InconsistentNaming

using System;
using Org.BouncyCastle.Math;
using System.Security.Cryptography;
using System.Linq;

namespace SRP
{
    public static class TestVectors
    {
        public const string I = "PLAYER"; // I - user's username
        public const string P = "PLAYER"; // P - user's password
        public static readonly byte[] s = "F1FFC7E816B694671FE93EBDD6C4A99F7296C1FE87D95D9BBD8DFF0779821CD5".ToSrpBigInt().ToByteArrayUnsigned().Reverse().ToArray(); // s - user's salt (from server)

        private static readonly HashAlgorithm hasher = SHA1.Create();
        public static readonly Func<byte[], byte[]> H = i => hasher.ComputeHash(i); // H - hash function

        public const int g = 7; // g - generator, modulo N (defined in RFC 5054)
        public static readonly BigInteger N = // N - a large, safe prime (defined in RFC 5054)
            "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7".ToSrpBigInt();

        public static readonly BigInteger a = "60975527035CF2AD1989806F0407210BC81EDC04E2762A56AFD529DDDA2D4393".ToSrpBigInt();
        public static readonly BigInteger b = "E487CB59D31AC550471E81F00F6928E01DDA08E974A004F49E61F5D105284D20".ToSrpBigInt();

        public static BigInteger expected_v =
            "767246c015c4b426b806f0fc0d0935473f95fe75cac20caebcc804d1f38b6270"
                .ToSrpBigInt();

        public static BigInteger expected_A =
            "3868f18b53596f17f61c31304b47f98fa399bfdbcbc48f663d959240361783bd"
                .ToSrpBigInt();
                
        public static BigInteger expected_B =
            "41f4b7f3e1da4f236fbcdf2f9bb723f44fc75d9fddd423942eb0ab7a604868d0"
                .ToSrpBigInt();

        public static BigInteger expected_S =
            "B0DC82BABCF30674AE450C0287745E7990A3381F63B387AAF271A10D233861E359B48220F7C4693C9AE12B0A6F67809F0876E2D013800D6C41BB59B6D5979B5C00A172B4A2A5903A0BDCAF8A709585EB2AFAFA8F3499B200210DCC1F10EB33943CD67FC88A2F39A4BE5BEC4EC0A3212DC346D7E474B29EDE8A469FFECA686E5A"
                .ToSrpBigInt();
    }
}