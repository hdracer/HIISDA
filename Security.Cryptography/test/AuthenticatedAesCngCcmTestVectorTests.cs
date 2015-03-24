﻿// Copyright (c) Microsoft Corporation.  All rights reserved.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Security.Cryptography;

namespace Security.Cryptography.Test
{
    /// <summary>
    ///    Test vectors for AES CCM mode from http://www.ietf.org/rfc/rfc3610.txt
    ///</summary>
    [TestClass]
    public class AuthenticatedAesCngCcmTestVectorTests
    {
        private class CcmTestVector
        {
            // Test vector input data
            public string Key { get; set; }
            public string Nonce { get; set; }
            public string InputPacket { get; set; }
            public int InputHeaderSize { get; set; }
            public string OutputPacket { get; set; }

            // Inputs to AuthenticatedAesCng

            public byte[] KeyBytes
            {
                get { return Util.HexStringToBytes(Key); }
            }

            public byte[] IV
            {
                get { return Util.HexStringToBytes(Nonce); }
            }

            private byte[] InputPacketBytes
            {
                get { return Util.HexStringToBytes(InputPacket); }
            }

            public byte[] Plaintext
            {
                get
                {
                    byte[] plaintext = new byte[InputPacketBytes.Length - InputHeaderSize];
                    Array.Copy(InputPacketBytes, InputHeaderSize, plaintext, 0, plaintext.Length);
                    return plaintext;
                }
            }

            public byte[] AuthenticationData
            {
                get
                {
                    byte[] authenticationData = new byte[InputHeaderSize];
                    Array.Copy(InputPacketBytes, 0, authenticationData, 0, authenticationData.Length);
                    return authenticationData;
                }
            }

            private byte[] OutputPacketBytes
            {
                get { return Util.HexStringToBytes(OutputPacket); }
            }

            public byte[] Ciphertext
            {
                get
                {
                    byte[] ciphertext = new byte[Plaintext.Length];
                    Array.Copy(OutputPacketBytes, InputHeaderSize, ciphertext, 0, ciphertext.Length);
                    return ciphertext;
                }
            }

            public byte[] Tag
            {
                get
                {
                    byte[] tag = new byte[OutputPacketBytes.Length - InputHeaderSize - Ciphertext.Length];
                    Array.Copy(OutputPacketBytes, InputHeaderSize + Ciphertext.Length, tag, 0, tag.Length);
                    return tag;
                }
            }
        }

        private static CcmTestVector[] s_testVectors = new CcmTestVector[]
        {
            // Packet Vector #1
            new CcmTestVector
            {
                Key             = "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
                Nonce           = "00 00 00 03  02 01 00 A0  A1 A2 A3 A4  A5",
                InputPacket     = "00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
                InputHeaderSize = 8,
                OutputPacket    = "00 01 02 03  04 05 06 07  58 8C 97 9A  61 C6 63 D2  F0 66 D0 C2  C0 F9 89 80  6D 5F 6B 61  DA C3 84 17  E8 D1 2C FD  F9 26 E0"
            },

            // Packet Vector #2
            new CcmTestVector
            {
                Key             = "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
                Nonce           = "00 00 00 04  03 02 01 A0  A1 A2 A3 A4  A5",
                InputPacket     = "00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F",
                InputHeaderSize = 8,
                OutputPacket    = "00 01 02 03  04 05 06 07  72 C9 1A 36  E1 35 F8 CF  29 1C A8 94  08 5C 87 E3  CC 15 C4 39  C9 E4 3A 3B  A0 91 D5 6E  10 40 09 16"

            },

            // Packet Vector #3
            new CcmTestVector
            {
                Key             = "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
                Nonce           = "00 00 00 05  04 03 02 A0  A1 A2 A3 A4  A5",
                InputPacket     = "00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F  20",
                InputHeaderSize = 8,
                OutputPacket    = "00 01 02 03  04 05 06 07  51 B1 E5 F4  4A 19 7D 1D  A4 6B 0F 8E  2D 28 2A E8  71 E8 38 BB  64 DA 85 96  57 4A DA A7  6F BD 9F B0  C5"
            },

            // Packet Vector #4
            new CcmTestVector
            {
                Key             = "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
                Nonce           = "00 00 00 06  05 04 03 A0  A1 A2 A3 A4  A5",
                InputPacket     = "00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
                InputHeaderSize = 12,
                OutputPacket    = "00 01 02 03  04 05 06 07  08 09 0A 0B  A2 8C 68 65  93 9A 9A 79  FA AA 5C 4C  2A 9D 4A 91  CD AC 8C 96  C8 61 B9 C9  E6 1E F1"
            },

            // Packet Vector #5
            new CcmTestVector
            {
                Key             = "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
                Nonce           = "00 00 00 07  06 05 04 A0  A1 A2 A3 A4  A5",
                InputPacket     = "00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F",
                InputHeaderSize = 12,
                OutputPacket    = "00 01 02 03  04 05 06 07  08 09 0A 0B  DC F1 FB 7B  5D 9E 23 FB  9D 4E 13 12  53 65 8A D8  6E BD CA 3E  51 E8 3F 07  7D 9C 2D 93"
            },

            // Packet Vector #6
            new CcmTestVector
            {
                Key             = "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
                Nonce           = "00 00 00 08  07 06 05 A0  A1 A2 A3 A4  A5",
                InputPacket     = "00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F  20",
                InputHeaderSize = 12,
                OutputPacket    = "00 01 02 03  04 05 06 07  08 09 0A 0B  6F C1 B0 11  F0 06 56 8B  51 71 A4 2D  95 3D 46 9B  25 70 A4 BD  87 40 5A 04  43 AC 91 CB  94"

            },

            // Packet Vector #7
            new CcmTestVector
            {
                Key             = "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
                Nonce           = "00 00 00 09  08 07 06 A0  A1 A2 A3 A4  A5",
                InputPacket     = "00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
                InputHeaderSize = 8,
                OutputPacket    = "00 01 02 03  04 05 06 07  01 35 D1 B2  C9 5F 41 D5  D1 D4 FE C1  85 D1 66 B8  09 4E 99 9D  FE D9 6C 04  8C 56 60 2C  97 AC BB 74  90"

            },

            // Packet Vector #8
            new CcmTestVector
            {
                Key             = "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
                Nonce           = "00 00 00 0A  09 08 07 A0  A1 A2 A3 A4  A5",
                InputPacket     = "00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F",
                InputHeaderSize = 8,
                OutputPacket    = "00 01 02 03  04 05 06 07  7B 75 39 9A  C0 83 1D D2  F0 BB D7 58  79 A2 FD 8F  6C AE 6B 6C  D9 B7 DB 24  C1 7B 44 33  F4 34 96 3F  34 B4"

            },

            // Packet Vector #9
            new CcmTestVector
            {
                Key             = "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
                Nonce           = "00 00 00 0B  0A 09 08 A0  A1 A2 A3 A4  A5",
                InputPacket     = "00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F  20",
                InputHeaderSize = 8,
                OutputPacket    = "00 01 02 03  04 05 06 07  82 53 1A 60  CC 24 94 5A  4B 82 79 18  1A B5 C8 4D  F2 1C E7 F9  B7 3F 42 E1  97 EA 9C 07  E5 6B 5E B1  7E 5F 4E"
            },

            // Packet Vector #10
            new CcmTestVector
            {
                Key             = "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
                Nonce           = "00 00 00 0C  0B 0A 09 A0  A1 A2 A3 A4  A5",
                InputPacket     = "00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E",
                InputHeaderSize = 12,
                OutputPacket    = "00 01 02 03  04 05 06 07  08 09 0A 0B  07 34 25 94  15 77 85 15  2B 07 40 98  33 0A BB 14  1B 94 7B 56  6A A9 40 6B  4D 99 99 88  DD"
            },

            // Packet Vector #11
            new CcmTestVector
            {
                Key             = "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
                Nonce           = "00 00 00 0D  0C 0B 0A A0  A1 A2 A3 A4  A5",
                InputPacket     = "00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F",
                InputHeaderSize = 12,
                OutputPacket    = "00 01 02 03  04 05 06 07  08 09 0A 0B  67 6B B2 03  80 B0 E3 01  E8 AB 79 59  0A 39 6D A7  8B 83 49 34  F5 3A A2 E9  10 7A 8B 6C  02 2C"
            },

            // Packet Vector #12
            new CcmTestVector
            {
                Key             = "C0 C1 C2 C3  C4 C5 C6 C7  C8 C9 CA CB  CC CD CE CF",
                Nonce           = "00 00 00 0E  0D 0C 0B A0  A1 A2 A3 A4  A5",
                InputPacket     = "00 01 02 03  04 05 06 07  08 09 0A 0B  0C 0D 0E 0F  10 11 12 13  14 15 16 17  18 19 1A 1B  1C 1D 1E 1F  20",
                InputHeaderSize = 12,
                OutputPacket    = "00 01 02 03  04 05 06 07  08 09 0A 0B  C0 FF A0 D6  F0 5B DB 67  F2 4D 43 A4  33 8D 2A A4  BE D7 B2 0E  43 CD 1A A3  16 62 E7 AD  65 D6 DB"
            },

            // Packet Vector #13
            new CcmTestVector
            {
                Key             = "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
                Nonce           = "00 41 2B 4E  A9 CD BE 3C  96 96 76 6C  FA",
                InputPacket     = "0B E1 A8 8B  AC E0 18 B1  08 E8 CF 97  D8 20 EA 25  84 60 E9 6A  D9 CF 52 89  05 4D 89 5C  EA C4 7C",
                InputHeaderSize = 8,
                OutputPacket    = "0B E1 A8 8B  AC E0 18 B1  4C B9 7F 86  A2 A4 68 9A  87 79 47 AB  80 91 EF 53  86 A6 FF BD  D0 80 F8 E7  8C F7 CB 0C  DD D7 B3"
            },

            // Packet Vector #14
            new CcmTestVector
            {
                Key             = "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
                Nonce           = "00 33 56 8E  F7 B2 63 3C  96 96 76 6C  FA",
                InputPacket     = "63 01 8F 76  DC 8A 1B CB  90 20 EA 6F  91 BD D8 5A  FA 00 39 BA  4B AF F9 BF  B7 9C 70 28  94 9C D0 EC",
                InputHeaderSize = 8,
                OutputPacket    = "63 01 8F 76  DC 8A 1B CB  4C CB 1E 7C  A9 81 BE FA  A0 72 6C 55  D3 78 06 12  98 C8 5C 92  81 4A BC 33  C5 2E E8 1D  7D 77 C0 8A"
            },

            // Packet Vector #15
            new CcmTestVector
            {
                Key             = "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
                Nonce           = "00 10 3F E4  13 36 71 3C  96 96 76 6C  FA",
                InputPacket     = "AA 6C FA 36  CA E8 6B 40  B9 16 E0 EA  CC 1C 00 D7  DC EC 68 EC  0B 3B BB 1A  02 DE 8A 2D  1A A3 46 13  2E",
                InputHeaderSize = 8,
                OutputPacket    = "AA 6C FA 36  CA E8 6B 40  B1 D2 3A 22  20 DD C0 AC  90 0D 9A A0  3C 61 FC F4  A5 59 A4 41  77 67 08 97  08 A7 76 79  6E DB 72 35  06"
            },

            // Packet Vector #16
            new CcmTestVector
            {
                Key             = "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
                Nonce           = "00 76 4C 63  B8 05 8E 3C  96 96 76 6C  FA",
                InputPacket     = "D0 D0 73 5C  53 1E 1B EC  F0 49 C2 44  12 DA AC 56  30 EF A5 39  6F 77 0C E1  A6 6B 21 F7  B2 10 1C",
                InputHeaderSize = 12,
                OutputPacket    = "D0 D0 73 5C  53 1E 1B EC  F0 49 C2 44  14 D2 53 C3  96 7B 70 60  9B 7C BB 7C  49 91 60 28  32 45 26 9A  6F 49 97 5B  CA DE AF"
            },

            // Packet Vector #17
            new CcmTestVector
            {
                Key             = "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
                Nonce           = "00 F8 B6 78  09 4E 3B 3C  96 96 76 6C  FA",
                InputPacket     = "77 B6 0F 01  1C 03 E1 52  58 99 BC AE  E8 8B 6A 46  C7 8D 63 E5  2E B8 C5 46  EF B5 DE 6F  75 E9 CC 0D",
                InputHeaderSize = 12,
                OutputPacket    = "77 B6 0F 01  1C 03 E1 52  58 99 BC AE  55 45 FF 1A  08 5E E2 EF  BF 52 B2 E0  4B EE 1E 23  36 C7 3E 3F  76 2C 0C 77  44 FE 7E 3C"
            },

            // Packet Vector #18
            new CcmTestVector
            {
                Key             = "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
                Nonce           = "00 D5 60 91  2D 3F 70 3C  96 96 76 6C  FA",
                InputPacket     = "CD 90 44 D2  B7 1F DB 81  20 EA 60 C0  64 35 AC BA  FB 11 A8 2E  2F 07 1D 7C  A4 A5 EB D9  3A 80 3B A8  7F",
                InputHeaderSize = 12,
                OutputPacket    = "CD 90 44 D2  B7 1F DB 81  20 EA 60 C0  00 97 69 EC  AB DF 48 62  55 94 C5 92  51 E6 03 57  22 67 5E 04  C8 47 09 9E  5A E0 70 45  51"
            },

            // Packet Vector #19
            new CcmTestVector
            {
                Key             = "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
                Nonce           = "00 42 FF F8  F1 95 1C 3C  96 96 76 6C  FA",
                InputPacket     = "D8 5B C7 E6  9F 94 4F B8  8A 19 B9 50  BC F7 1A 01  8E 5E 67 01  C9 17 87 65  98 09 D6 7D  BE DD 18",
                InputHeaderSize = 8,
                OutputPacket    = "D8 5B C7 E6  9F 94 4F B8  BC 21 8D AA  94 74 27 B6  DB 38 6A 99  AC 1A EF 23  AD E0 B5 29  39 CB 6A 63  7C F9 BE C2  40 88 97 C6  BA"
            },

            // Packet Vector #20
            new CcmTestVector
            {
                Key             = "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
                Nonce           = "00 92 0F 40  E5 6C DC 3C  96 96 76 6C  FA",
                InputPacket     = "74 A0 EB C9  06 9F 5B 37  17 61 43 3C  37 C5 A3 5F  C1 F3 9F 40  63 02 EB 90  7C 61 63 BE  38 C9 84 37",
                InputHeaderSize = 8,
                OutputPacket    = "74 A0 EB C9  06 9F 5B 37  58 10 E6 FD  25 87 40 22  E8 03 61 A4  78 E3 E9 CF  48 4A B0 4F  44 7E FF F6  F0 A4 77 CC  2F C9 BF 54  89 44"
            },

            // Packet Vector #21
            new CcmTestVector
            {
                Key             = "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
                Nonce           = "00 27 CA 0C  71 20 BC 3C  96 96 76 6C  FA",
                InputPacket     = "44 A3 AA 3A  AE 64 75 CA  A4 34 A8 E5  85 00 C6 E4  15 30 53 88  62 D6 86 EA  9E 81 30 1B  5A E4 22 6B  FA",
                InputHeaderSize = 8,
                OutputPacket    = "44 A3 AA 3A  AE 64 75 CA  F2 BE ED 7B  C5 09 8E 83  FE B5 B3 16  08 F8 E2 9C  38 81 9A 89  C8 E7 76 F1  54 4D 41 51  A4 ED 3A 8B  87 B9 CE"
            },

            // Packet Vector #22
            new CcmTestVector
            {
                Key             = "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
                Nonce           = "00 5B 8C CB  CD 9A F8 3C  96 96 76 6C  FA",
                InputPacket     = "EC 46 BB 63  B0 25 20 C3  3C 49 FD 70  B9 6B 49 E2  1D 62 17 41  63 28 75 DB  7F 6C 92 43  D2 D7 C2",
                InputHeaderSize = 12,
                OutputPacket    = "EC 46 BB 63  B0 25 20 C3  3C 49 FD 70  31 D7 50 A0  9D A3 ED 7F  DD D4 9A 20  32 AA BF 17  EC 8E BF 7D  22 C8 08 8C  66 6B E5 C1  97"
            },

            // Packet Vector #23
            new CcmTestVector
            {
                Key             = "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
                Nonce           = "00 3E BE 94  04 4B 9A 3C  96 96 76 6C  FA",
                InputPacket     = "47 A6 5A C7  8B 3D 59 42  27 E8 5E 71  E2 FC FB B8  80 44 2C 73  1B F9 51 67  C8 FF D7 89  5E 33 70 76",
                InputHeaderSize = 12,
                OutputPacket    = "47 A6 5A C7  8B 3D 59 42  27 E8 5E 71  E8 82 F1 DB  D3 8C E3 ED  A7 C2 3F 04  DD 65 07 1E  B4 13 42 AC  DF 7E 00 DC  CE C7 AE 52  98 7D"
            },

            // Packet Vector #24
            new CcmTestVector
            {
                Key             = "D7 82 8D 13  B2 B0 BD C3  25 A7 62 36  DF 93 CC 6B",
                Nonce           = "00 8D 49 3B  30 AE 8B 3C  96 96 76 6C  FA",
                InputPacket     = "6E 37 A6 EF  54 6D 95 5D  34 AB 60 59  AB F2 1C 0B  02 FE B8 8F  85 6D F4 A3  73 81 BC E3  CC 12 85 17  D4",
                InputHeaderSize = 12,
                OutputPacket    = "6E 37 A6 EF  54 6D 95 5D  34 AB 60 59  F3 29 05 B8  8A 64 1B 04  B9 C9 FF B5  8C C3 90 90  0F 3D A1 2A  B1 6D CE 9E  82 EF A1 6D  A6 20 59"
            }
        };

        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector1() { RunTestVector(s_testVectors[0]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector2() { RunTestVector(s_testVectors[1]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector3() { RunTestVector(s_testVectors[2]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector4() { RunTestVector(s_testVectors[3]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector5() { RunTestVector(s_testVectors[4]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector6() { RunTestVector(s_testVectors[5]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector7() { RunTestVector(s_testVectors[6]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector8() { RunTestVector(s_testVectors[7]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector9() { RunTestVector(s_testVectors[8]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector10() { RunTestVector(s_testVectors[9]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector11() { RunTestVector(s_testVectors[10]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector12() { RunTestVector(s_testVectors[11]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector13() { RunTestVector(s_testVectors[12]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector14() { RunTestVector(s_testVectors[13]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector15() { RunTestVector(s_testVectors[14]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector16() { RunTestVector(s_testVectors[15]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector17() { RunTestVector(s_testVectors[16]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector18() { RunTestVector(s_testVectors[17]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector19() { RunTestVector(s_testVectors[18]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector20() { RunTestVector(s_testVectors[19]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector21() { RunTestVector(s_testVectors[20]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector22() { RunTestVector(s_testVectors[21]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector23() { RunTestVector(s_testVectors[22]); }
        [TestMethod]
        public void AuthenticatedAesCngCcmTestVector24() { RunTestVector(s_testVectors[23]); }

        private void RunTestVector(CcmTestVector test)
        {
            // Encrypt the input
            byte[] ciphertext = null;
            using (AuthenticatedAesCng ccm = new AuthenticatedAesCng())
            {
                ccm.CngMode = CngChainingMode.Ccm;
                ccm.Key = test.KeyBytes;
                ccm.IV = test.IV;
                ccm.AuthenticatedData = test.AuthenticationData;
                ccm.TagSize = test.Tag.Length * 8;

                using (MemoryStream ms = new MemoryStream())
                using (IAuthenticatedCryptoTransform encryptor = ccm.CreateAuthenticatedEncryptor())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(test.Plaintext, 0, test.Plaintext.Length);
                    cs.FlushFinalBlock();

                    ciphertext = ms.ToArray();

                    // Verify the produced tag is what we expected it to be
                    Assert.IsTrue(Util.CompareBytes(test.Tag, encryptor.GetTag()));
                }
            }

            // Verify the ciphertext is what we expected it to be
            Assert.IsTrue(Util.CompareBytes(test.Ciphertext, ciphertext));

            // Round trip the data
            using (AuthenticatedAesCng ccm = new AuthenticatedAesCng())
            {
                ccm.CngMode = CngChainingMode.Ccm;
                ccm.Key = test.KeyBytes;
                ccm.IV = test.IV;
                ccm.AuthenticatedData = test.AuthenticationData;
                ccm.Tag = test.Tag;

                using (MemoryStream ms = new MemoryStream())
                using (ICryptoTransform decryptor = ccm.CreateDecryptor())
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                {
                    cs.Write(test.Ciphertext, 0, test.Ciphertext.Length);
                    cs.FlushFinalBlock();

                    byte[] plaintext = ms.ToArray();
                    Assert.IsTrue(Util.CompareBytes(test.Plaintext, plaintext));
                }
            }
        }
    }
}
