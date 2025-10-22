using System.Text;

namespace ClientChatWebSocket;

public static class AesVisualizer128
{
    public static string EncryptTrace(string ptHex, string keyHex)
    {
        var pt = HexToBytes(ptHex);
        var key = HexToBytes(keyHex);
        if (pt.Length != 16) throw new ArgumentException("Plaintext deve ter 16 bytes (HEX).");
        if (key.Length != 16) throw new ArgumentException("Chave AES-128 deve ter 16 bytes (HEX).");

        var sb = new StringBuilder();
        byte[,] state = ToState(pt);
        var roundKeys = KeyExpansion128(key);

        sb.AppendLine("== AES-128 Trace (ECB de 1 bloco) ==");
        LogState(sb, "Estado inicial", state);
        AddRoundKey(state, roundKeys, 0);
        LogState(sb, "AddRoundKey[r0]", state);

        for (int r = 1; r <= 9; r++)
        {
            SubBytes(state);
            LogState(sb, $"SubBytes   [r{r}]", state);
            ShiftRows(state);
            LogState(sb, $"ShiftRows  [r{r}]", state);
            MixColumns(state);
            LogState(sb, $"MixColumns [r{r}]", state);
            AddRoundKey(state, roundKeys, r);
            LogState(sb, $"AddRoundKey[r{r}]", state);
        }

        SubBytes(state);
        LogState(sb, "SubBytes   [r10]", state);
        ShiftRows(state);
        LogState(sb, "ShiftRows  [r10]", state);
        AddRoundKey(state, roundKeys, 10);
        LogState(sb, "AddRoundKey[r10]", state);

        var ct = FromState(state);
        sb.AppendLine($"Ciphertext: {Convert.ToHexString(ct)}");
        return sb.ToString();
    }

    static readonly byte[] S = new byte[]
    {
        0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
        0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
        0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
        0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
        0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
        0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
        0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
        0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
        0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
        0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
        0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
        0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
        0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
        0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
        0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
        0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
    };

    static readonly byte[] Rcon = new byte[] { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };

    static byte[,] ToState(byte[] b)
    {
        var s = new byte[4, 4];
        for (int i = 0; i < 16; i++) s[i % 4, i / 4] = b[i];
        return s;
    }
    static byte[] FromState(byte[,] s)
    {
        var b = new byte[16];
        for (int i = 0; i < 16; i++) b[i] = s[i % 4, i / 4];
        return b;
    }

    static void SubBytes(byte[,] s)
    { for (int r = 0; r < 4; r++) for (int c = 0; c < 4; c++) s[r, c] = S[s[r, c]]; }

    static void ShiftRows(byte[,] s)
    {
        for (int r = 1; r < 4; r++)
        {
            var row = new byte[] { s[r, 0], s[r, 1], s[r, 2], s[r, 3] };
            for (int c = 0; c < 4; c++) s[r, c] = row[(c + r) % 4];
        }
    }

    static byte xtime(byte a) => (byte)((a << 1) ^ ((a & 0x80) != 0 ? 0x1B : 0));
    static byte Mul(byte a, byte b)
    {
        byte r = 0;
        while (b != 0)
        {
            if ((b & 1) != 0) r ^= a;
            a = xtime(a);
            b >>= 1;
        }
        return r;
    }

    static void MixColumns(byte[,] s)
    {
        for (int c = 0; c < 4; c++)
        {
            byte a0 = s[0, c], a1 = s[1, c], a2 = s[2, c], a3 = s[3, c];
            s[0, c] = (byte)(Mul(0x02, a0) ^ Mul(0x03, a1) ^ a2 ^ a3);
            s[1, c] = (byte)(a0 ^ Mul(0x02, a1) ^ Mul(0x03, a2) ^ a3);
            s[2, c] = (byte)(a0 ^ a1 ^ Mul(0x02, a2) ^ Mul(0x03, a3));
            s[3, c] = (byte)(Mul(0x03, a0) ^ a1 ^ a2 ^ Mul(0x02, a3));
        }
    }

    static void AddRoundKey(byte[,] s, byte[][] w, int round)
    {
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                s[r, c] ^= w[round * 4 + c][r];
    }

    static byte[][] KeyExpansion128(byte[] key)
    {
        var w = new byte[44][];
        for (int i = 0; i < 4; i++)
        {
            w[i] = new byte[4];
            for (int j = 0; j < 4; j++) w[i][j] = key[4 * i + j];
        }
        for (int i = 4; i < 44; i++)
        {
            var temp = (byte[])w[i - 1].Clone();
            if (i % 4 == 0)
            {
                temp = new byte[] { temp[1], temp[2], temp[3], temp[0] };
                for (int t = 0; t < 4; t++) temp[t] = S[temp[t]];
                temp[0] ^= Rcon[i / 4];
            }
            w[i] = new byte[4];
            for (int t = 0; t < 4; t++) w[i][t] = (byte)(w[i - 4][t] ^ temp[t]);
        }
        return w;
    }

    static void LogState(StringBuilder sb, string title, byte[,] s)
    {
        sb.AppendLine(title);
        for (int r = 0; r < 4; r++)
        {
            sb.Append("  ");
            for (int c = 0; c < 4; c++)
                sb.Append($"{s[r, c]:X2} ");
            sb.AppendLine();
        }
    }

    static byte[] HexToBytes(string hex)
    {
        var cl = new string(hex.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (cl.Length % 2 != 0) throw new ArgumentException("HEX inválido.");
        var b = new byte[cl.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(cl.Substring(2 * i, 2), 16);
        return b;
    }
}

