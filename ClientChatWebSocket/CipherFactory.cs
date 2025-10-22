using System.Text;

namespace ClientChatWebSocket;

public class CipherFactory
{
    public static ICipher Create(string id) => id.ToLower() switch
    {
        "caesar" => new CaesarCipher(),
        "mono" => new MonoalphabeticCipher(),
        "playfair" => new PlayfairCipher(),
        "vigenere" => new VigenereCipher(),
        "rc4" => new Rc4Cipher(),
        "des" => new DesCipher(),
        _ => new VigenereCipher(),
    };

    public class CaesarCipher : ICipher
    {
        public string Encrypt(string plain, string key) => Shift(plain, ParseKey(key));
        public string Decrypt(string cipher, string key) => Shift(cipher, -ParseKey(key));

        static int ParseKey(string k)
        {
            if (!int.TryParse(k, out int n)) throw new ArgumentException("Deslocamento inválido");
            n %= 26; if (n < 0) n += 26; return n;
        }

        static string Shift(string input, int shift)
        {
            var sb = new StringBuilder(input.Length);
            foreach (char ch in input)
            {
                if (char.IsLetter(ch))
                {
                    bool upper = char.IsUpper(ch);
                    char a = upper ? 'A' : 'a';
                    int pos = (ch - a + shift + 26) % 26;
                    sb.Append((char)(a + pos));
                }
                else sb.Append(ch);
            }
            return sb.ToString();
        }
    }

    public class MonoalphabeticCipher : ICipher
    {
        public string Encrypt(string plain, string key)
        {
            var map = BuildSubstAlphabet(key);
            return Subst(plain, map, encrypt: true);
        }

        public string Decrypt(string cipher, string key)
        {
            var map = BuildSubstAlphabet(key);
            var inv = new char[26];
            for (int i = 0; i < 26; i++) inv[map[i] - 'A'] = (char)('A' + i);
            return Subst(cipher, inv, encrypt: false);
        }

        static char[] BuildSubstAlphabet(string key)
        {
            string k = NormalizeLetters(key);
            if (k.Length == 26 && k.Distinct().Count() == 26)
            {
                return k.ToUpper().ToCharArray();
            }

            var seen = new HashSet<char>();
            var list = new List<char>();
            foreach (var c in k)
            {
                char u = char.ToUpperInvariant(c);
                if (u < 'A' || u > 'Z') continue;
                if (seen.Add(u)) list.Add(u);
            }
            for (char c = 'A'; c <= 'Z'; c++) if (seen.Add(c)) list.Add(c);
            return list.ToArray();
        }

        static string Subst(string text, char[] map, bool encrypt)
        {
            var sb = new StringBuilder(text.Length);
            foreach (char ch in text)
            {
                if (char.IsLetter(ch))
                {
                    bool upper = char.IsUpper(ch);
                    int idx = (char.ToUpperInvariant(ch) - 'A');
                    char sub = map[idx];
                    sb.Append(upper ? sub : char.ToLowerInvariant(sub));
                }
                else sb.Append(ch);
            }
            return sb.ToString();
        }

        static string NormalizeLetters(string s)
            => new string(s.ToUpperInvariant().Where(char.IsLetter).ToArray());
    }

    public class PlayfairCipher : ICipher
    {
        public string Encrypt(string plain, string key)
        {
            var grid = BuildGrid(key);
            var pairs = ToPairs(Prepare(plain));
            var sb = new StringBuilder();
            foreach (var (a, b) in pairs) sb.Append(EncPair(a, b, grid));
            return sb.ToString();
        }

        public string Decrypt(string cipher, string key)
        {
            var grid = BuildGrid(key);
            var pairs = ToPairs(Prepare(cipher));
            var sb = new StringBuilder();
            foreach (var (a, b) in pairs) sb.Append(DecPair(a, b, grid));
            return sb.ToString();
        }

        record Grid(char[,] M, Dictionary<char, (int r, int c)> Pos);

        static Grid BuildGrid(string key)
        {
            string k = new string(Normalize(key).Concat(AlphabetNoJ()).ToArray());
            var seen = new HashSet<char>();
            var list = new List<char>();
            foreach (var c in k)
                if (seen.Add(c)) list.Add(c);
            var mat = new char[5, 5];
            var pos = new Dictionary<char, (int, int)>();
            int idx = 0;
            for (int r = 0; r < 5; r++)
                for (int c = 0; c < 5; c++)
                {
                    char ch = list[idx++];
                    mat[r, c] = ch;
                    pos[ch] = (r, c);
                }
            return new Grid(mat, pos);
        }

        static IEnumerable<char> AlphabetNoJ()
        {
            for (char c = 'A'; c <= 'Z'; c++) if (c != 'J') yield return c;
        }

        static IEnumerable<char> Normalize(string s)
            => s.ToUpperInvariant().Where(char.IsLetter).Select(c => c == 'J' ? 'I' : c);

        static string Prepare(string s)
        {
            var letters = Normalize(s).ToList();
            var sb = new List<char>();
            for (int i = 0; i < letters.Count;)
            {
                char a = letters[i++];
                char b = '\0';
                if (i < letters.Count) b = letters[i];
                if (b == '\0') { b = 'X'; i = letters.Count; }
                if (a == b)
                {
                    sb.Add(a);
                    sb.Add('X');
                }
                else
                {
                    sb.Add(a);
                    sb.Add(b);
                    i++;
                }
            }
            if (sb.Count % 2 == 1) sb.Add('X');
            return new string(sb.ToArray());
        }

        static List<(char, char)> ToPairs(string s)
        {
            var pairs = new List<(char, char)>();
            for (int i = 0; i < s.Length; i += 2) pairs.Add((s[i], s[i + 1]));
            return pairs;
        }

        static string EncPair(char a, char b, Grid g)
        {
            var (ra, ca) = g.Pos[a];
            var (rb, cb) = g.Pos[b];
            if (ra == rb)
                return new string(new[] { g.M[ra, (ca + 1) % 5], g.M[rb, (cb + 1) % 5] });
            if (ca == cb)
                return new string(new[] { g.M[(ra + 1) % 5, ca], g.M[(rb + 1) % 5, cb] });
            return new string(new[] { g.M[ra, cb], g.M[rb, ca] });
        }

        static string DecPair(char a, char b, Grid g)
        {
            var (ra, ca) = g.Pos[a];
            var (rb, cb) = g.Pos[b];
            if (ra == rb)
                return new string(new[] { g.M[ra, (ca + 5 - 1) % 5], g.M[rb, (cb + 5 - 1) % 5] });
            if (ca == cb)
                return new string(new[] { g.M[(ra + 5 - 1) % 5, ca], g.M[(rb + 5 - 1) % 5, cb] });
            return new string(new[] { g.M[ra, cb], g.M[rb, ca] });
        }
    }

    public class VigenereCipher : ICipher
    {
        public string Encrypt(string plain, string key) => Process(plain, key, true);
        public string Decrypt(string cipher, string key) => Process(cipher, key, false);

        static string Process(string text, string key, bool enc)
        {
            if (string.IsNullOrWhiteSpace(key)) throw new ArgumentException("Chave vazia");
            var k = key.Where(char.IsLetter).ToArray();
            if (k.Length == 0) throw new ArgumentException("Chave deve conter letras");
            int ki = 0;
            var sb = new StringBuilder(text.Length);
            foreach (char ch in text)
            {
                if (!char.IsLetter(ch)) { sb.Append(ch); continue; }
                int shift = (char.ToUpperInvariant(k[ki % k.Length]) - 'A');
                if (!enc) shift = 26 - shift;
                bool upper = char.IsUpper(ch);
                char a = upper ? 'A' : 'a';
                int pos = (ch - a + shift) % 26;
                sb.Append((char)(a + pos));
                ki++;
            }
            return sb.ToString();
        }
    }

    public class Rc4Cipher : ICipher
    {
        public string Encrypt(string plain, string key)
        {
            var pt = Encoding.UTF8.GetBytes(plain);
            var kb = Encoding.UTF8.GetBytes(key);
            var ct = Rc4(pt, kb);
            return string.Join(",", ct.Select(b => b.ToString()));
        }

        public string Decrypt(string cipher, string key)
        {
            var kb = Encoding.UTF8.GetBytes(key);
            var ct = ParseCsvBytes(cipher);
            var pt = Rc4(ct, kb);
            return Encoding.UTF8.GetString(pt);
        }

        static byte[] Rc4(byte[] data, byte[] key)
        {
            if (key.Length == 0 || key.Length > 256)
                throw new ArgumentException("Chave RC4 deve ter 1..256 bytes");

            byte[] S = new byte[256];
            for (int i = 0; i < 256; i++) S[i] = (byte)i;
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + key[i % key.Length]) & 0xFF;
                (S[i], S[j]) = (S[j], S[i]);
            }

            int i1 = 0, j1 = 0;
            var output = new byte[data.Length];
            for (int k = 0; k < data.Length; k++)
            {
                i1 = (i1 + 1) & 0xFF;
                j1 = (j1 + S[i1]) & 0xFF;
                (S[i1], S[j1]) = (S[j1], S[i1]);
                byte K = S[(S[i1] + S[j1]) & 0xFF];
                output[k] = (byte)(data[k] ^ K);
            }
            return output;
        }

        static byte[] ParseCsvBytes(string s)
        {
            var parts = s.Split(new[] { ',', ' ', ';', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            var list = new List<byte>(parts.Length);
            foreach (var p in parts)
            {
                if (!byte.TryParse(p, out var b))
                    throw new ArgumentException("Payload RC4 inválido. Use CSV de números 0..255.");
                list.Add(b);
            }
            return list.ToArray();
        }
    }

    public class DesCipher : ICipher
    {
        public string Encrypt(string plain, string key)
        {
            var k = ParseKey(key);
            bool isHex = LooksLikeHex(plain);
            byte[] pt = isHex ? HexToBytes(plain) : Encoding.UTF8.GetBytes(plain);

            byte[] input = (isHex && (pt.Length % 8 == 0)) ? pt : Pkcs7Pad(pt, 8);

            var ct = EcbEncrypt(input, k);
            return BytesToHex(ct);
        }

        public string Decrypt(string cipher, string key)
        {
            var k = ParseKey(key);
            var ct = HexToBytes(cipher);
            var ptMaybePadded = EcbDecrypt(ct, k);

            byte[] pt;
            try { pt = Pkcs7Unpad(ptMaybePadded, 8); }
            catch { pt = ptMaybePadded; }

            try { return Encoding.UTF8.GetString(pt); }
            catch { return BytesToHex(pt); }
        }

        static byte[] ParseKey(string key)
        {
            key = key.Trim();
            if (IsHex(key) && key.Length == 16)
                return HexToBytes(key);
            if (key.Length == 8)
                return Encoding.ASCII.GetBytes(key);
            throw new ArgumentException("Chave DES inválida. Use 16 hex (ex: 133457799BBCDFF1) ou 8 chars ASCII.");
        }

        static bool IsHex(string s) => s.All(c =>
            (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F'));

        static bool LooksLikeHex(string s)
        {
            if (string.IsNullOrEmpty(s) || (s.Length % 2 != 0)) return false;
            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (!((c >= '0' && c <= '9') ||
                      (c >= 'a' && c <= 'f') ||
                      (c >= 'A' && c <= 'F')))
                    return false;
            }
            return true;
        }

        static byte[] EcbEncrypt(byte[] data, byte[] key8)
        {
            if (data.Length % 8 != 0) throw new ArgumentException("ECB: blocos devem ter múltiplo de 8 bytes.");
            var outb = new byte[data.Length];
            var subkeys = GenRoundKeys(key8);
            for (int i = 0; i < data.Length; i += 8)
            {
                ulong block = BytesToUInt64BE(data, i);
                ulong enc = DesBlock(block, subkeys);
                UInt64ToBytesBE(enc, outb, i);
            }
            return outb;
        }

        static byte[] EcbDecrypt(byte[] data, byte[] key8)
        {
            if (data.Length % 8 != 0) throw new ArgumentException("ECB: blocos devem ter múltiplo de 8 bytes.");
            var outb = new byte[data.Length];
            var subkeys = GenRoundKeys(key8);
            Array.Reverse(subkeys);
            for (int i = 0; i < data.Length; i += 8)
            {
                ulong block = BytesToUInt64BE(data, i);
                ulong dec = DesBlock(block, subkeys);
                UInt64ToBytesBE(dec, outb, i);
            }
            return outb;
        }

        static ulong DesBlock(ulong input, ulong[] subkeys48)
        {
            ulong ip = Permute64(input, IP);
            uint L = (uint)(ip >> 32);
            uint R = (uint)(ip & 0xFFFFFFFF);

            for (int round = 0; round < 16; round++)
            {
                uint f = F(R, subkeys48[round]);
                uint newL = R;
                uint newR = L ^ f;
                L = newL; R = newR;
            }

            ulong preoutput = ((ulong)R << 32) | L;
            return Permute64(preoutput, FP);
        }

        static uint F(uint R, ulong K48)
        {
            ulong ER = Permute32to48(R, E);
            ER ^= K48;
            uint sOut = SBoxes(ER);
            return (uint)Permute32(sOut, P);
        }

        static uint SBoxes(ulong six48)
        {
            uint output = 0;
            for (int i = 0; i < 8; i++)
            {
                int shift = (7 - i) * 6;
                int six = (int)((six48 >> shift) & 0x3F);
                int row = ((six & 0b100000) >> 4) | (six & 0b000001);
                int col = (six >> 1) & 0b1111;
                int sVal = SBOX[i, row, col];
                output = (output << 4) | (uint)sVal;
            }
            return output;
        }

        static ulong[] GenRoundKeys(byte[] key8)
        {
            ulong k64 = BytesToUInt64BE(key8, 0);
            ulong k56 = Permute64to56(k64, PC1);
            uint C = (uint)((k56 >> 28) & 0x0FFFFFFF);
            uint D = (uint)(k56 & 0x0FFFFFFF);

            var keys = new ulong[16];
            for (int r = 0; r < 16; r++)
            {
                int rot = SHIFTS[r];
                C = Rol28(C, rot);
                D = Rol28(D, rot);
                ulong CD = (((ulong)C & 0x0FFFFFFFUL) << 28) | ((ulong)D & 0x0FFFFFFFUL);
                keys[r] = Permute56to48(CD, PC2);
            }
            return keys;
        }

        static uint Rol28(uint v, int s) => ((v << s) | (v >> (28 - s))) & 0x0FFFFFFF;

        static byte[] Pkcs7Pad(byte[] data, int blockSize)
        {
            int pad = blockSize - (data.Length % blockSize);
            if (pad == 0) pad = blockSize;
            var res = new byte[data.Length + pad];
            Buffer.BlockCopy(data, 0, res, 0, data.Length);
            for (int i = data.Length; i < res.Length; i++) res[i] = (byte)pad;
            return res;
        }

        static byte[] Pkcs7Unpad(byte[] data, int blockSize)
        {
            if (data.Length == 0 || data.Length % blockSize != 0) throw new ArgumentException("PKCS#7 inválido.");
            int pad = data[^1];
            if (pad <= 0 || pad > blockSize) throw new ArgumentException("PKCS#7 inválido.");
            for (int i = data.Length - pad; i < data.Length; i++)
                if (data[i] != pad) throw new ArgumentException("PKCS#7 inválido.");
            var res = new byte[data.Length - pad];
            Buffer.BlockCopy(data, 0, res, 0, res.Length);
            return res;
        }

        static ulong Permute64(ulong v, int[] table) => Permute(v, 64, table);
        static ulong Permute32(uint v, int[] table) => Permute(v, 32, table);
        static ulong Permute32to48(uint v, int[] table) => Permute(v, 32, table);
        static ulong Permute56to48(ulong v, int[] table) => Permute(v, 56, table);
        static ulong Permute64to56(ulong v, int[] table) => Permute(v, 64, table);

        static ulong Permute(ulong val, int inBits, int[] table)
        {
            ulong res = 0;
            for (int i = 0; i < table.Length; i++)
            {
                int from = table[i];
                int bitIndex = inBits - from;
                ulong bit = (val >> bitIndex) & 1UL;
                res = (res << 1) | bit;
            }
            return res;
        }

        static readonly int[] IP = {
        58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
        57,49,41,33,25,17,9 ,1, 59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
    };
        static readonly int[] FP = {
        40,8 ,48,16,56,24,64,32, 39,7 ,47,15,55,23,63,31,
        38,6 ,46,14,54,22,62,30, 37,5 ,45,13,53,21,61,29,
        36,4 ,44,12,52,20,60,28, 35,3 ,43,11,51,19,59,27,
        34,2 ,42,10,50,18,58,26, 33,1 ,41,9 ,49,17,57,25
    };
        static readonly int[] E = {
        32,1 ,2 ,3 ,4 ,5 , 4 ,5 ,6 ,7 ,8 ,9 , 8 ,9 ,10,11,12,13,
        12,13,14,15,16,17, 16,17,18,19,20,21, 20,21,22,23,24,25,
        24,25,26,27,28,29, 28,29,30,31,32,1
    };
        static readonly int[] P = {
        16,7 ,20,21,29,12,28,17, 1 ,15,23,26,5 ,18,31,10,
        2 ,8 ,24,14,32,27,3 ,9 , 19,13,30,6 ,22,11,4 ,25
    };
        static readonly int[] PC1 = {
        57,49,41,33,25,17,9 , 1 ,58,50,42,34,26,18,
        10,2 ,59,51,43,35,27, 19,11,3 ,60,52,44,36,
        63,55,47,39,31,23,15, 7 ,62,54,46,38,30,22,
        14,6 ,61,53,45,37,29, 21,13,5 ,28,20,12,4
    };
        static readonly int[] PC2 = {
        14,17,11,24,1 ,5 , 3 ,28,15,6 ,21,10,
        23,19,12,4 ,26,8 , 16,7 ,27,20,13,2 ,
        41,52,31,37,47,55, 30,40,51,45,33,48,
        44,49,39,56,34,53, 46,42,50,36,29,32
    };
        static readonly int[] SHIFTS = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        static readonly int[,,] SBOX = new int[8, 4, 16]
         {
        {
          {14,4 ,13,1 ,2 ,15,11,8 ,3 ,10,6 ,12,5 ,9 ,0 ,7 },
          {0 ,15,7 ,4 ,14,2 ,13,1 ,10,6 ,12,11,9 ,5 ,3 ,8 },
          {4 ,1 ,14,8 ,13,6 ,2 ,11,15,12,9 ,7 ,3 ,10,5 ,0 },
          {15,12,8 ,2 ,4 ,9 ,1 ,7 ,5 ,11,3 ,14,10,0 ,6 ,13}
        },
        {
          {15,1 ,8 ,14,6 ,11,3 ,4 ,9 ,7 ,2 ,13,12,0 ,5 ,10},
          {3 ,13,4 ,7 ,15,2 ,8 ,14,12,0 ,1 ,10,6 ,9 ,11,5 },
          {0 ,14,7 ,11,10,4 ,13,1 ,5 ,8 ,12,6 ,9 ,3 ,2 ,15},
          {13,8 ,10,1 ,3 ,15,4 ,2 ,11,6 ,7 ,12,0 ,5 ,14,9 }
        },
        {
          {10,0 ,9 ,14,6 ,3 ,15,5 ,1 ,13,12,7 ,11,4 ,2 ,8 },
          {13,7 ,0 ,9 ,3 ,4 ,6 ,10,2 ,8 ,5 ,14,12,11,15,1 },
          {13,6 ,4 ,9 ,8 ,15,3 ,0 ,11,1 ,2 ,12,5 ,10,14,7 },
          {1 ,10,13,0 ,6 ,9 ,8 ,7 ,4 ,15,14,3 ,11,5 ,2 ,12}
        },
        {
          {7 ,13,14,3 ,0 ,6 ,9 ,10,1 ,2 ,8 ,5 ,11,12,4 ,15},
          {13,8 ,11,5 ,6 ,15,0 ,3 ,4 ,7 ,2 ,12,1 ,10,14,9 },
          {10,6 ,9 ,0 ,12,11,7 ,13,15,1 ,3 ,14,5 ,2 ,8 ,4 },
          {3 ,15,0 ,6 ,10,1 ,13,8 ,9 ,4 ,5 ,11,12,7 ,2 ,14}
        },
        {
          {2 ,12,4 ,1 ,7 ,10,11,6 ,8 ,5 ,3 ,15,13,0 ,14,9 },
          {14,11,2 ,12,4 ,7 ,13,1 ,5 ,0 ,15,10,3 ,9 ,8 ,6 },
          {4 ,2 ,1 ,11,10,13,7 ,8 ,15,9 ,12,5 ,6 ,3 ,0 ,14},
          {11,8 ,12,7 ,1 ,14,2 ,13,6 ,15,0 ,9 ,10,4 ,5 ,3 }
        },
        {
          {12,1 ,10,15,9 ,2 ,6 ,8 ,0 ,13,3 ,4 ,14,7 ,5 ,11},
          {10,15,4 ,2 ,7 ,12,9 ,5 ,6 ,1 ,13,14,0 ,11,3 ,8 },
          {9 ,14,15,5 ,2 ,8 ,12,3 ,7 ,0 ,4 ,10,1 ,13,11,6 },
          {4 ,3 ,2 ,12,9 ,5 ,15,10,11,14,1 ,7 ,6 ,0 ,8 ,13}
        },
        {
          {4 ,11,2 ,14,15,0 ,8 ,13,3 ,12,9 ,7 ,5 ,10,6 ,1 },
          {13,0 ,11,7 ,4 ,9 ,1 ,10,14,3 ,5 ,12,2 ,15,8 ,6 },
          {1 ,4 ,11,13,12,3 ,7 ,14,10,15,6 ,8 ,0 ,5 ,9 ,2 },
          {6 ,11,13,8 ,1 ,4 ,10,7 ,9 ,5 ,0 ,15,14,2 ,3 ,12}
        },
        {
          {13,2 ,8 ,4 ,6 ,15,11,1 ,10,9 ,3 ,14,5 ,0 ,12,7 },
          {1 ,15,13,8 ,10,3 ,7 ,4 ,12,5 ,6 ,11,0 ,14,9 ,2 },
          {7 ,11,4 ,1 ,9 ,12,14,2 ,0 ,6 ,10,13,15,3 ,5 ,8 },
          {2 ,1 ,14,7 ,4 ,10,8 ,13,15,12,9 ,0 ,3 ,5 ,6 ,11}
        }
         };

        static ulong BytesToUInt64BE(byte[] b, int off) =>
            ((ulong)b[off + 0] << 56) | ((ulong)b[off + 1] << 48) |
            ((ulong)b[off + 2] << 40) | ((ulong)b[off + 3] << 32) |
            ((ulong)b[off + 4] << 24) | ((ulong)b[off + 5] << 16) |
            ((ulong)b[off + 6] << 8) | ((ulong)b[off + 7]);

        static void UInt64ToBytesBE(ulong v, byte[] dst, int off)
        {
            dst[off + 0] = (byte)(v >> 56); dst[off + 1] = (byte)(v >> 48);
            dst[off + 2] = (byte)(v >> 40); dst[off + 3] = (byte)(v >> 32);
            dst[off + 4] = (byte)(v >> 24); dst[off + 5] = (byte)(v >> 16);
            dst[off + 6] = (byte)(v >> 8); dst[off + 7] = (byte)v;
        }

        static string BytesToHex(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 2);
            foreach (var b in data) sb.Append(b.ToString("X2"));
            return sb.ToString();
        }

        static byte[] HexToBytes(string hex)
        {
            if (hex.Length % 2 != 0) throw new ArgumentException("HEX inválido");
            var res = new byte[hex.Length / 2];
            for (int i = 0; i < res.Length; i++)
                res[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return res;
        }
    }
}
