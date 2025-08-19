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
}
