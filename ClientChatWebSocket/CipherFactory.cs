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
    public class DesCipher : ICipher
    {
        public string Encrypt(string plain, string key)
        {
            byte[] dataToEncrypt = Encoding.UTF8.GetBytes(plain);
            byte[] keyBytes = NormalizeKey(key);
            byte[] encryptedData = DesImplementation.Process(dataToEncrypt, keyBytes, isEncrypt: true);
            return Convert.ToBase64String(encryptedData);
        }

        public string Decrypt(string cipher, string key)
        {
            byte[] dataToDecrypt = Convert.FromBase64String(cipher);
            byte[] keyBytes = NormalizeKey(key);
            byte[] decryptedData = DesImplementation.Process(dataToDecrypt, keyBytes, isEncrypt: false);
            return Encoding.UTF8.GetString(decryptedData);
        }

        //Garante que a chave fornecida pelo usuário tenha exatamente 8 bytes
        private static byte[] NormalizeKey(string key)
        {
            // Cria um "molde" de chave com exatamente 8 bytes, inicialmente preenchido com zeros.
            var keyBytes = new byte[8];
            var sourceBytes = Encoding.UTF8.GetBytes(key);
            // Copia os bytes da chave do usuário para o molde. Se a chave for menor que 8, o resto fica com zeros.
            // Se for maior, apenas os 8 primeiros bytes são copiados.
            Array.Copy(sourceBytes, keyBytes, Math.Min(keyBytes.Length, sourceBytes.Length));
            return keyBytes;
        }

        private static class DesImplementation
        {
            public static byte[] Process(byte[] data, byte[] key, bool isEncrypt)
            {
                // Gera as 16 sub-chaves de 48 bits a partir da chave principal de 64 bits.
                var subKeys = GenerateSubKeys(key);
                if (!isEncrypt) { Array.Reverse(subKeys); }

                byte[] dataToProcess;
                if (isEncrypt)
                {
                    int dataLength = data.Length;
                    int paddedLength = dataLength % 8 == 0 ? dataLength + 8 : (dataLength / 8 + 1) * 8;
                    dataToProcess = new byte[paddedLength];
                    Array.Copy(data, dataToProcess, dataLength);
                    byte paddingValue = (byte)(paddedLength - dataLength);
                    for (int i = dataLength; i < paddedLength; i++)
                    {
                        dataToProcess[i] = paddingValue;
                    }
                }
                else
                {
                    dataToProcess = data;
                }

                if (dataToProcess.Length % 8 != 0)
                    throw new ArgumentException("Os dados para descriptografar devem ser um múltiplo de 8 bytes.");

                byte[] result = new byte[dataToProcess.Length];
                for (int i = 0; i < dataToProcess.Length; i += 8)
                {
                    byte[] block = new byte[8];
                    Array.Copy(dataToProcess, i, block, 0, 8);
                    byte[] processedBlock = ProcessBlock(block, subKeys);
                    Array.Copy(processedBlock, 0, result, i, 8);
                }

                if (!isEncrypt)
                {
                    // =================================================================
                    // ESTE BLOCO É O PONTO CRÍTICO QUE REMOVE O PADDING
                    // Ele verifica o último byte para saber quantos bytes de padding remover.
                    // =================================================================
                    if (result.Length == 0) return Array.Empty<byte>();

                    byte paddingValue = result[result.Length - 1];
                    if (paddingValue > 0 && paddingValue <= 8 && result.Length >= paddingValue)
                    {
                        // Verificação de segurança: todos os bytes de padding devem ter o mesmo valor
                        for (int i = result.Length - paddingValue; i < result.Length; i++)
                        {
                            if (result[i] != paddingValue) return result; // Retorna como está se o padding for inválido
                        }

                        byte[] unpaddedResult = new byte[result.Length - paddingValue];
                        Array.Copy(result, unpaddedResult, unpaddedResult.Length);
                        return unpaddedResult;
                    }
                }

                return result;
            }

            private static byte[] ProcessBlock(byte[] block, System.Collections.BitArray[] subKeys)
            {
                // Converte o bloco de bytes para um array de bits para manipulação.
                var bits = new System.Collections.BitArray(block);

                // 1. Permutação Inicial (IP) - Embaralha os bits de acordo com a tabela IP.
                bits = Permute(bits, CipherTable.IP);

                // 2. Divide em duas metades: Esquerda (L) e Direita (R), de 32 bits cada.
                var left = new System.Collections.BitArray(32);
                var right = new System.Collections.BitArray(32);
                for (int i = 0; i < 32; i++) { left[i] = bits[i]; right[i] = bits[i + 32]; }

                // 3. Executa as 16 rodadas do algoritmo.
                for (int i = 0; i < 16; i++)
                {
                    var previousLeft = left;
                    // A nova Esquerda é a antiga Direita.
                    left = right;
                    // A nova Direita é o XOR entre a antiga Esquerda e o resultado da função de Feistel.
                    right = previousLeft.Xor(FeistelFunction(right, subKeys[i]));
                }

                // 4. Recombina as metades (note a troca final: Direita primeiro, depois Esquerda).
                var combined = new System.Collections.BitArray(64);
                for (int i = 0; i < 32; i++) { combined[i] = right[i]; combined[i + 32] = left[i]; }

                // 5. Permutação Final (FP) - Desfaz o embaralhamento inicial.
                var finalBits = Permute(combined, CipherTable.FP);
                byte[] result = new byte[8];
                finalBits.CopyTo(result, 0);
                return result;
            }
            // A função "F" da Rede de Feistel para cada rodada.
            private static System.Collections.BitArray FeistelFunction(System.Collections.BitArray right, System.Collections.BitArray subKey)
            {
                // 1. Expansão (E) - Expande a metade Direita de 32 para 48 bits para corresponder ao tamanho da sub-chave.
                var expanded = Permute(right, CipherTable.E);
                // 2. XOR - Mistura os bits expandidos com a sub-chave da rodada atual.
                expanded.Xor(subKey);
                // 3. Substituição S-Box - Parte não-linear que garante a segurança, trocando 6 bits de entrada por 4 de saída.
                var sboxOutput = new System.Collections.BitArray(32);
                for (int i = 0; i < 8; i++)
                {
                    int row = (expanded[i * 6] ? 2 : 0) + (expanded[i * 6 + 5] ? 1 : 0);
                    int col = (expanded[i * 6 + 1] ? 8 : 0) + (expanded[i * 6 + 2] ? 4 : 0) + (expanded[i * 6 + 3] ? 2 : 0) + (expanded[i * 6 + 4] ? 1 : 0);
                    int val = CipherTable.SBoxes[i, row, col];
                    sboxOutput[i * 4 + 0] = (val & 8) != 0; sboxOutput[i * 4 + 1] = (val & 4) != 0;
                    sboxOutput[i * 4 + 2] = (val & 2) != 0; sboxOutput[i * 4 + 3] = (val & 1) != 0;
                }
                // 4. Permutação (P) - Embaralha a saída das S-Boxes.
                return Permute(sboxOutput, CipherTable.P);
            }

            private static System.Collections.BitArray[] GenerateSubKeys(byte[] key)
            {
                var keyBits = new System.Collections.BitArray(key);
                var subKeys = new System.Collections.BitArray[16];

                //PC-1 - Seleciona 56 bits da chave de 64 bits, descartando os bits de paridade.
                var permutedKey = Permute(keyBits, CipherTable.PC1);

                // Divide em metades de 28 bits (C e D).
                var C = new System.Collections.BitArray(28);
                var D = new System.Collections.BitArray(28);
                for (int i = 0; i < 28; i++) { C[i] = permutedKey[i]; D[i] = permutedKey[i + 28]; }
                // Gera uma sub-chave para cada uma das 16 rodadas.
                for (int i = 0; i < 16; i++)
                {
                    C = LeftCircularShift(C, CipherTable.KeyRotations[i]);
                    D = LeftCircularShift(D, CipherTable.KeyRotations[i]);
                    // Junta as metades rotacionadas.
                    var combined = new System.Collections.BitArray(56);
                    // PC-2 - Comprime os 56 bits para 48 bits, formando a sub-chave da rodada.
                    for (int j = 0; j < 28; j++) { combined[j] = C[j]; combined[j + 28] = D[j]; }
                    subKeys[i] = Permute(combined, CipherTable.PC2);
                }
                return subKeys;
            }
            // Função utilitária genérica para reorganizar (permutar) os bits de um array de acordo com uma tabela.
            private static System.Collections.BitArray Permute(System.Collections.BitArray input, int[] table)
            {
                var output = new System.Collections.BitArray(table.Length);
                for (int i = 0; i < table.Length; i++) { output[i] = input[table[i] - 1]; }
                return output;
            }
            // Função utilitária que rotaciona os bits de um array para a esquerda em 'n' posições.
            private static System.Collections.BitArray LeftCircularShift(System.Collections.BitArray bits, int shifts)
            {
                var rotated = new System.Collections.BitArray(bits.Length);
                for (int i = 0; i < bits.Length; i++) { rotated[i] = bits[(i + shifts) % bits.Length]; }
                return rotated;
            }
        }
    }

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
}
