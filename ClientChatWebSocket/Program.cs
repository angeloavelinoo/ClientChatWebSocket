using ClientChatWebSocket;
using System.Net.Sockets;
using System.Text.Json;
using System.Text;
using System.Text.RegularExpressions;

#region BIRDS_NAMES
string[] birds = new string[]
{
    "Canário",
    "Papagaio",
    "Arara",
    "Beija-flor",
    "Pica-pau",
    "Coruja",
    "Rouxinol",
    "Pardal",
    "Tucano",
    "Gaivota",
    "Andorinha",
    "Sabiá",
    "Colibri",
    "Falcão",
    "Gavião",
    "Pomba",
    "Marreco",
    "Ema",
    "Faisão",
    "Pinguim",
    "Trinca-ferro",
    "Pato",
    "Codorna",
    "Bem-te-vi",
    "Curió"
};
#endregion

Console.OutputEncoding = Encoding.UTF8;
Console.WriteLine("=== CHAT TCP com Cifras Clássicas ===\n");
Console.Write("Seu nome: ");
string name = Console.ReadLine()!.Trim();
if (string.IsNullOrWhiteSpace(name)) name = GetUserName(birds);

string ip = "localhost";
int port = 5124;

Console.WriteLine("\nEscolha a cifra:\n 1) César\n 2) Substituição Monoalfabética\n 3) Playfair\n 4) Vigenère\n 5) RCFOUR\n 6) DES\n");
Console.Write("Opção: ");
string opt = Console.ReadLine()!.Trim();
string cipherId = opt switch
{
    "1" => "caesar",
    "2" => "mono",
    "3" => "playfair",
    "4" => "vigenere",
    "5" => "rc4",
    "6" => "des",
    _ => "vigenere"
};

string key = AskKey(cipherId);
var cipher = CipherFactory.Create(cipherId);

var tcp = new TcpClient();
await tcp.ConnectAsync(ip, port);
var stream = tcp.GetStream();
Console.WriteLine($"\n[Conectado] {ip}:{port} — cifra: {cipherId}, chave: {key}\nDigite mensagens e ENTER para enviar. Digite 'exit' para sair.\n");

_ = Task.Run(async () =>
{
    try
    {
        while (tcp.Connected)
        {
            string? json = await ReadFramedAsync(stream);
            if (json == null) break;
            var msg = JsonSerializer.Deserialize<ChatMessage>(json);
            if (msg == null) continue;

            string shown;
            if (msg.Cipher == cipherId)
            {
                try { shown = cipher.Decrypt(msg.Payload, key); }
                catch { shown = $"(Falha ao decifrar) {msg.Payload}"; }
            }
            else
            {
                shown = $"(Cifra diferente: {msg.Cipher}) {msg.Payload}";
            }

            Console.WriteLine($"{msg.Sender}: {shown}");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[ERRO RX] {ex.Message}");
    }
});

while (tcp.Connected)
{
    string? line = Console.ReadLine();
    if (line == null) break;
    if (line.Equals("exit", StringComparison.OrdinalIgnoreCase)) break;

    string cipherText = cipher.Encrypt(line, key);
    var payload = new ChatMessage(cipherId, name, cipherText);
    string json = JsonSerializer.Serialize(payload);
    await WriteFramedAsync(stream, json);
}

try { tcp.Close(); } catch { }
Console.WriteLine("Conexão encerrada.");

static string AskKey(string id)
{
    switch (id)
    {
        case "caesar":
            Console.Write("Chave (deslocamento inteiro, ex: 3): ");

            while (true) 
            {
                string key = Console.ReadLine()!.Trim();

                if(!string.IsNullOrEmpty(key) && ValidatorCaesar(key))
                {
                    return key;
                }

                Console.WriteLine("Chave inválida! Informe um número inteiro (ex: 3).");
                Console.Write("Chave: ");
            };

        case "mono":
            Console.WriteLine("\nChave da Substituição Monoalfabética:\n- Você pode informar UM ALFABETO de 26 letras (permutação)\n  OU uma palavra-chave (será expandida para o alfabeto). Ex: 'SEGURANCA'\n");
            Console.Write("Chave: ");
            return Console.ReadLine()!.Trim();
        case "playfair":
            Console.Write("Chave (palavra/frase, J=I): ");
            return Console.ReadLine()!.Trim();
        case "vigenere":
        case "rc4":
            Console.Write("Chave RC4 (1–256 bytes; pode ser texto UTF-8): ");
            return Console.ReadLine()!.Trim();
        case "des":
            Console.Write("Chave DES (qualquer texto; será ajustado para 8 bytes): ");
            return Console.ReadLine()!.Trim();
        default:
            Console.Write("Chave (palavra/frase): ");
            return Console.ReadLine()!.Trim();
    }
}

static async Task<string?> ReadFramedAsync(NetworkStream stream)
{
    byte[] lenBuf = new byte[4];
    int read = await ReadExactAsync(stream, lenBuf, 0, 4);
    if (read == 0) return null; // desconectou
    if (read < 4) throw new IOException("Frame incompleto");
    if (BitConverter.IsLittleEndian) Array.Reverse(lenBuf);
    int len = BitConverter.ToInt32(lenBuf, 0);
    if (len <= 0 || len > 10_000_000) throw new IOException("Tamanho inválido");
    byte[] data = new byte[len];
    read = await ReadExactAsync(stream, data, 0, len);
    if (read < len) throw new IOException("Payload incompleto");
    return Encoding.UTF8.GetString(data);
}

static async Task<int> ReadExactAsync(NetworkStream s, byte[] buf, int off, int count)
{
    int total = 0;
    while (total < count)
    {
        int r = await s.ReadAsync(buf.AsMemory(off + total, count - total));
        if (r == 0) break;
        total += r;
    }
    return total;
}

static async Task WriteFramedAsync(NetworkStream stream, string json)
{
    byte[] data = Encoding.UTF8.GetBytes(json);
    byte[] len = BitConverter.GetBytes(data.Length);
    if (BitConverter.IsLittleEndian) Array.Reverse(len);
    await stream.WriteAsync(len);
    await stream.WriteAsync(data);
    await stream.FlushAsync();
}

static string GetUserName(string[] birds)
{
    int number = new Random().Next(0, birds.Length);

    return birds[number];
}

static bool ValidatorCaesar(string key)
{
    Regex hasLetters = new Regex("[A-Za-z]");

    return !hasLetters.IsMatch(key);
}

public record ChatMessage(string Cipher, string Sender, string Payload);
