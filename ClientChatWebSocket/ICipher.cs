using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ClientChatWebSocket;

public interface ICipher
{
    string Encrypt(string plain, string key);
    string Decrypt(string cipher, string key);
}
