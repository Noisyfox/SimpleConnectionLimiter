using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SimpleConnectionLimiter.socks5;

namespace SimpleConnectionLimiter.impl
{
    class SimpleServer : IServer
    {
        public Client Client { get; set; }

        public void OnClientRequestConnect(string host, int port)
        {
            Client.OnAfterServerConnected(Client.ServerReply.Failure);
        }

        public void OnClientReadReady()
        {
        }

        public void OnClientWriteReady()
        {
        }

        public void OnStop()
        {
        }
    }
}
