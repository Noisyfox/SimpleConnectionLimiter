using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleConnectionLimiter.socks5
{
    public interface IServer
    {
        Client Client { set; }

        void OnClientRequestConnect(string host, int port);

        void OnClientReadReady();

        void OnClientWriteReady();

        void OnStop();
    }
}
