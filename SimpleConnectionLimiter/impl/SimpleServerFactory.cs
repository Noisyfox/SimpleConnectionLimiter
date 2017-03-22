using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SimpleConnectionLimiter.socks5;

namespace SimpleConnectionLimiter.impl
{
    public class SimpleServerFactory : IServerFactory
    {
        public IServer CreateServer()
        {
            return new SimpleServer();
        }
    }
}
