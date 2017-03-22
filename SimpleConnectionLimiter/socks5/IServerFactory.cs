using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SimpleConnectionLimiter.socks5
{
    public interface IServerFactory
    {
        IServer CreateServer();
    }
}
