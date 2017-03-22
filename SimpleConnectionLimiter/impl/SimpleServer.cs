using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using SimpleConnectionLimiter.common;
using SimpleConnectionLimiter.socks5;

namespace SimpleConnectionLimiter.impl
{
    class SimpleServer : IServer
    {
        public Client Client { get; set; }

        private Socket _socket;

        public void OnClientRequestConnect(string host, int port)
        {
            IPAddress ipAddress;
            if (IPAddress.TryParse(host, out ipAddress))
            {
                StartConnection(ipAddress, port);
            }
            else
            {
                Dns.BeginGetHostAddresses(host, GetHostAddressCallback, new object[] {host, port});
            }
        }

        public void OnClientReadReady()
        {
            Send(Client.ClientFromBuffer.Size, Client.OnServerWriteReady);
        }

        public void OnClientWriteReady()
        {
            ReadAtLeast(1, Client.OnServerReadReady);
        }

        public void OnStop()
        {
            lock (this)
            {
                _socket?.Close();
            }
        }

        private void Stop()
        {
            Client.Stop();
        }

        private void GetHostAddressCallback(IAsyncResult ar)
        {
            try
            {
                var param = (object[]) ar.AsyncState;
                var host = (string) param[0];
                var port = (int)param[1];

                var results = Dns.EndGetHostAddresses(ar);

                var supportV4 = Socket.OSSupportsIPv4;
                var supportV6 = Socket.OSSupportsIPv6;
                var address = results?.FirstOrDefault(d =>
                    d.AddressFamily == AddressFamily.InterNetwork && supportV4
                    || d.AddressFamily == AddressFamily.InterNetworkV6 && supportV6);

                if (address == null)
                {
                    Client.OnAfterServerConnected(Client.ServerReply.HostUnreachable);
                    return;
                }

                StartConnection(address, port);
            }
            catch (Exception)
            {
                // TODO: log

                Stop();
            }
        }

        private void StartConnection(IPAddress address, int port)
        {
            lock (this)
            {
                _socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            }

            _socket.BeginConnect(new IPEndPoint(address, port), ServerConnectionCallback, null);
        }

        private void ServerConnectionCallback(IAsyncResult ar)
        {
            var succeeded = false;
            try
            {
                _socket.EndConnect(ar);
                succeeded = true;
            }
            catch (Exception)
            {
                // TODO: log
            }

            try
            {
                Client.OnAfterServerConnected(succeeded ? Client.ServerReply.Succeeded : Client.ServerReply.Failure);
            }
            catch (Exception)
            {
                // TODO:log
                Stop();
            }
        }

        #region Read / Send

        private void ReadAtLeast(int minDataCount, Action callback)
        {
            _socket.ReadAtLeast(Client.ClientToBuffer, minDataCount, (success, exception) =>
            {
                if (!success)
                {
                    // TODO: log
                    Stop();
                }
                else
                {
                    callback();
                }
            });
        }

        private void Send(int count, Action callback)
        {
            _socket.Send(Client.ClientFromBuffer, count, (success, exception) =>
            {
                if (!success)
                {
                    // TODO: log
                    Stop();
                }
                else
                {
                    callback();
                }
            });
        }
        #endregion
    }
}
