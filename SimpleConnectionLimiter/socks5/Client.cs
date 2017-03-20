using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SimpleConnectionLimiter.common;

namespace SimpleConnectionLimiter.socks5
{
    public class Client
    {
        public delegate void ClientExitDelegate(Client client);

        public long Id { get; }

        public ListenerContext Context { get; }

        private int _isStopped = 0;
        public event ClientExitDelegate OnClientExit;

        private readonly Socket _socket;

        private readonly PassiveBuffer _clientFromBuffer = new PassiveBuffer(1024);
        private readonly PassiveBuffer _clientToBuffer = new PassiveBuffer(1024);


        private delegate RunStateDelegate RunStateDelegate();


        public Client(ListenerContext ctx, Socket clientSocket)
        {
            Context = ctx;
            Id = ctx.IdCounter++;
            _socket = clientSocket;
        }

        public void Stop()
        {
            if (Interlocked.Exchange(ref _isStopped, 1) != 0)
            {
                return;
            }

            OnClientExit?.Invoke(this);
            try
            {
                _socket.Close();
            }
            catch (ObjectDisposedException)
            {
                // Ignore
            }
        }

        private void ConnectionReject(bool notSocks5)
        {
            _clientToBuffer.Clear();
            _clientToBuffer.RequireWrite(2, true, false, out ArraySegment<byte> _buffer);
            var buffer = (IList<byte>) _buffer;
            if (notSocks5)
            {
                // Reject socks 4
                buffer[0] = 0x0;
                buffer[1] = 0x91;
            }
            else
            {
                buffer[0] = 0x5;
                buffer[1] = 0xFF; // NO ACCEPTABLE METHODS
            }
            _clientToBuffer.ConfirmWrite(2);

            Send(2, Stop);
        }

        public void Start()
        {
            try
            {
                ReadAtLeast(3, AuthMethodRecvCallback);
            }
            catch (Exception)
            {
                // TODO: log
                Stop();
            }
        }

        private void AuthMethodRecvCallback()
        {
            {
                // Parse client methods
                _clientFromBuffer.RequireRead(_clientFromBuffer.Size, out ArraySegment<byte> _buffer);
                var buffer = (IList<byte>) _buffer;
                if (buffer[0] != 0x5)
                {
                    ConnectionReject(true);
                    return;
                }

                int nMethods = buffer[1];
                var authMethodLen = nMethods + 2;
                if (authMethodLen < buffer.Count)
                {
                    ReadAtLeast(authMethodLen, AuthMethodRecvCallback);
                    return;
                }

                var hasNoAuthRequired = false;
                var j = 0;
                for (var i = 2; j < nMethods; i++, j++)
                {
                    if (buffer[i] == 0x0)
                    {
                        hasNoAuthRequired = true;
                        break;
                    }
                }

                _clientFromBuffer.ConfirmRead(authMethodLen);

                if (!hasNoAuthRequired)
                {
                    ConnectionReject(false);
                    return;
                }
            }

            {
                // Select method
                _clientToBuffer.Clear();
                _clientToBuffer.RequireWrite(2, true, false, out ArraySegment<byte> _buffer);
                var buffer = (IList<byte>)_buffer;
                buffer[0] = 0x5;
                buffer[1] = 0x0;
                _clientToBuffer.ConfirmWrite(2);

                Send(_clientToBuffer.Size, AuthMethodSendCallback);
            }
        }

        private void AuthMethodSendCallback()
        {
            /*
             *  +----+-----+-------+------+----------+----------+
             *  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
             *  +----+-----+-------+------+----------+----------+
             *  | 1  |  1  | X'00' |  1   | Variable |    2     |
             *  +----+-----+-------+------+----------+----------+
             *  
             * Skip first 3 bytes, and read 2 more bytes to analysis the address.
             * 2 more bytes is designed if address is domain then we don't need to read once more to get the addr length.
             */

            ReadAtLeast(3 + 2, RequestHeadReadCallback);
        }

        private void RequestHeadReadCallback()
        {
            _clientFromBuffer.RequireRead(3 + 2, out ArraySegment<byte> _buffer);
            var buffer = (IList<byte>)_buffer;


            int atyp = buffer[3];

            switch (atyp)
            {
                case 1: // IPv4 address, 4 bytes
                    ReadAtLeast(3 + 1 + 4 + 2, OnRequestFullyReadCallback);
                    break;
                case 3: // domain name, length + str
                    int len = buffer[4];
                    ReadAtLeast(3 + 1 + 1 + len + 2, OnRequestFullyReadCallback);
                    break;
                case 4: // IPv6 address, 16 bytes
                    ReadAtLeast(3 + 1 + 16 + 2, OnRequestFullyReadCallback);
                    break;
                default:
                    Debug.WriteLine("Unsupported ATYP=" + atyp);
                    Stop();
                    break;
            }
        }

        private void OnRequestFullyReadCallback()
        {
            _clientFromBuffer.RequireRead(_clientFromBuffer.Size, out ArraySegment<byte> _buffer);
            var buffer = (IList<byte>)_buffer;

            int cmd = buffer[1];
            int atyp = buffer[3];
            string dstAddr;
            int dstPort;
            int headerLen;

            switch (atyp)
            {
                case 1: // IPv4 address, 4 bytes
                    dstAddr = new IPAddress(buffer.Skip(4).Take(4).ToArray()).ToString();
                    dstPort = (buffer[4 + 4] << 8) + buffer[4 + 4 + 1];
                    headerLen = 4 + 4 + 2;
                    break;
                case 3: // domain name, length + str
                    int len = buffer[4];
                    dstAddr = Encoding.UTF8.GetString(_buffer.Array, _buffer.Offset + 4 + 1, len);
                    dstPort = (buffer[4 + 1 + len] << 8) + buffer[4 + 1 + len + 1];
                    headerLen = 4 + 1 + len + 2;

                    break;
                case 4: // IPv6 address, 16 bytes
                    dstAddr = $"[{new IPAddress(buffer.Skip(4).Take(16).ToArray())}]";
                    dstPort = (buffer[4 + 16] << 8) + buffer[4 + 16 + 1];
                    headerLen = 4 + 16 + 2;

                    break;
                default:
                    Debug.WriteLine("Unsupported ATYP=" + atyp);
                    Stop();
                    return;
            }

            _clientFromBuffer.ConfirmRead(headerLen);

            Debug.WriteLine($"connect to {dstAddr}:{dstPort}");

            // Handle cmd
            switch (cmd)
            {
                case 1:
                    Debug.WriteLine("CMD=" + cmd);
                    Reply(0x01, Stop); // TODO: handle this
                    break;
                case 3:
                    Debug.WriteLine("Unsupported CMD=" + cmd);
                    Reply(0x07, Stop); // 0x07 = Command not supported
                    break;
                default:
                    Debug.WriteLine("Unsupported CMD=" + cmd);
                    Reply(0x07, Stop);
                    break;
            }
        }

        private void Reply(byte result, Action callback)
        {
            _clientToBuffer.RequireWrite(10, true, false, out ArraySegment<byte> _buffer);
            var buffer = (IList<byte>)_buffer;
            buffer[0] = 0x5;
            buffer[1] = result;
            buffer[2] = 0x0;
            buffer[3] = 0x1;
            buffer[4] = 0x0;
            buffer[5] = 0x0;
            buffer[6] = 0x0;
            buffer[7] = 0x0;
            buffer[8] = 0x0;
            buffer[9] = 0x0;
            _clientToBuffer.ConfirmWrite(10);

            Send(_clientToBuffer.Size, callback);
        }

        #region Read / Send

        private void ReadAtLeast(int minDataCount, Action callback)
        {
            _socket.ReadAtLeast(_clientFromBuffer, minDataCount, (success, exception) =>
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
            _socket.Send(_clientToBuffer, count, (success, exception) =>
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
