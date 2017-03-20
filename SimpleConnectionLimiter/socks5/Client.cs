using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using SimpleConnectionLimiter.common;

namespace SimpleConnectionLimiter.socks5
{
    public class Client
    {
        public delegate void ClientExitDelegate(Client client);

        public long Id { get; }

        public ListenerContext Context { get; }

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
            try
            {
                _socket.Close();
            }
            catch (ObjectDisposedException)
            {
                // Ignore
            }
        }

        private void CallOnExitAndStop()
        {
            OnClientExit?.Invoke(this);
            Stop();
        }

        private void ConnectionReject(bool notSocks5)
        {
            _clientToBuffer.Clear();
            _clientToBuffer.RequireWrite(2, true, false, out byte[] buffer,
                out int offset, out int availableCount);
            if (notSocks5)
            {
                // Reject socks 4
                buffer[offset++] = 0x0;
                buffer[offset] = 0x91;
            }
            else
            {
                buffer[offset++] = 0x5;
                buffer[offset] = 0xFF; // NO ACCEPTABLE METHODS
            }
            _clientToBuffer.ConfirmWrite(2);

            Send(2, CallOnExitAndStop);
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
                CallOnExitAndStop();
            }
        }

        private void AuthMethodRecvCallback()
        {
            {
                // Parse client methods
                _clientFromBuffer.RequireRead(_clientFromBuffer.Size, out byte[] buffer, out int offset,
                    out int availableCount);
                if (buffer[offset] != 0x5)
                {
                    ConnectionReject(true);
                    return;
                }

                int nMethods = buffer[offset + 1];
                var authMethodLen = nMethods + 2;
                if (authMethodLen < availableCount)
                {
                    ReadAtLeast(authMethodLen, AuthMethodRecvCallback);
                    return;
                }

                var hasNoAuthRequired = false;
                var j = 0;
                for (var i = offset + 2; j < nMethods; i++, j++)
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
                _clientToBuffer.RequireWrite(2, true, false, out byte[] buffer,
                    out int offset, out int availableCount);
                buffer[offset++] = 0x5;
                buffer[offset] = 0x0;
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
            _clientFromBuffer.RequireRead(3 + 2, out byte[] buffer, out int offset, out int availableCount);

            int atyp = buffer[offset + 3];

            switch (atyp)
            {
                case 1: // IPv4 address, 4 bytes
                    ReadAtLeast(3 + 1 + 4 + 2, OnRequestFullyReadCallback);
                    break;
                case 3: // domain name, length + str
                    int len = buffer[offset + 4];
                    ReadAtLeast(3 + 1 + 1 + len + 2, OnRequestFullyReadCallback);
                    break;
                case 4: // IPv6 address, 16 bytes
                    ReadAtLeast(3 + 1 + 16 + 2, OnRequestFullyReadCallback);
                    break;
                default:
                    Debug.WriteLine("Unsupported ATYP=" + atyp);
                    CallOnExitAndStop();
                    break;
            }
        }

        private void OnRequestFullyReadCallback()
        {
            _clientFromBuffer.RequireRead(_clientFromBuffer.Size, out byte[] buffer, out int offset, out int availableCount);

            int cmd = buffer[offset + 1];
            int atyp = buffer[offset + 3];
            string dstAddr;
            int dstPort;
            int headerLen;

            switch (atyp)
            {
                case 1: // IPv4 address, 4 bytes
                    dstAddr = new IPAddress(buffer.Skip(offset + 4).Take(4).ToArray()).ToString();
                    dstPort = (buffer[offset + 4 + 4] << 8) + buffer[offset + 4 + 4 + 1];
                    headerLen = 4 + 4 + 2;
                    break;
                case 3: // domain name, length + str
                    int len = buffer[offset + 4];
                    dstAddr = Encoding.UTF8.GetString(buffer, offset + 4 + 1, len);
                    dstPort = (buffer[offset + 4 + 1 + len] << 8) + buffer[offset + 4 + 1 + len + 1];
                    headerLen = 4 + 1 + len + 2;

                    break;
                case 4: // IPv6 address, 16 bytes
                    dstAddr = $"[{new IPAddress(buffer.Skip(offset + 4).Take(16).ToArray())}]";
                    dstPort = (buffer[offset + 4 + 16] << 8) + buffer[offset + 4 + 16 + 1];
                    headerLen = 4 + 16 + 2;

                    break;
                default:
                    Debug.WriteLine("Unsupported ATYP=" + atyp);
                    CallOnExitAndStop();
                    return;
            }

            _clientFromBuffer.ConfirmRead(headerLen);

            Debug.WriteLine($"connect to {dstAddr}:{dstPort}");

            // Handle cmd
            switch (cmd)
            {
                case 1:
                    Debug.WriteLine("CMD=" + cmd);
                    Reply(0x01, CallOnExitAndStop); // TODO: handle this
                    break;
                case 3:
                    Debug.WriteLine("Unsupported CMD=" + cmd);
                    Reply(0x07, CallOnExitAndStop); // 0x07 = Command not supported
                    break;
                default:
                    Debug.WriteLine("Unsupported CMD=" + cmd);
                    Reply(0x07, CallOnExitAndStop);
                    break;
            }
        }

        private void Reply(byte result, Action callback)
        {
            _clientToBuffer.RequireWrite(10, true, false, out byte[] buffer, out int offset, out int availableCount);
            buffer[offset++] = 0x5;
            buffer[offset++] = result;
            buffer[offset++] = 0x0;
            buffer[offset++] = 0x1;
            buffer[offset++] = 0x0;
            buffer[offset++] = 0x0;
            buffer[offset++] = 0x0;
            buffer[offset++] = 0x0;
            buffer[offset++] = 0x0;
            buffer[offset++] = 0x0;
            _clientToBuffer.ConfirmWrite(10);

            Send(_clientToBuffer.Size, callback);
        }

        #region Read / Send

        private void ReadAtLeast(int minDataCount, Action callback)
        {
            if (_clientFromBuffer.Size >= minDataCount)
            {
                callback();
                return;
            }

            _clientFromBuffer.RequireWrite(_clientFromBuffer.Available, false, false, out byte[] buffer,
                out int offset, out int availableCount);
            _socket.BeginReceive(buffer, offset, availableCount, 0, ClientReadCallback,
                new object[] {minDataCount, callback});
        }

        private void ClientReadCallback(IAsyncResult ar)
        {
            try
            {
                var bytesRead = _socket.EndReceive(ar);
                _clientFromBuffer.ConfirmWrite(bytesRead);

                if (bytesRead == 0)
                {
                    CallOnExitAndStop();
                    return;
                }

                var param = (object[]) ar.AsyncState;
                var minDataCount = (int)param[0];
                var callback = (Action) param[1];

                ReadAtLeast(minDataCount, callback);
            }
            catch (Exception)
            {
                // TODO: log
                CallOnExitAndStop();
            }
        }

        private void Send(int count, Action callback)
        {
            _clientToBuffer.RequireRead(count, out byte[] buffer, out int offset, out int availableCount);
            _socket.BeginSend(buffer, offset, availableCount, 0, ClientSendCallback, new object[] {count, callback});
        }

        private void ClientSendCallback(IAsyncResult ar)
        {
            try
            {
                var byteSend = _socket.EndSend(ar);
                _clientToBuffer.ConfirmRead(byteSend);

                var param = (object[])ar.AsyncState;
                var count = (int)param[0];
                var callback = (Action)param[1];

                var remainCount = count - byteSend;
                if (remainCount > 0)
                {
                    Send(remainCount, callback);
                }
                else
                {
                    callback();
                }
            }
            catch (Exception)
            {
                // TODO: log
                CallOnExitAndStop();
            }
        }
        #endregion
    }
}
