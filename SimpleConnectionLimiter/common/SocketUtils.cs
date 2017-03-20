using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SimpleConnectionLimiter.common
{
    public static class SocketUtils
    {

        public static void ReadAtLeast(this Socket socket, PassiveBuffer readBuffer, int minDataCount, Action<bool, Exception> callback)
        {
            if (readBuffer.Size >= minDataCount)
            {
                callback(true, null);
                return;
            }

            readBuffer.RequireWrite(readBuffer.Available, false, false, out byte[] buffer,
                out int offset, out int availableCount);
            socket.BeginReceive(buffer, offset, availableCount, 0, SocketReadCallback,
                new object[] { socket, readBuffer, minDataCount, callback });
        }

        private static void SocketReadCallback(IAsyncResult ar)
        {
            var param = (object[]) ar.AsyncState;
            var socket = (Socket) param[0];
            var readBuffer = (PassiveBuffer) param[1];
            var minDataCount = (int) param[2];
            var callback = (Action<bool, Exception>) param[3];

            try
            {

                var bytesRead = socket.EndReceive(ar);
                readBuffer.ConfirmWrite(bytesRead);

                if (bytesRead == 0)
                {
                    callback(false, null);
                    return;
                }


                socket.ReadAtLeast(readBuffer, minDataCount, callback);
            }
            catch (Exception ex)
            {
                // TODO: log
                callback(false, ex);
            }
        }

        public static void Send(this Socket socket, PassiveBuffer sendBuffer, int count, Action<bool, Exception> callback)
        {
            sendBuffer.RequireRead(count, out byte[] buffer, out int offset, out int availableCount);
            socket.BeginSend(buffer, offset, availableCount, 0, SocketSendCallback, new object[] { socket, sendBuffer, count, callback });
        }

        private static void SocketSendCallback(IAsyncResult ar)
        {
            var param = (object[])ar.AsyncState;
            var socket = (Socket)param[0];
            var sendBuffer = (PassiveBuffer)param[1];
            var count = (int)param[2];
            var callback = (Action<bool, Exception>)param[3];

            try
            {
                var byteSend = socket.EndSend(ar);
                sendBuffer.ConfirmRead(byteSend);

                var remainCount = count - byteSend;
                if (remainCount > 0)
                {
                    socket.Send(sendBuffer, remainCount, callback);
                }
                else
                {
                    callback(true, null);
                }
            }
            catch (Exception ex)
            {
                // TODO: log
                callback(false, ex);
            }
        }
    }
}
