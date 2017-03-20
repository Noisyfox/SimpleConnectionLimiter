using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SimpleConnectionLimiter.socks5
{
    public class ListenerContext
    {
        internal ListenerContext(Socket socket, int maxConnections)
        {
            ListenSocket = socket;
            MaxConnections = maxConnections;
        }

        internal readonly int MaxConnections;

        internal readonly Socket ListenSocket;

        internal readonly object SyncRoot = new object();

        internal bool Accepting = false;

        internal long IdCounter = 0;

        internal readonly ConcurrentDictionary<long, Client> Clients = new ConcurrentDictionary<long, Client>();
    }

    public class Listener
    {

        public ushort Port { get; }

        public int MaxConnections { get; set; }

        private ListenerContext _currentContext;

        public Listener(ushort port)
        {
            Port = port;
        }

        public void Start()
        {
            var listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            try
            {

                listenSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                var endPoint = new IPEndPoint(IPAddress.Loopback, Port);

                listenSocket.Bind(endPoint);
                listenSocket.Listen(1024);

                var context = new ListenerContext(listenSocket, MaxConnections);

                if (Interlocked.CompareExchange(ref _currentContext, context, null) == null)
                {
                    StartAccept(context, true);
                }
                else
                {
                    throw new Exception("Already started!");
                }
            }
            catch (Exception)
            {
                listenSocket.Close();
                throw;
            }
        }

        private void AcceptCallback(IAsyncResult ar)
        {
            var listenContex = (ListenerContext) ar.AsyncState;
            var listenSocket = listenContex.ListenSocket;

            try
            {
                Debug.WriteLine("EndAccept");
                var clientSocket = listenSocket.EndAccept(ar);

                var client = new Client(listenContex, clientSocket);
                client.OnClientExit += ClientExit;
                listenContex.Clients[client.Id] = client;
                client.Start();
            }
            catch (ObjectDisposedException)
            {
                // Ignore
            }
            finally
            {
                StartAccept(listenContex, true);
            }
        }

        private void AcceptCallbackLimited(IAsyncResult ar)
        {
            var listenContex = (ListenerContext) ar.AsyncState;

            lock (listenContex.SyncRoot)
            {
                listenContex.Accepting = false;

                AcceptCallback(ar);
            }

        }

        private void StartAccept(ListenerContext ctx, bool inAcceptCallback)
        {
            if (ctx.MaxConnections <= 0)
            {
                if (!inAcceptCallback)
                {
                    return;
                }

                try
                {
                    Debug.WriteLine("BeginAccept");
                    ctx.ListenSocket.BeginAccept(AcceptCallback, ctx);
                }
                catch (ObjectDisposedException)
                {
                    // Ignore
                }
            }
            else
            {
                lock (ctx.SyncRoot)
                {
                    Debug.WriteLine($"inAcceptCallback = {inAcceptCallback} Accepting = {ctx.Accepting} Client count = {ctx.Clients.Count}");
                    if (ctx.Accepting || ctx.Clients.Count >= ctx.MaxConnections)
                    {
                        return;
                    }

                    try
                    {
                        Debug.WriteLine("BeginAccept");
                        if (!ctx.ListenSocket.BeginAccept(AcceptCallbackLimited, ctx).CompletedSynchronously)
                        {
                            ctx.Accepting = true;
                        }
                    }
                    catch (ObjectDisposedException)
                    {
                        // Ignore
                    }
                }
            }
        }

        /// <summary>
        /// Check if it's necessary to start new accept
        /// </summary>
        /// <param name="client"></param>
        private void ClientExit(Client client)
        {
            client.OnClientExit -= ClientExit;

            var ctx = client.Context;
            ctx.Clients.TryRemove(client.Id, out Client dummy);

            StartAccept(ctx, false);
        }

        public void Stop()
        {
            var ctx = Interlocked.Exchange(ref _currentContext, null);

            if (ctx == null)
            {
                return;
            }

            ctx.ListenSocket.Close();
            foreach (var client in ctx.Clients.Values)
            {
                client.Stop();
            }
        }
    }
}
