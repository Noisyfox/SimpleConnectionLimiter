using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using SimpleConnectionLimiter.socks5;

namespace SimpleConnectionLimiter
{
    static class Program
    {
        /// <summary>
        /// 应用程序的主入口点。
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // Init notify menu

            // Test listener
            new Listener(5555) {MaxConnections = 1/* for better debugging */}.Start();

            Application.Run();
        }
    }
}
