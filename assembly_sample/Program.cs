using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace assembly_sample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello world!");
            System.Diagnostics.Trace.WriteLine("Hello C#");
            foreach (var s in args)
            {
                Console.WriteLine(s);
                System.Diagnostics.Trace.WriteLine("C# param:" + s);
            }
            return ;
        }
    }
}
