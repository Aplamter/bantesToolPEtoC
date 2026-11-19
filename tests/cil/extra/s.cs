using System;
using System.Collections.Generic;
public class A1 { public static int v; static A1() { v = 5; } }
public class A2 { public static int v; static A2() { v = ++S.tick; } }
public class A3 { public static A3 I; public static int v; static A3() { I = new A3(); v = 7; } }
public class A4 { public static Func<int> f; static A4() { f = () => 9; } }
public class A5 { public static Dictionary<string,int> d; static A5() { d = new Dictionary<string,int>(StringComparer.OrdinalIgnoreCase); d["a"] = 1; } }
public class A6 { public static readonly int v = 3; public static int w; }
public class S {
    public static int tick;
    public static void Main(string[] a) {
        switch (a[0]) {
        case "1": Console.WriteLine(A1.v); break;
        case "2": Console.WriteLine(A2.v); break;
        case "3": Console.WriteLine(A3.v); break;
        case "4": Console.WriteLine(A4.f()); break;
        case "5": Console.WriteLine(A5.d.Count); break;
        case "6": Console.WriteLine(A6.v); break;
        }
    }
}
