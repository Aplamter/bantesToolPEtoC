using System;
using System.Collections.Generic;
public interface ICounter { int Next(); int Value { get; } }
public struct Counter : ICounter { int v; public int Next() { v += 3; return v; } public int Value { get { return v; } } public override string ToString() { return "C" + v; } }
public struct Pt : IComparable<Pt>, IEquatable<Pt> { public int x, y; public int CompareTo(Pt o) { return x != o.x ? x.CompareTo(o.x) : y.CompareTo(o.y); }
    public bool Equals(Pt o) { return x == o.x && y == o.y; } public override int GetHashCode() { return x * 31 + y; } public override string ToString() { return "(" + x + "," + y + ")"; } }
public class G {
    static int Drive<T>(ref T c, int n) where T : ICounter { int s = 0; for (int i = 0; i < n; i++) s += c.Next(); return s + c.Value; }
    static string Show<T>(T v) { return v.ToString() + "/" + v.GetHashCode() + "/" + v.Equals(v); }
    static T Max<T>(T a, T b) where T : IComparable<T> { return a.CompareTo(b) >= 0 ? a : b; }
    static int Sum<TE>(TE e) where TE : IEnumerator<int> { int s = 0; while (e.MoveNext()) s += e.Current; e.Dispose(); return s; }
    public static void Main() {
        var c = new Counter();
        Console.WriteLine(Drive(ref c, 4) + " " + c.Value + " " + c);
        ICounter ic = new Counter(); ic.Next(); ic.Next(); Console.WriteLine(ic.Value + " " + ic);
        object o = new Pt { x = 3, y = 4 }; Console.WriteLine(o.ToString() + " " + o.GetHashCode() + " " + o.Equals(new Pt { x = 3, y = 4 }));
        Console.WriteLine(Show(new Pt { x = 1, y = 2 }) + " " + Show(7) + " " + Show("s") + " " + Max(new Pt { x = 1, y = 9 }, new Pt { x = 2, y = 0 }) + " " + Max(3, 8));
        var l = new List<int> { 4, 5, 6 }; Console.WriteLine(Sum(l.GetEnumerator()));
        IComparable<Pt> cmp = new Pt { x = 5, y = 5 }; Console.WriteLine(cmp.CompareTo(new Pt { x = 5, y = 6 }));
        var d = new Dictionary<Pt, string> { { new Pt { x = 1, y = 1 }, "a" } }; Console.WriteLine(d[new Pt { x = 1, y = 1 }] + d.ContainsKey(new Pt { x = 2, y = 1 }));
    }
}
