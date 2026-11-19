using System;
using System.Collections.Generic;
using System.Linq;
public struct Interned { public string a, lower; public Interned(string s) { a = s; lower = s.ToLower(); } }
public struct Big { public long x, y, z; public Interned n; public byte b; }
public class F {
    static List<Big> bigs = new List<Big>();
    static void T(string n, Func<long> f) { try { Console.WriteLine(n + " " + f()); } catch (Exception e) { Console.WriteLine(n + " EXC " + e.GetType().Name); } }
    static long A() { long t = 0; foreach (var b in bigs) t += b.x + b.y + b.z + b.b + b.n.lower.Length; return t; }
    static long B() { long t = 0; var st = new Stack<Big>(bigs); foreach (var b in st) t += b.b; return t; }
    static long C() { long t = 0; var q = new Queue<Interned>(bigs.Select(b => b.n)); foreach (var i in q) t += i.a.Length; return t; }
    static long D() { long t = 0; var ll = new LinkedList<Big>(bigs); foreach (var b in ll) t ^= b.y; return t; }
    static long E() { long t = 0; var sd = new SortedDictionary<int, Big>(); foreach (var b in bigs) sd[(int)b.z] = b; foreach (var kv in sd) t += kv.Key * kv.Value.x; return t; }
    static long G() { long t = 0; var arr = bigs.ToArray(); foreach (var b in arr) t += b.z; return t; }
    static long H() { long t = 0; using (var en = bigs.GetEnumerator()) { while (en.MoveNext()) t += en.Current.x; } return t; }
    static long I() { long t = 0; IEnumerable<Big> ie = bigs; foreach (var b in ie) t += b.y; return t; }
    static long J() { long t = 0; Nullable<Big> nb = bigs[2]; if (nb.HasValue) t += nb.Value.y; return t; }
    static long K() { var tup = new KeyValuePair<Big, Interned>(bigs[1], bigs[3].n); return tup.Key.b + tup.Value.a.Length; }
    static long L() { long t = 0; var d = new Dictionary<Interned, Big>(); foreach (var b in bigs) d[b.n] = b; foreach (var kv in d) t += kv.Value.y; return t; }
    static long M() { long t = 0; var l = new List<int> {1, 2, 3}; foreach (var v in l) t += v; return t; }
    static long N() { long t = 0; var l = new List<string> {"a", "bc"}; foreach (var v in l) t += v.Length; return t; }
    static long O() { long t = 0; var l = new List<Interned> { new Interned("Ab"), new Interned("c") }; foreach (var v in l) t += v.lower.Length; return t; }
    public static void Main() {
        for (int i = 0; i < 5; i++) bigs.Add(new Big { x = i, y = i * 10L, z = -i, n = new Interned("N" + i), b = (byte)(200 + i) });
        T("A", A); T("B", B); T("C", C); T("D", D); T("E", E); T("G", G); T("H", H); T("I", I); T("J", J); T("K", K); T("L", L); T("M", M); T("N", N); T("O", O);
    }
}
