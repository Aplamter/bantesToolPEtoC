using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
public struct Interned : IEquatable<Interned> {
    public string a, lower;
    public Interned(string s) { a = s; lower = s == null ? null : s.ToLower(); }
    public bool Equals(Interned o) { return lower == o.lower; }
    public override int GetHashCode() { return lower == null ? 0 : lower.GetHashCode(); }
    public override string ToString() { return a ?? ""; }
}
public struct Big { public long x, y, z; public Interned n; public byte b; }
[AttributeUsage(AttributeTargets.Field | AttributeTargets.Property, AllowMultiple = true)]
public class CtlAttribute : Attribute { public string name; public int offset = -1; public string[] aliases; }
public class Dev {
    [Ctl(name = "left")] public int leftButton;
    [Ctl(name = "pos", offset = 4)] [Ctl(name = "pos2", aliases = new[] { "p", "q" })] public float position;
    [Ctl] public Interned Name { get; set; }
    public int plain;
}
public class E {
    static Dictionary<Interned, Type> types = new Dictionary<Interned, Type>();
    static List<Big> bigs = new List<Big>();
    static int FromType(string name, Type type) {
        // the shape of InputControlLayout.FromType: reflection, attributes, struct-keyed collections, foreach
        var found = new List<KeyValuePair<Interned, int>>();
        var members = type.GetMembers(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
        foreach (var m in members) {
            if (m.DeclaringType == typeof(object)) continue;
            var attrs = m.GetCustomAttributes<CtlAttribute>(false).ToArray();
            if (attrs.Length == 0) continue;
            foreach (var at in attrs) {
                var n = new Interned(at.name ?? m.Name);
                found.Add(new KeyValuePair<Interned, int>(n, at.offset));
                if (at.aliases != null) foreach (var al in at.aliases) found.Add(new KeyValuePair<Interned, int>(new Interned(al), -2));
            }
        }
        int sum = 0;
        foreach (var kv in found) { types[kv.Key] = type; sum += kv.Value + kv.Key.ToString().Length; }
        foreach (var kv in types) sum += kv.Key.lower.Length;
        foreach (var k in types.Keys) sum += k.a.Length;
        foreach (var v in types.Values) sum += v.Name.Length;
        var hs = new HashSet<Interned>(found.Select(x => x.Key));
        foreach (var h in hs) sum += h.lower[0];
        found.Sort((x, y) => string.CompareOrdinal(x.Key.lower, y.Key.lower));
        Console.WriteLine(name + ": " + string.Join(",", found.Select(x => x.Key + "=" + x.Value)) + " sum " + sum);
        return sum;
    }
    static void Structs() {
        for (int i = 0; i < 5; i++) bigs.Add(new Big { x = i, y = i * 10L, z = -i, n = new Interned("N" + i), b = (byte)(200 + i) });
        long t = 0;
        foreach (var b in bigs) t += b.x + b.y + b.z + b.b + b.n.lower.Length;
        var st = new Stack<Big>(bigs); foreach (var b in st) t += b.b;
        var q = new Queue<Interned>(bigs.Select(b => b.n)); foreach (var i in q) t += i.a.Length;
        var ll = new LinkedList<Big>(bigs); foreach (var b in ll) t ^= b.y;
        var sd = new SortedDictionary<int, Big>(); foreach (var b in bigs) sd[(int)b.z] = b; foreach (var kv in sd) t += kv.Key * kv.Value.x;
        var arr = bigs.ToArray(); foreach (var b in arr) t += b.z;
        using (var en = bigs.GetEnumerator()) { while (en.MoveNext()) t += en.Current.x; }
        IEnumerable<Big> ie = bigs; foreach (var b in ie) t += b.y;
        Nullable<Big> nb = bigs[2]; if (nb.HasValue) t += nb.Value.y;
        var tup = new KeyValuePair<Big, Interned>(bigs[1], bigs[3].n); t += tup.Key.b + tup.Value.a.Length;
        Console.WriteLine("structs " + t);
        try { foreach (var b in bigs) { if (b.x == 3) bigs.Add(b); } } catch (InvalidOperationException) { Console.WriteLine("modified: caught (expected)"); }
    }
    public static void Main() {
        Console.WriteLine(FromType("Dev", typeof(Dev)) + FromType("again", typeof(Dev)));
        Structs();
    }
}
