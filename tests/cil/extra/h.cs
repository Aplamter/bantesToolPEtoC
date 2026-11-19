using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
[StructLayout(LayoutKind.Explicit, Size = 20)] public unsafe struct State { [FieldOffset(0)] public int buttons; [FieldOffset(4)] public float x; [FieldOffset(8)] public fixed byte raw[8]; [FieldOffset(16)] public short s; [FieldOffset(4)] public uint xbits; }
public struct FourCC { public int code; public FourCC(char a, char b, char c, char d) { code = (a << 24) | (b << 16) | (c << 8) | d; } public static implicit operator int(FourCC f) { return f.code; }
    public override string ToString() { return string.Format("{0}{1}{2}{3}", (char)(code >> 24), (char)((code >> 16) & 0xff), (char)((code >> 8) & 0xff), (char)(code & 0xff)); } }
public struct Inlined<T> { public int length; public T first; public T[] rest;
    public void Append(T v) { if (length == 0) first = v; else { Array.Resize(ref rest, length); rest[length - 1] = v; } length++; }
    public T this[int i] { get { if (i < 0 || i >= length) throw new ArgumentOutOfRangeException("i"); return i == 0 ? first : rest[i - 1]; } } }
public enum Kind : byte { None, Button = 3, Axis = 200 }
[Flags] public enum Fl : long { A = 1, B = 1L << 40 }
public abstract class Ctl { public string name; public Ctl parent; public virtual int Size { get { return 1; } } public abstract object Read(); protected static int made; protected Ctl() { made++; }
    public string Path { get { return parent == null ? "/" + name : parent.Path + "/" + name; } } }
public class Btn : Ctl { public bool v; public override object Read() { return v; } }
public class Axis : Ctl { public float v; public override int Size { get { return 4; } } public override object Read() { return v; } public static int Made { get { return made; } } }
public class Reg { public static readonly Reg I; public static readonly Dictionary<string, Func<Ctl>> makers; public static int order;
    static Reg() { order = ++H.tick; makers = new Dictionary<string, Func<Ctl>>(StringComparer.OrdinalIgnoreCase); I = new Reg(); makers["button"] = () => new Btn(); makers["axis"] = () => new Axis { v = 0.5f }; }
    public event Action<Ctl, string> onChange; public void Fire(Ctl c, string s) { var h = onChange; if (h != null) h(c, s); } }
public unsafe class H {
    public static int tick;
    static IEnumerable<int> Evens(int n) { for (int i = 0; i < n; i++) { if (i % 2 == 1) continue; try { yield return i; } finally { tick++; } } }
    static int Tr(int k) { try { try { if (k == 1) throw new InvalidOperationException("one"); if (k == 2) { int[] a = new int[2]; return a[k + 5]; } if (k == 3) { object o = "s"; return (int)o; } if (k == 4) { string s = null; return s.Length; } if (k == 5) return checked(int.MaxValue + k); return k; }
            catch (InvalidOperationException e) when (e.Message == "one") { return -1; } finally { tick += 10; } }
        catch (IndexOutOfRangeException) { return -2; } catch (InvalidCastException) { return -3; } catch (NullReferenceException) { return -4; } catch (OverflowException) { return -5; } }
    static void Swap<T>(ref T a, ref T b) { T t = a; a = b; b = t; }
    static bool TryGet(Dictionary<string, int> d, string k, out int v) { return d.TryGetValue(k, out v); }
    static int Sum(params int[] a) { int s = 0; foreach (var x in a) s += x; return s; }
    static string Sw(object o) { switch (o as string) { case "a": return "A"; case "bb": return "BB"; case null: return o is int ? "int" + (int)o : o is Kind ? "kind" : "?"; default: return "other"; } }
    public static void Main() {
        var st = new State { buttons = 0x55, x = 1.5f, s = -7 }; byte* p = (byte*)&st; st.raw[1] = 9; int total = 0; for (int i = 0; i < sizeof(State); i++) total += p[i] * (i + 1);
        uint* up = (uint*)(p + 4); float* fp = (float*)up; *fp *= 2; ushort* sp = (ushort*)(p + 16);
        Console.WriteLine("unsafe " + total + " " + st.xbits.ToString("x") + " " + st.x + " " + *sp + " " + sizeof(State) + " " + Marshal.SizeOf(typeof(State)) + " " + (long)((byte*)sp - p));
        byte[] bufa = new byte[16]; fixed (byte* buf = bufa) { for (int i = 0; i < 16; i++) buf[i] = (byte)(i * 17); long* lp = (long*)buf; Console.WriteLine("stackalloc " + lp[1].ToString("x") + " " + (*(int*)(buf + 3)).ToString("x")); }
        int[] arr = { 5, 6, 7, 8 }; fixed (int* ap = &arr[1]) { ap[1] += 100; *(ap - 1) = -1; } Console.WriteLine("fixed " + string.Join(",", arr));
        var fcc = new FourCC('M', 'O', 'U', 'S'); int code = fcc; Console.WriteLine("fourcc " + fcc + " " + code.ToString("x") + " " + (Kind)200 + " " + (int)Kind.Button + " " + (Fl.A | Fl.B) + " " + ((long)(Fl.A | Fl.B)).ToString("x") + " " + Enum.Parse(typeof(Kind), "Axis"));
        var inl = new Inlined<string>(); inl.Append("a"); inl.Append("b"); inl.Append("c"); var inl2 = inl; inl2.Append("d"); string oor; try { oor = inl[5]; } catch (ArgumentOutOfRangeException e) { oor = e.ParamName; }
        Console.WriteLine("inlined " + inl.length + inl[0] + inl[2] + " " + inl2.length + inl2[3] + " " + oor);
        var ii = new Inlined<FourCC>(); ii.Append(fcc); ii.Append(new FourCC('K', 'E', 'Y', 'B')); Console.WriteLine("inlined2 " + ii[1] + ii.length);
        Console.WriteLine("reg " + Reg.order + " " + Reg.makers.Count + " " + (Reg.I != null) + " " + tick);
        Ctl root = Reg.makers["BUTTON"](); root.name = "dev"; Ctl ax = Reg.makers["Axis"](); ax.name = "stick"; ax.parent = root; var log = new StringBuilder();
        Reg.I.onChange += (c, s) => log.Append(c.Path).Append(':').Append(s).Append(';'); Action<Ctl, string> h2 = (c, s) => log.Append(c.Size); Reg.I.onChange += h2; Reg.I.Fire(ax, "x"); Reg.I.onChange -= h2; Reg.I.Fire(root, "y");
        Console.WriteLine("events " + log + " " + ax.Read() + root.Read() + " " + Axis.Made + " " + (ax is Axis) + (root as Axis == null));
        Console.WriteLine("iter " + string.Join(",", Evens(7)) + " " + tick + " " + Evens(100).Skip(3).First() + " " + tick);
        Console.WriteLine("try " + string.Join(",", Enumerable.Range(0, 7).Select(Tr)) + " " + tick);
        int a1 = 1, b1 = 2; Swap(ref a1, ref b1); string s1 = "x", s2 = "y"; Swap(ref s1, ref s2); var d = new Dictionary<string, int> { { "k", 5 } }; int got; bool ok = TryGet(d, "k", out got); int miss; bool ok2 = TryGet(d, "z", out miss);
        Console.WriteLine("ref " + a1 + b1 + s1 + s2 + ok + got + ok2 + miss + " " + Sum() + Sum(1, 2, 3) + " " + Sw("a") + Sw("bb") + Sw(5) + Sw(Kind.Axis) + Sw("zz") + Sw(2.5));
        int[][] jag = { new[] { 1 }, new[] { 2, 3 } }; object[] objs = new string[] { "p", "q" }; string cov; try { objs[0] = 5; cov = "no"; } catch (ArrayTypeMismatchException) { cov = "mismatch"; }
        Console.WriteLine("arrays " + jag[1][1] + cov + ((IList)arr).Contains(7) + Array.IndexOf(arr, 107) + " " + "abc".Substring(1) + string.Concat("a", 1, 'c', 2.5f) + $"{5,3}|{3.14159:F2}|{255:X4}");
        int? n1 = null, n2 = 4; long big = (n1 ?? 10) + (n2 ?? 0) + (n2 > 3 ? 100 : 0); double dd = 7 / 2 + 7 / 2.0 + 7 % 3 + Math.Floor(-2.5) + (float)1 / 3; char ch = (char)('a' + 2); ulong ul = ulong.MaxValue / 3; uint ui = 3000000000u; int sh = -16 >> 2; uint ush = 0x80000000u >> 4; long mul = (long)ui * ui;
        Console.WriteLine("arith " + big + " " + dd.ToString("R") + " " + ch + " " + ul + " " + (ui + 2000000000u) + " " + sh + " " + ush + " " + mul + " " + (ui > 5) + (-1 < (int)ui) + " " + (byte)(ui >> 3) + " " + unchecked((sbyte)0xf0) + " " + (1.0f / 3).ToString("R") + " " + (float)(0.1 + 0.2) + " " + double.NaN.Equals(double.NaN) + (double.NaN == double.NaN) + " " + (int)3.99 + (int)-3.99 + " " + Math.Round(2.25) + Math.Round(3.75));
        lock (Reg.I) { tick++; } var weak = new WeakReference(root); GC.Collect(); Console.WriteLine("misc " + weak.IsAlive + " " + typeof(Dictionary<string, List<int>>).Name + " " + typeof(Inlined<>).IsGenericTypeDefinition + " " + default(State).buttons + default(Kind) + " " + nameof(Reg.makers) + " " + string.IsNullOrEmpty(null) + " " + object.ReferenceEquals(s1, s1) + " " + "A".Equals("a", StringComparison.OrdinalIgnoreCase) + " " + new[] { 3, 1, 2 }.OrderBy(x => x).Select(x => x * x).Aggregate((x, y) => x * 10 + y) + " " + tick);
    }
}
