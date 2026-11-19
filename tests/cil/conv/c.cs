using System;
public class C {
    static long Broadcast() { return 0x00000000FFFFFFFF; }
    static ulong U(int x) { return (ulong)(uint)x; }
    static ulong U2(int x) { unchecked { return (ulong)x; } }
    static long L(uint x) { return x; }
    static UIntPtr P(int x) { unchecked { return (UIntPtr)(uint)x; } }
    public static void Main() {
        Console.WriteLine(Broadcast() + " " + U(-1) + " " + U2(-1) + " " + L(0xFFFFFFFE) + " " + P(-2) + " " + U(int.MinValue));
    }
}
