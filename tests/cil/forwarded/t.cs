using System;
public class T {
    int limit = 4;
    bool Big(int x) { return x > limit; }
    public static int Run() {
        var t = new T();
        int[] a = {1, 5, 9, 2, 7};
        int n = Lib.Count(a, new Mathf(t.Big));
        int m = Lib.Count(a, x => x % 2 == 1);
        return n * 10 + m;
    }
    public static void Main() { Console.WriteLine("counts: " + Run()); }
}
