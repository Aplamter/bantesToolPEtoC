public static class Lib {
    public static int Count(int[] a, System.Mathf p) { int n = 0; foreach (var x in a) if (p(x)) n++; return n; }
}
