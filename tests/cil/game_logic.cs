// C# test for cil2c (C# -> C): what typical game scripts use
using System;

interface IShape { double Area(); string Name { get; } }

abstract class Shape : IShape {
    public static int Created;
    protected Shape() { Created++; }
    public abstract double Area();
    public virtual string Name { get { return "shape"; } }
}

class Circle : Shape {
    double r;
    public Circle(double r) { this.r = r; }
    public override double Area() { return 3.0 * r * r; }
    public override string Name { get { return "circle"; } }
}

class Rect : Shape {
    int w, h;
    public Rect(int w, int h) { this.w = w; this.h = h; }
    public override double Area() { return w * h; }
}

struct Vec {
    public int X, Y;
    public Vec(int x, int y) { X = x; Y = y; }
    public int Dot(Vec o) { return X * o.X + Y * o.Y; }
    public Vec Add(Vec o) { return new Vec(X + o.X, Y + o.Y); }
}

class Node<T> {
    public T Value;
    public Node<T> Next;
    public Node(T v, Node<T> next) { Value = v; Next = next; }
}

class GameError : Exception {
    public int Code;
    public GameError(string msg, int code) : base(msg) { Code = code; }
}

class Player {
    public string Name;
    public int Hp = 100;
    public Player(string name) { Name = name; }
    public void Hit(int dmg) {
        if (dmg < 0) throw new GameError("negative damage", dmg);
        Hp -= dmg;
    }
}

delegate int BinOp(int a, int b);

static class Program {
    static int ticks;
    static readonly int[] Table = { 3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9 };
    static Program() { ticks = 1000; }

    static int Fib(int n) { return n < 2 ? n : Fib(n - 1) + Fib(n - 2); }

    static T Max<T>(T a, T b) where T : IComparable<T> { return a.CompareTo(b) >= 0 ? a : b; }

    static int Count<T>(Node<T> n) { int c = 0; while (n != null) { c++; n = n.Next; } return c; }

    static string Grade(int score) {
        switch (score / 10) {
            case 10: case 9: return "A";
            case 8: return "B";
            case 7: return "C";
            default: return "F";
        }
    }

    static int Apply(BinOp op, int a, int b) { return op(a, b); }

    static int Main() {
        Console.WriteLine("fib(20) = " + Fib(20));
        int sum = 0;
        for (int i = 0; i < Table.Length; i++) sum += Table[i] * (i + 1);
        Console.WriteLine("table sum " + sum + ", ticks " + ticks);

        IShape[] shapes = { new Circle(2.5), new Rect(3, 4), new Circle(1) };
        double total = 0;
        foreach (IShape s in shapes) {
            Console.WriteLine(s.Name + " area " + s.Area());
            total += s.Area();
        }
        Console.WriteLine("total " + total + ", created " + Shape.Created);

        Vec a = new Vec(3, 4), b = new Vec(-2, 5);
        Vec c = a.Add(b);
        Console.WriteLine("dot " + a.Dot(b) + " add " + c.X + "," + c.Y);

        Node<string> list = null;
        for (int i = 0; i < 5; i++) list = new Node<string>("n" + i, list);
        Console.WriteLine("list " + Count(list) + " head " + list.Value);
        Node<Vec> vl = new Node<Vec>(a, new Node<Vec>(b, null));
        Console.WriteLine("vec list " + Count(vl) + " second " + vl.Next.Value.X);

        Console.WriteLine("max " + Max(17, 42) + " " + Max("pear", "apple"));
        Console.WriteLine("grades " + Grade(95) + Grade(81) + Grade(70) + Grade(12));

        BinOp add = (x, y) => x + y;
        BinOp mul = delegate (int x, int y) { return x * y; };
        Console.WriteLine("delegates " + Apply(add, 20, 22) + " " + Apply(mul, 6, 7));

        object boxed = 1234;
        int unboxed = (int)boxed + 1;
        Console.WriteLine("boxing " + boxed + " -> " + unboxed);

        Player p = new Player("hero");
        try {
            p.Hit(30);
            p.Hit(-5);
            Console.WriteLine("not reached");
        } catch (GameError e) {
            Console.WriteLine("caught " + e.Message + " code " + e.Code + ", hp " + p.Hp);
        } finally {
            Console.WriteLine("finally ran");
        }

        try { int[] small = new int[2]; small[5] = 1; }
        catch (IndexOutOfRangeException) { Console.WriteLine("index out of range caught"); }

        try { Player nobody = null; nobody.Hit(1); }
        catch (NullReferenceException) { Console.WriteLine("null reference caught"); }

        int zero = sum - sum;
        try { Console.WriteLine(10 / zero); }
        catch (DivideByZeroException) { Console.WriteLine("divide by zero caught"); }

        int fin = 0;
        for (int i = 0; i < 3; i++) {
            try {
                try { if (i == 1) throw new InvalidOperationException("inner " + i); fin += 1; }
                finally { fin += 10; }
            } catch (InvalidOperationException e) { fin += 100; Console.WriteLine("caught " + e.Message); }
        }
        Console.WriteLine("nested finally " + fin);

        string s2 = "";
        for (int i = 0; i < 5; i++) s2 += i;
        long big = 1L << 40;
        Console.WriteLine("string " + s2 + " len " + s2.Length + " big " + (big + 7) + " char " + s2[3]);
        return sum % 7;
    }
}
