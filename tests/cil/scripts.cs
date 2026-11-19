// C# test 2 for cil2c: what Unity game scripts typically do
using System;
using System.Collections.Generic;
using System.Text;

enum State { Idle, Walk, Run, Dead }

struct Vector3 {
    public float x, y, z;
    public Vector3(float x, float y, float z) { this.x = x; this.y = y; this.z = z; }
    public static Vector3 operator +(Vector3 a, Vector3 b) { return new Vector3(a.x + b.x, a.y + b.y, a.z + b.z); }
    public static Vector3 operator *(Vector3 a, float s) { return new Vector3(a.x * s, a.y * s, a.z * s); }
    public float Magnitude { get { return (float)Math.Sqrt(x * x + y * y + z * z); } }
    public static Vector3 zero;
    public override string ToString() { return string.Format("({0:F2}, {1:F2}, {2:F2})", x, y, z); }
}

class Behaviour {
    public string name;
    public virtual void Update(float dt) { Log("Behaviour.Update " + name); }
    public virtual int Priority { get { return 0; } }
    protected static void Log(string s) { Console.WriteLine(s); }
}

class Enemy : Behaviour {
    public State state = State.Idle;
    public Vector3 pos;
    public int hp = 50;
    public event Action<int> Damaged;
    public override void Update(float dt) {
        base.Update(dt);
        switch (state) {
            case State.Idle: state = State.Walk; break;
            case State.Walk: pos = pos + new Vector3(1, 0, 0.5f) * dt; if (pos.x > 1.5f) state = State.Run; break;
            case State.Run: pos.x += 2 * dt; break;
        }
    }
    public override int Priority { get { return hp > 25 ? 2 : 1; } }
    public void Hit(int dmg) {
        hp = checked(hp - dmg);
        if (Damaged != null) Damaged(dmg);
        if (hp <= 0) state = State.Dead;
    }
}

static class Game {
    static Vector3[] path = new Vector3[4];
    static Dictionary<string, int> scores = new Dictionary<string, int>();

    static int Main() {
        var enemies = new List<Enemy>();
        for (int i = 0; i < 3; i++) enemies.Add(new Enemy { name = "e" + i, pos = new Vector3(i, 0, 0) });
        int total = 0;
        foreach (var e in enemies) e.Damaged += d => total += d;
        Action<int> extra = d => Console.WriteLine("  hit for " + d);
        enemies[1].Damaged += extra;
        for (int frame = 0; frame < 4; frame++)
            foreach (Behaviour b in enemies) b.Update(0.5f);
        foreach (var e in enemies) Console.WriteLine(e.name + " " + e.state + " at " + e.pos + " |pos| " + e.pos.Magnitude.ToString("F3"));
        enemies[1].Hit(30); enemies[1].Hit(30); enemies[0].Hit(5);
        Console.WriteLine("total damage " + total + ", e1 " + enemies[1].state + " hp " + enemies[1].hp);
        try { enemies[2].hp = int.MinValue + 3; enemies[2].Hit(10); }
        catch (OverflowException) { Console.WriteLine("checked overflow caught"); }

        for (int i = 0; i < path.Length; i++) path[i] = new Vector3(i, i * i, -i) * 0.5f;
        Vector3.zero.y = 7;
        Vector3 sum = Vector3.zero;
        foreach (var p in path) sum = sum + p;
        Console.WriteLine("path sum " + sum + " zero.y " + Vector3.zero.y);

        scores["alice"] = 10; scores["bob"] = 7; scores["alice"] += 5;
        var keys = new List<string>(scores.Keys); keys.Sort();
        var sb = new StringBuilder();
        foreach (var k in keys) sb.Append(k).Append('=').Append(scores[k]).Append(';');
        int bobs; scores.TryGetValue("bob", out bobs);
        Console.WriteLine(sb.ToString() + " bob " + bobs);

        int prio = 0;
        enemies.Sort((a, b) => b.Priority.CompareTo(a.Priority));
        foreach (var e in enemies) prio = prio * 10 + e.Priority;
        Console.WriteLine("priorities " + prio + " first " + enemies[0].name);

        float f = 0.1f; double d2 = 0.1;
        for (int i = 0; i < 10; i++) { f += 0.1f; d2 += 0.1; }
        long l = 1; for (int i = 0; i < 40; i++) l = l * 3 % 1000000007;
        char c = 'a'; c += (char)3;
        Console.WriteLine("float " + f.ToString("R") + " double " + d2.ToString("R") + " long " + l + " char " + c +
                          " shift " + (-17 >> 2) + " " + (unchecked((uint)-17) >> 2) + " div " + (-17 / 5) + " rem " + (-17 % 5));
        object o = State.Run;
        Console.WriteLine("boxed enum " + o + " int " + (int)(State)o + " is " + (o is State));
        return enemies.Count;
    }
}
