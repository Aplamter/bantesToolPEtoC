using System;
using System.Collections.Generic;

namespace TinyRpg
{
    class Enemy
    {
        public string Name { get; }
        public int Hp { get; private set; }
        public Enemy(string name, int hp) { Name = name; Hp = hp; }
        public bool TakeDamage(int dmg) { Hp = Math.Max(0, Hp - dmg); return Hp == 0; }
    }

    static class Program
    {
        static int CriticalHit(int baseDmg, int roll) => roll > 90 ? baseDmg * 3 : baseDmg;

        static void Main()
        {
            var enemies = new List<Enemy> { new("Slime", 30), new("Goblin", 55), new("Dragon", 400) };
            var rng = new Random(1234);
            int turns = 0;
            foreach (var e in enemies)
                while (!e.TakeDamage(CriticalHit(12, rng.Next(100)))) turns++;
            Console.WriteLine($"All enemies defeated in {turns} turns");
        }
    }
}
