using System;

namespace DHAlgorithm
{
    public class Program
    {
        // PRIVATE
        private static int PrivateKey { get; set; }

        private static int SharedKey { get; set; }

        // PUBLIC
        public static int AgreedMod { get; set; }
        public static int AgreedBase { get; set; }
        public static int EncryptedKey { get; set; }
        public static int EncryptedKey2 { get; set; }

        public static void Main(string[] args)
        {
            Console.Write("Write your private key: (DO NOT SHARE WITH ANYONE) ");
            PrivateKey = Int32.Parse(Console.ReadLine() ?? string.Empty);
            Console.Write("Write the agreed Mod value: ");
            AgreedMod = Int32.Parse(Console.ReadLine() ?? string.Empty);
            Console.Write("Write the agreed base: ");
            AgreedBase = Int32.Parse(Console.ReadLine() ?? string.Empty);
            EncryptedKey = ModExp(AgreedBase, PrivateKey, AgreedMod);
            Console.WriteLine($"Your encrypted key is {EncryptedKey}, you're free to share this with the person you're talking with.");
            
            Console.Write("Enter other person's encrypted key: ");
            EncryptedKey2 = Int32.Parse(Console.ReadLine() ?? string.Empty);
            SharedKey = ModExp(EncryptedKey2, PrivateKey, AgreedMod);
            Console.WriteLine($"You have an encryption key now! (DO NOT SHARE WITH ANYONE) {SharedKey}");

            while (true)
            {
                Console.Write("Choose decrypt (1) or encrypt (2)");
                switch (Console.ReadLine())
                {
                    case "1":
                        Console.WriteLine(Cryptography.Decrypt(Console.ReadLine(), SharedKey.ToString()));
                        break;
                    case "2":
                        Console.WriteLine(Cryptography.Encrypt(Console.ReadLine(), SharedKey.ToString()));
                        break;
                }
            }
        }

        // Method for modular exponentiation
        private static int ModExp(int baseValue, int exponent, int mod)
        {
            int result = 1;
            baseValue = baseValue % mod;

            while (exponent > 0)
            {
                if ((exponent % 2) == 1)
                {
                    result = (result * baseValue) % mod;
                }
                exponent = exponent >> 1;
                baseValue = (baseValue * baseValue) % mod;
            }

            return result;
        }
    }
}