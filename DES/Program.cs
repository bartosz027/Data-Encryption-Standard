using System;
using System.Collections;

namespace DES {

    class Program {
        static void Main(string[] args) {
            var des = new DES();

            // Key
            var key1 = "0001001100110100010101110111100110011011101111001101111111110001";
            Console.WriteLine("Key1  : {0}", key1);

            var key2 = "1000111111111011001111011101100110011110111010100010110011001000";
            Console.WriteLine("Key2  : {0}\n", key2);

            // Encryption
            var input1 = "TEST MESSAGE!";
            Console.WriteLine("Input : {0}", input1);

            var output1 = des.EncryptText(input1, key1);
            des.PrintBitArray("Output: ", output1);

            Console.WriteLine();

            // Decryption with correct key
            var input2 = output1;
            des.PrintBitArray("Input : ", input2);

            var output2 = des.DecryptText(input2, key1);
            Console.WriteLine("Output: {0}\n", output2);

            // Decryption with invalid key
            var input3 = output1;
            des.PrintBitArray("Input : ", input3);

            var output3 = des.DecryptText(input3, key2);
            Console.WriteLine("Output: {0}\n", output3);

            // Wait for key press
            Console.ReadKey();
        }
    }

}