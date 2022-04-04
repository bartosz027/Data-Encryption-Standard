using System;

using System.Linq;
using System.Text;

using System.Collections;
using System.Collections.Generic;

namespace DES {

    public class DES {
        public void PrintBitArray(string prefix, BitArray array) {
            Console.Write(prefix);

            for (int i = array.Count - 1; i >= 0; i--) {
                char c = array[i] ? '1' : '0';
                Console.Write(c);
            }

            Console.Write('\n');
        }


        public BitArray EncryptText(string input, string key) {
            var input_blocks = new List<BitArray>();
            var output_blocks = new List<BitArray>();

            var input_bits = new BitArray(Encoding.Default.GetBytes(input));
            var key_bits = new BitArray(key.Select(c => c == '1').Reverse().ToArray());

            int block_count = input_bits.Length / 64;

            for (int i = 0; i < block_count; i++) {
                var block = new BitArray(64);
                int start_index = (input_bits.Length - 1) - (64 * i);

                for (int j = start_index, k = block.Length - 1; j >= start_index - 63; j--, k--) {
                    block[k] = input_bits[j];
                }

                input_blocks.Add(block);
            }

            if (input_bits.Length % 64 != 0) {
                var block = new BitArray(64);

                int remaining_bits_count = input_bits.Count - (block_count * 64);
                long missing_bytes_count = (64 - remaining_bits_count) / 8;

                for(int i = block.Length - 1, j = remaining_bits_count - 1; i >= missing_bytes_count * 8; i--, j--) {
                    block[i] = input_bits[j];
                }

                block = block.Or(new BitArray(BitConverter.GetBytes(missing_bytes_count)));
                input_blocks.Add(block);
            }
            else {
                var block = new BitArray(64);
                block = block.Or(new BitArray(new byte[] { 8, 0, 0, 0, 0, 0, 0, 0 }));

                input_blocks.Add(block);
            }

            foreach(var block in input_blocks) {
                var output = EncryptBlock(block, key_bits);
                output_blocks.Add(output);
            }

            int total_size = input_blocks.Count * 64;
            var result = new BitArray(total_size);

            for(int i = total_size - 1, j = -1; i >= 0; i--) {
                int index = i % 64;

                if(index == 63) {
                    j++;
                }

                result[i] = output_blocks[j][index];
            }

            return result;
        }

        public string DecryptText(BitArray input, string key) {
            var input_blocks = new List<BitArray>();
            var output_blocks = new List<BitArray>();

            var key_bits = new BitArray(key.Select(c => c == '1').Reverse().ToArray());
            int block_count = input.Length / 64;

            for (int i = 0; i < block_count; i++) {
                var block = new BitArray(64);
                int start_index = (input.Length - 1) - (64 * i);

                for (int j = start_index; j >= start_index - 63; j--) {
                    block[j % 64] = input[j];
                }

                input_blocks.Add(block);
            }

            foreach (var block in input_blocks) {
                var output = DecryptBlock(block, key_bits);
                output_blocks.Add(output);
            }

            int total_size = input_blocks.Count * 64;
            var result = new BitArray(total_size);

            for (int i = total_size - 1, j = -1; i >= 0; i--) {
                int index = i % 64;

                if (index == 63) {
                    j++;
                }

                result[i] = output_blocks[j][index];
            }

            var result_bytes = new byte[output_blocks.Count * 8];
            result.CopyTo(result_bytes, 0);

            if(result_bytes.Length > result_bytes[0]) {
                int length = result_bytes.Length - result_bytes[0];
                var decrypted_message = new byte[length];

                Array.Copy(result_bytes, result_bytes[0], decrypted_message, 0, length);
                return Encoding.Default.GetString(decrypted_message);
            }

            return "ERROR";
        }


        public BitArray EncryptBlock(BitArray input, BitArray key) {
            var data = InitialPermutation(input);
            var keys = GenerateKeys(key);

            var L = new BitArray(32);
            var R = new BitArray(32);

            for (int i = 0; i < 32; i++) {
                L[i] = data[i + 32];
                R[i] = data[i];
            }

            for (int i = 0; i < 16; i++) {
                FeistelFunction(ref L, ref R, keys[i]);
            }

            for(int i = 0; i < 32; i++) {
                data[i + 32] = R[i];
                data[i] = L[i];
            }

            return InverseInitialPermutation(data);
        }

        public BitArray DecryptBlock(BitArray input, BitArray key) {
            var data = InitialPermutation(input);
            var keys = GenerateKeys(key);

            var L = new BitArray(32);
            var R = new BitArray(32);

            for (int i = 0; i < 32; i++) {
                L[i] = data[i];
                R[i] = data[i + 32];
            }

            for (int i = 15; i >= 0; i--) {
                FeistelFunction(ref R, ref L, keys[i]);
            }

            for (int i = 0; i < 32; i++) {
                data[i + 32] = L[i];
                data[i] = R[i];
            }

            return InverseInitialPermutation(data);
        }


        private BitArray InitialPermutation(BitArray array) {
            int[] indices = { 
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17,  9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
            };

            return ApplyPermutation(array, indices);
        }

        private BitArray InverseInitialPermutation(BitArray array) {
            int[] indices = {
                40,  8, 48, 16, 56, 24, 64, 32,
                39,  7, 47, 15, 55, 23, 63, 31,
                38,  6, 46, 14, 54, 22, 62, 30,
                37,  5, 45, 13, 53, 21, 61, 29,
                36,  4, 44, 12, 52, 20, 60, 28,
                35,  3, 43, 11, 51, 19, 59, 27,
                34,  2, 42, 10, 50, 18, 58, 26,
                33,  1, 41,  9, 49, 17, 57, 25
            };

            return ApplyPermutation(array, indices);
        }


        private BitArray ExpansionFunction(BitArray array) {
            int[] indices = {
                32,  1,  2,  3,  4,  5,
                 4,  5,  6,  7,  8,  9,
                 8,  9, 10, 11, 12, 13,
                12, 13, 14, 15, 16, 17,
                16, 17, 18, 19, 20, 21,
                20, 21, 22, 23, 24, 25,
                24, 25, 26, 27, 28, 29,
                28, 29, 30, 31, 32,  1
            };

            return ApplyPermutation(array, indices);
        }

        private BitArray Permutation(BitArray array) {
            int[] indices = {
                16,  7, 20, 21,
                29, 12, 28, 17,
                 1, 15, 23, 26,
                 5, 18, 31, 10,
                 2,  8, 24, 14,
                32, 27,  3,  9,
                19, 13, 30,  6,
                22, 11,  4, 25
            };

            return ApplyPermutation(array, indices);
        }


        private BitArray PermutedChoice1(BitArray array) {
            int[] indices = {
                57, 49, 41, 33, 25, 17,  9,
                 1, 58, 50, 42, 34, 26, 18,
                10,  2, 59, 51, 43, 35, 27,
                19, 11,  3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                 7, 62, 54, 46, 38, 30, 22,
                14,  6, 61, 53, 45, 37, 29,
                21, 13,  5, 28, 20, 12,  4
            };

            return ApplyPermutation(array, indices);
        }

        private BitArray PermutedChoice2(BitArray array) {
            int[] indices = {
                14, 17, 11, 24,  1,  5,
                 3, 28, 15,  6, 21, 10,
                23, 19, 12,  4, 26,  8,
                16,  7, 27, 20, 13,  2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32
            };

            return ApplyPermutation(array, indices);
        }


        private void FeistelFunction(ref BitArray L, ref BitArray R, BitArray key) {
            var expanded_R = ExpansionFunction(R);
            var xor = key.Xor(expanded_R);

            int[] s1 = {
                14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
                 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
                 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
                15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
            };

            int[] s2 = {
                15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
                 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
                 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
                13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
            };

            int[] s3 = {
                10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
                13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
                13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
                 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
            };

            int[] s4 = {
                 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
                13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
                10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
                 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
            };

            int[] s5 = {
                 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
                14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
                 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
                11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
            };

            int[] s6 = {
                12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
                10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
                 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
                 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
            };

            int[] s7 = {
                 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
                13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
                 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
                 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
            };

            int[] s8 = {
                13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
                 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
                 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
                 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
            };

            var splitted_xor = new List<BitArray>() {
                new BitArray(6), new BitArray(6), new BitArray(6), new BitArray(6),
                new BitArray(6), new BitArray(6), new BitArray(6), new BitArray(6)
            };

            var s_arrays = new List<int[]>() {
                s1, s2, s3, s4,
                s5, s6, s7, s8
            };

            var result = new BitArray(32);

            for (int i = 0; i < 6; i++) {
                splitted_xor[0][i] = xor[i + 42];
                splitted_xor[1][i] = xor[i + 36];
                splitted_xor[2][i] = xor[i + 30];
                splitted_xor[3][i] = xor[i + 24];
                splitted_xor[4][i] = xor[i + 18];
                splitted_xor[5][i] = xor[i + 12];
                splitted_xor[6][i] = xor[i + 6];
                splitted_xor[7][i] = xor[i + 0];
            }

            for (int i = 0; i < 8; i++) {
                var row_bits = new BitArray(2);
                var column_bits = new BitArray(4);

                row_bits[0] = splitted_xor[i][0];
                row_bits[1] = splitted_xor[i][5];

                column_bits[0] = splitted_xor[i][1];
                column_bits[1] = splitted_xor[i][2];
                column_bits[2] = splitted_xor[i][3];
                column_bits[3] = splitted_xor[i][4];

                int[] row_int = new int[1];
                row_bits.CopyTo(row_int, 0);

                int[] column_int = new int[1];
                column_bits.CopyTo(column_int, 0);

                int row_index = row_int[0];
                int column_index = column_int[0];

                var index = (row_index * 16) + column_index;
                var value = s_arrays[i][index];

                var value_bytes = BitConverter.GetBytes(value);
                var value_bits = new BitArray(value_bytes);

                var start_index = (result.Length - 1) - (i * 4);
                result[start_index - 3] = value_bits[0];
                result[start_index - 2] = value_bits[1];
                result[start_index - 1] = value_bits[2];
                result[start_index - 0] = value_bits[3];
            }

            result = Permutation(result);

            var next_L = new BitArray(R);
            var next_R = new BitArray(result.Xor(L));

            L = next_L;
            R = next_R;
        }


        private List<BitArray> GenerateKeys(BitArray array) {
            var C = new BitArray(28);
            var D = new BitArray(28);

            var result = new List<BitArray>();
            array = PermutedChoice1(array);

            for (int i = 0; i < 28; i++) {
                C[i] = array[i + 28];
            }

            for (int i = 0; i < 28; i++) {
                D[i] = array[i];
            }

            int[] shift_values = { 
                1, 1, 2, 2, 
                2, 2, 2, 2, 
                1, 2, 2, 2, 
                2, 2, 2, 1 
            };

            for (int i = 0; i < 16; i++) {
                var key = new BitArray(56);

                C = LeftShift(C, shift_values[i]);
                D = LeftShift(D, shift_values[i]);

                for (int j = 0; j < 28; j++) {
                    key[j + 28] = C[j];
                    key[j] = D[j];
                }

                result.Add(PermutedChoice2(key));
            }

            return result;
        }

        private BitArray LeftShift(BitArray array, int value) {
            var result = new BitArray(array.Length);

            for (int i = 0; i < array.Length; i++) {
                var index = ((i - value) % array.Length + array.Length) % array.Length;
                result[i] = array[index];
            }

            return result;
        }


        private BitArray ApplyPermutation(BitArray array, int[] indices) {
            var result = new BitArray(indices.Length);

            for (int i = 1; i <= indices.Length; i++) {
                result[indices.Length - i] = array[array.Length - indices[i - 1]];
            }

            return result;
        }
    }

}