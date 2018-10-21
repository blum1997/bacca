using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace keccak
{
    public class Keccack
    {

        //константы рандов, всего их 24
        //применяются на шаге ι
        private ulong[] RC ={0x0000000000000001,
        0x0000000000008082,
        0x800000000000808A,
        0x8000000080008000,
        0x000000000000808B,
        0x0000000080000001,
        0x8000000080008081,
        0x8000000000008009,
        0x000000000000008A,
        0x0000000000000088,
        0x0000000080008009,
        0x000000008000000A,
        0x000000008000808B,
        0x800000000000008B,
        0x8000000000008089,
        0x8000000000008003,
        0x8000000000008002,
        0x8000000000000080,
        0x000000000000800A,
        0x800000008000000A,
        0x8000000080008081,
        0x8000000000008080,
        0x0000000080000001,
        0x8000000080008008};
        //матрица смещений, применяется при каждом раунде на шаге θ
        private int[,] r = {{0,    36,     3,    41,    18}    ,
                          {1,    44,    10,    45,     2}    ,
                          {62,    6,    43,    15,    61}    ,
                          {28,   55,    25,    21,    56}    ,
                          {27,   20,    39,     8,    14}    };
        private int w, l, n;
        //в конструкторе устанавливаем параметры функции b=1600
        public Keccack(int b)
        {
            w = b / 25;
            l = (Convert.ToInt32(Math.Log(w, 2)));
            n = 12 + 2 * l;
        }
        //циклический сдвиг переменной x на n бит
        private ulong rot(ulong x, int n)
        {
            n = n % w;
            return (((x << n) | (x >> (w - n))));
        }

        private ulong[,] roundB(ulong[,] A, ulong RC)
        {
            ulong[] C = new ulong[5];
            ulong[] D = new ulong[5];
            ulong[,] B = new ulong[5, 5];
            //шаг θ
            for (int i = 0; i < 5; i++)
                C[i] = A[i, 0] ^ A[i, 1] ^ A[i, 2] ^ A[i, 3] ^ A[i, 4];
            for (int i = 0; i < 5; i++)
                D[i] = C[(i + 4) % 5] ^ rot(C[(i + 1) % 5], 1);
            for (int i = 0; i < 5; i++)
                for (int j = 0; j < 5; j++)
                    A[i, j] = A[i, j] ^ D[i];
            //шаги ρ и π
            for (int i = 0; i < 5; i++)
                for (int j = 0; j < 5; j++)
                    B[j, (2 * i + 3 * j) % 5] = rot(A[i, j], r[i, j]);
            //шаг χ
            for (int i = 0; i < 5; i++)
                for (int j = 0; j < 5; j++)
                    A[i, j] = B[i, j] ^ ((~B[(i + 1) % 5, j]) & B[(i + 2) % 5, j]);
            //шаг ι
            A[0, 0] = A[0, 0] ^ RC;
            return A;
        }

        private ulong[,] Keccackf(ulong[,] A)
        {
            for (int i = 0; i < n; i++)
                A = roundB(A, RC[i]);
            return A;
        }
        //функция дополняет 16-чную строку до размер r-байт и преобразует ее в матрицу 64-битных слов
        private ulong[][] padding(string M, int r)
        {
            int size = 0;
            //дополняем сообщение до длины кратной r
            M = M + "01";
            while (((M.Length / 2) * 8 % r) != ((r - 8)))
            {
                M = M + "00";
            };
            M = M + "80";
            //получаем из скольки блоков длиной r-бит состоит сообщение
            size = (((M.Length / 2) * 8) / r);
            //инициальзируем массив массивов 64-битных слов 
            ulong[][] arrayM = new ulong[size][];
            arrayM[0] = new ulong[1600 / w];
            string temp = "";
            int count = 0;
            int j = 0;
            int i = 0;
            //конвертируем строковое представление в массив 64-битных слов
            foreach (char ch in M)
            {
                if (j > (r / w - 1))
                {
                    j = 0;
                    i++;
                    arrayM[i] = new ulong[1600 / w];
                }
                count++;
                if ((count * 4 % w) == 0)
                {
                    arrayM[i][j] = Convert.ToUInt64(M.Substring((count - w / 4), w / 4), 16);
                    temp = ToReverseHexString(arrayM[i][j]);
                    arrayM[i][j] = Convert.ToUInt64(temp, 16);
                    j++;
                }

            }
            return arrayM;

        }
        private string ToReverseHexString(ulong S)
        {
            string temp = BitConverter.ToString(BitConverter.GetBytes(S).ToArray()).Replace("-", "");
            return temp;
        }
        private string ToHexString(ulong S)
        {
            string temp = BitConverter.ToString(BitConverter.GetBytes(S).Reverse().ToArray()).Replace("-", "");
            return temp;
        }
        //
        public string GetHash(string M, int r, int c, int d)
        {
            //Забиваем начальное значение матрицы S=0
            ulong[,] S = new ulong[5, 5];
            for (int i = 0; i < 5; i++)
                for (int j = 0; j < 5; j++)
                    S[i, j] = 0;
            ulong[][] P = padding(M, r);
            //Сообщение P представляет собой массив элементов Pi, 
            //каждый из которых в свою очередь является массивом 64-битных элементов 
            foreach (ulong[] Pi in P)
            {
                for (int i = 0; i < 5; i++)
                    for (int j = 0; j < 5; j++)
                        if ((i + j * 5) < (r / w))
                            S[i, j] = S[i, j] ^ Pi[i + j * 5];
                Keccackf(S);
            }
            string Z = "";
            //добавляем к возвращаемой строке значения, пока не достигнем нужной длины
            do
            {
                for (int i = 0; i < 5; i++)
                    for (int j = 0; j < 5; j++)
                        if ((5 * i + j) < (r / w))
                            Z = Z + ToReverseHexString(S[j, i]);
                Keccackf(S);
            } while (Z.Length < d);
            return Z.Substring(0, d);
        }
    }

}
