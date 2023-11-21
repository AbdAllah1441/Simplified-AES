#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MODULUS 0b10011 // x^4 + x + 1 in binary

// Substitution table (S-Box)
const unsigned char sBox[16] = {
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7};

const unsigned char inverseSBox[16] = {
    0XA, 0x5, 0x9, 0xB,
    0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3,
    0xC, 0x4, 0xD, 0xE};

char RotNib(char in)
{
    char right = in & 0X0F;
    char left = (in & 0XF0) >> 4;
    return right << 4 | left;
}

char SubNib(char in)
{
    unsigned char nib1 = (in & 0XF0) >> 4;
    unsigned char nib2 = in & 0X0F;
    return (sBox[nib1] << 4) | sBox[nib2];
}

// Function to multiply two numbers in GF(2^4)
char multiply_GF2_4(char a, char b)
{
    char result = 0;

    for (int i = 0; i < 4; ++i)
    {
        if (b & 1)
        {
            result ^= a; // XOR operation
        }

        int highBitSet = a & 0b1000;
        a <<= 1;

        if (highBitSet)
        {
            a ^= MODULUS;
        }

        b >>= 1;
    }

    return result;
}

void multiplyMatrices(short firstMatrix[2][2], short secondMatrix[2][2], short result[2][2])
{
    for (int i = 0; i < 2; ++i)
    {
        for (int j = 0; j < 2; ++j)
        {
            result[i][j] = 0;

            for (int k = 0; k < 2; ++k)
            {
                result[i][j] ^= multiply_GF2_4(firstMatrix[i][k], secondMatrix[k][j]);
            }
        }
    }
}

// Nibble substitution function for 16-bit input
unsigned short substituteNibbles(unsigned short input)
{
    // Masking to separate the two 4-bit nibbles
    unsigned short firstNibble = input & 0x000F;
    unsigned short secondNibble = input & 0x00F0;
    unsigned short thirdNibble = input & 0x0F00;
    unsigned short fourthNibble = input & 0xF000;

    // Perform nibble substitution for each nibble
    unsigned char firstSubstitutedNibble = sBox[firstNibble];
    unsigned char secondSubstitutedNibble = sBox[secondNibble >> 4];
    unsigned char thirdSubstitutedNibble = sBox[thirdNibble >> 8];
    unsigned char fourthSubstitutedNibble = sBox[fourthNibble >> 12];
    // Combine the substituted nibbles back into a 16-bit result
    return firstSubstitutedNibble | secondSubstitutedNibble << 4 | thirdSubstitutedNibble << 8 | fourthSubstitutedNibble << 12;
}

unsigned short substituteNibblesInverse(unsigned short input)
{
    // Masking to separate the two 4-bit nibbles
    unsigned short firstNibble = input & 0x000F;
    unsigned short secondNibble = input & 0x00F0;
    unsigned short thirdNibble = input & 0x0F00;
    unsigned short fourthNibble = input & 0xF000;

    // Perform nibble substitution for each nibble
    unsigned char firstSubstitutedNibble = inverseSBox[firstNibble];
    unsigned char secondSubstitutedNibble = inverseSBox[secondNibble >> 4];
    unsigned char thirdSubstitutedNibble = inverseSBox[thirdNibble >> 8];
    unsigned char fourthSubstitutedNibble = inverseSBox[fourthNibble >> 12];
    // Combine the substituted nibbles back into a 16-bit result
    return firstSubstitutedNibble | secondSubstitutedNibble << 4 | thirdSubstitutedNibble << 8 | fourthSubstitutedNibble << 12;
}

unsigned short shiftRows(unsigned short input)
{
    unsigned short firstNibble = (input & 0x000F) << 8;
    unsigned short thirdNibble = (input & 0x0F00) >> 8;
    unsigned short out = (input & 0xF0F0) | firstNibble | thirdNibble;
    return out;
}

unsigned short DEC(unsigned short cipher, unsigned short key)
{
    unsigned short w0 = (key & 0XFF00) >> 8;
    unsigned short w1 = key & 0X00FF;
    unsigned short w2 = w0 ^ 0b10000000 ^ SubNib(RotNib(w1));
    unsigned short w3 = w1 ^ w2;
    unsigned short w4 = w2 ^ 0b00110000 ^ SubNib(RotNib(w3));
    unsigned short w5 = w3 ^ w4;
    unsigned short key0 = key;
    unsigned short key1 = (w2 << 8) | w3;
    unsigned short key2 = (w4 << 8) | w5;

    // Add Round Key 0
    unsigned short addround0 = cipher ^ key2;

    // Perform nibble substitution for the entire block
    unsigned short shift1 = shiftRows(addround0);
    unsigned short s_box1 = substituteNibblesInverse(shift1);

    unsigned short addround1 = s_box1 ^ key1;

    short mix[2][2] = {{9, 2}, {2, 9}};
    short shiftMatrix[2][2] = {{(addround1 & 0XF000) >> 12, (addround1 & 0X00F0) >> 4}, {(addround1 & 0X0F00) >> 8, (addround1 & 0X000F)}};
    short mixedMatrix[2][2];

    multiplyMatrices(mix, shiftMatrix, mixedMatrix);

    unsigned short mixed1 = mixedMatrix[0][0] << 12 | mixedMatrix[1][0] << 8 | mixedMatrix[0][1] << 4 | mixedMatrix[1][1];

    unsigned short shift2 = shiftRows(mixed1);
    unsigned short s_box2 = substituteNibblesInverse(shift2);

    unsigned short addround2 = s_box2 ^ key0;
    unsigned short plaintext = addround2;

    return plaintext;
}

unsigned short ENC(unsigned short plaintext, unsigned short key)
{
    unsigned short w0 = (key & 0XFF00) >> 8;
    unsigned short w1 = key & 0X00FF;
    unsigned short w2 = w0 ^ 0b10000000 ^ SubNib(RotNib(w1));
    unsigned short w3 = w1 ^ w2;
    unsigned short w4 = w2 ^ 0b00110000 ^ SubNib(RotNib(w3));
    unsigned short w5 = w3 ^ w4;
    unsigned short key0 = key;
    unsigned short key1 = (w2 << 8) | w3;
    unsigned short key2 = (w4 << 8) | w5;

    unsigned short addround0 = plaintext ^ key0;
    unsigned short s_box1 = substituteNibbles(addround0);
    unsigned short shift1 = shiftRows(s_box1);
    short mix[2][2] = {{1, 4}, {4, 1}};
    short shiftMatrix[2][2] = {{(shift1 & 0XF000) >> 12, (shift1 & 0X00F0) >> 4}, {(shift1 & 0X0F00) >> 8, (shift1 & 0X000F)}};
    short mixedMatrix[2][2];
    multiplyMatrices(mix, shiftMatrix, mixedMatrix);
    unsigned short mixed1 = mixedMatrix[0][0] << 12 | mixedMatrix[1][0] << 8 | mixedMatrix[0][1] << 4 | mixedMatrix[1][1];

    unsigned short addround1 = mixed1 ^ key1;
    unsigned short s_box2 = substituteNibbles(addround1);
    unsigned short shift2 = shiftRows(s_box2);

    unsigned short addround2 = shift2 ^ key2;
    unsigned short cipher = addround2;

    return cipher;
}

char charToDigit(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    else if (c >= 'A' && c <= 'F')
    {
        return 10 + (c - 'A');
    }
    else if (c >= 'a' && c <= 'f')
    {
        return 10 + (c - 'a');
    }
    else
    {
        fprintf(stderr, "Invalid character in hexadecimal string: %c\n", c);
        return -1; // Signal an error
    }
}

short hexStringToShort(const char *str)
{
    short result = 0;

    while (*str != '\0')
    {
        int digit = charToDigit(*str);
        if (digit == -1)
        {
            return -1; // Error occurred
        }

        result = (result << 4) | digit; // Shift and combine
        str++;
    }

    return result;
}

int main(int argc, char *argv[])
{

    unsigned short key = hexStringToShort(argv[2]);
    unsigned short text = hexStringToShort(argv[3]);

    if (strcmp(argv[1], "ENC") == 0)
    {
        unsigned short cipher = ENC(text, key);
        printf("0X%04X\n", cipher);
    }

    else if (strcmp(argv[1], "DEC") == 0)
    {
        unsigned short plaintext = DEC(text, key);
        printf("0X%04X\n", plaintext);
    }

    return 0;
}