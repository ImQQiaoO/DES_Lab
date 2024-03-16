﻿#include <bitset>
#include <iostream>
#include <vector>

using namespace std;

/**
 * DES加密所需的一些常量
 */
 // 初始置换表
const int IP[] = {
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

// 结尾置换表
const int IP_1[] = {
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25
};

/*------------------下面是生成密钥所用表-----------------*/

// 密钥置换表，将64位密钥变成56位
const int PC_1[] = {
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4
};

// 压缩置换，将56位密钥压缩成48位子密钥
const int PC_2[] = {
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

// 每轮左移的位数
const int shiftBits[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

/*------------------下面是密码函数 f 所用表-----------------*/

// 扩展置换表，将 32位 扩展至 48位
const int E[] = {
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
};

// S盒，每个S盒是4x16的置换表，6位 -> 4位
const int S_BOX[8][4][16] = {
	{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
	{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
	{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
	{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
	},
	{
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
	{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
	{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
	{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
	},
	{
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
	{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
	{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
	{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
	},
	{
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
	{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
	{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
	{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
	},
	{
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
	{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
	{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
	{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
	},
	{
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
	{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
	{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
	{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
	},
	{
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
	{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
	{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
	{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
	},
	{
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
	{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
	{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
	{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
	}
};

// P置换，32位 -> 32位
const int P[] = {
	16, 7, 20, 21, 29, 12, 28, 17,
	1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9,
	19, 13, 30, 6, 22, 11, 4, 25
};

/**----------------------------------------------------------------**/

/**
 * 将传入的字符串转化为二进制bitset
 * @param sub_str 传入的字符串
 * @return 二进制bitset
 */
bitset<64> str_to_bitset(const string &sub_str) {
	bitset<64> bits;
	for (size_t i = 0; i < sub_str.size(); ++i) {
		bitset<8> temp_char(sub_str[i]);
		for (size_t j = 0; j < 8; ++j) {
			bits[i % 8 * 8 + j] = temp_char[j];
		}
	}
	return bits;
}

/**
 * 将明文转化为二进制块
 * @return blocks 64位二进制块的vector
 */
vector<bitset<64>> generate_text_block(string &str) {
	vector<bitset<64>> blocks;
	unsigned short empty_bytes;
	if (str.size() % 8) {
		empty_bytes = 8 - str.size() % 8;
	} else {
		empty_bytes = 0;
	}
	// 将不足8位的用全0填充至8位
	for (size_t i = 0; i < empty_bytes; ++i) {
		str.push_back('\0');
	}
	for (size_t i = 0; i < str.size() / 8; ++i) {
		string temp_sub_str = str.substr(i * 8, (i + 1) * 8);
		auto bits = str_to_bitset(temp_sub_str);
		blocks.push_back(bits);
	}
	return blocks;
}

/**
 * 检查key是否合法
 * @param key
 * @return
 */
bool check_key_legality(const string &key) {
	return key.size() == 8;
}

///**
// * 置换函数
// * @tparam N bitset的长度
// * @param original 输入的bitset
// * @param transform_table 置换表
// * @return 进行转化后的bitset
// */
//template <size_t N>
//bitset<N> transform(const bitset<N> &original, const int transform_table[N]) {
//	bitset<N> transformed;
//	for (size_t i = 0; i < N; ++i) {
//		transformed[i] = original[transform_table[i] - 1];
//	}
//	return transformed;
//}

/**
 * 生成子密钥
 * @param key
 */
bitset<48> generate_key(const string &key) {
	bitset<64> bits = str_to_bitset(key);
	bitset<56> key_56;
	for (size_t i = 0; i < 56; ++i) {
		key_56[i] = bits[PC_1[i] - 1];
	}
	bitset<28> left, right;
	for (size_t i = 0; i < 28; ++i) {
		left[i] = key_56[i];
		right[i] = key_56[i + 28];
	}
	for (size_t i = 0; i < 16; ++i) {
		left = (left << shiftBits[i]) | (left >> (28 - shiftBits[i]));
		right = (right << shiftBits[i]) | (right >> (28 - shiftBits[i]));
		bitset<56> temp_key;
		for (size_t j = 0; j < 28; ++j) {
			temp_key[j] = left[j];
			temp_key[j + 28] = right[j];
		}
		bitset<48> sub_key;
		for (size_t j = 0; j < 48; ++j) {
			sub_key[j] = temp_key[PC_2[j] - 1];
		}
		return sub_key;
	}
}

bitset<64> initial_transform_text(const bitset<64> &original) {
	bitset<64> transformed;
	for (size_t i = 0; i < 64; ++i) {
		transformed[i] = original[IP[i] - 1];
	}
	return transformed;
}

/**
 * 输出函数
 * @param blocks
 */
void show_blocks(const vector<bitset<64>> &blocks) {
	for (size_t i = 0; i < blocks.size(); ++i) {
		cout << blocks[i] << endl;
	}
}

int main() {
	string text = "abcdefgh";
	string key = "12345678";
	if (!check_key_legality(key)) {
		cout << "Key is illegal!" << endl;
		return 0;
	}
	// 生成子密钥
	auto sub_key = generate_key(key);
	// 生成明文块
	vector<bitset<64>> blocks = generate_text_block(text);



	show_blocks(blocks);	// 输出明文块

	return 0;
}

