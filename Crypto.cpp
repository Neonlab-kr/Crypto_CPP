#include <iostream>
#include <fstream>
#include <bitset>
#include <string>
#include <sstream>
using namespace std;

string hex2bin(string p)//hexadecimal to binary
{
	string ap = "";
	int l = p.length();
	for (int i = 0;i < l;i++)
	{
		string st = "";
		if (p[i] >= '0' && p[i] <= '9')
		{
			int te = int(p[i]) - 48;
			while (te > 0)
			{
				st += char(te % 2 + 48);
				te /= 2;
			}
			while (st.length() != 4)
				st += '0';
			for (int j = 3;j >= 0;j--)
				ap += st[j];
		}
		else
		{
			int te = p[i] - 'A' + 10;
			while (te > 0)
			{
				st += char(te % 2 + 48);
				te /= 2;
			}
			for (int j = 3;j >= 0;j--)
				ap += st[j];
		}
	}
	return ap;
}

string TextToBinaryString(string words) {
	string binaryString = "";
	for (char& _char : words) {
		binaryString += bitset<8>(_char).to_string();
	}
	return binaryString;
}

string crypto(string p,string ke)
{
	string l, r, ap = "", kp, rtem;
	int key[16][48];
	/*p = hex2bin(p);*/
	p = TextToBinaryString(p);
	kp = hex2bin(ke);
	for (int i = 0;i < 48;i++)
		key[0][i] = kp[i] - '0';
	int nshift;
	l = p.substr(0, 32);
	r = p.substr(32, 32);
	//키생성
	int i, t = 1, j, row, col, temp, round = 16;
	for (i = 1;i < 16;i++)
	{
		nshift = key[i - 1][47] + 1;
		while (nshift)
		{
			key[i][0] = key[i - 1][47];
			for (j = 46;j >= 0;j--)
			{
				key[i][j + 1] = key[i - 1][j];
			}
			nshift = nshift - 1;
		}
	}
	//고정순열
	int per[32] = { 16 ,  7 , 20  ,21,
		29 , 12 , 28 , 17,
		1 , 15,  23,  26,
		5 , 18 , 31  ,10,
		2  , 8 , 24 , 14,
		32  ,27,   3 ,  9,
		19  ,13,  30,   6,
		22 , 11  , 4 , 25 };

	//SBOX 6->4
	int s[8][4][16] =
	{ {
			14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
			0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
			4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
			15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
		},
	{
		15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
		3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
		0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
		13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
	},


	{
		10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
		13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
		13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
		1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
	},
	{
		7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
		13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
		10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
		3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
	},
	{
		2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
		14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
		4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
		11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
	},
	{
		12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
		10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
		9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
		4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
	},
	{
		4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
		13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
		1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
		6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
	},
	{
		13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
		1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
		7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
		2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
	} };
	//암호화
	string cip = "";
	while (round--)
	{
		rtem = r;
		t = 1;
		string ep = "", xorout = "", sout = "", soutt;
		//PBOX 32->48
		ep += r[31];
		for (i = 0;i < 32;i++)
		{
			if ((t + 1) % 6 == 0)
			{
				ep += r[4 * ((t + 1) / 6)];
				t++;
			}
			if (t % 6 == 0 && i != 0)
			{
				ep += r[4 * (t / 6) - 1];
				t++;
			}
			ep = ep + r[i];
			t++;
		}
		ep += r[0];
		//PBOX출력과 키 XOR
		for (i = 0;i < 48;i++)
			xorout += char(((int(ep[i]) - 48) ^ key[16 - round - 1][i]) + 48);
		//SBOX 48->32압축
		for (i = 0;i < 48;i += 6)
		{
			row = (int(xorout[i + 5]) - 48) + (int(xorout[i]) - 48) * 2;
			col = (int(xorout[i + 1]) - 48) * 8 + (int(xorout[i + 2]) - 48) * 4 + (int(xorout[i + 3]) - 48) * 2 + (int(xorout[i + 4]) - 48);
			temp = s[i / 6][row][col];
			soutt = "";
			while (temp > 0)
			{
				soutt += char(temp % 2 + 48);
				temp /= 2;
			}
			while (soutt.length() != 4)
				soutt += '0';
			for (j = soutt.length() - 1;j >= 0;j--)
				sout += soutt[j];
		}
		//PBOX 고정순열
		char pc[32];
		for (i = 0;i < 32;i++)
			pc[i] = sout[per[i] - 1];
		r = "";
		for (i = 0;i < 32;i++)
			r += char(((int(pc[i]) - 48) ^ (int(l[i]) - 48)) + 48);
		l = rtem;
		cip = "";
		for (i = 0;i < 32;i += 8)
		{
			int te;
			te = ((int(l[i]) - 48) * 8 + (int(l[i + 1]) - 48) * 4 + (int(l[i + 2]) - 48) * 2 + (int(l[i + 3]) - 48)) * 16 + (int(l[i + 4]) - 48) * 8 + (int(l[i + 5]) - 48) * 4 + (int(l[i + 6]) - 48) * 2 + (int(l[i + 7]) - 48);
			cip += te;
		}
		for (i = 0;i < 32;i += 8)
		{
			int te;
			te = ((int(r[i]) - 48) * 8 + (int(r[i + 1]) - 48) * 4 + (int(r[i + 2]) - 48) * 2 + (int(r[i + 3]) - 48)) * 16 + (int(r[i + 4]) - 48) * 8 + (int(r[i + 5]) - 48) * 4 + (int(r[i + 6]) - 48) * 2 + (int(r[i + 7]) - 48);
			cip += te;

		}
	}
	string cip1 = cip;
	//복호
	round = 16;
	string ltem;
	while (round--)
	{
		ltem = l;
		t = 1;
		string ep = "", xorout = "", sout = "", soutt;
		//PBOX 32->48
		ep += l[31];
		for (i = 0;i < 32;i++)
		{
			if ((t + 1) % 6 == 0)
			{
				ep += l[4 * ((t + 1) / 6)];
				t++;
			}
			if (t % 6 == 0 && i != 0)
			{
				ep += l[4 * (t / 6) - 1];
				t++;
			}
			ep = ep + l[i];
			t++;
		}
		ep += l[0];
		//PBOX출력과 키 XOR
		for (i = 0;i < 48;i++)
			xorout += char(((int(ep[i]) - 48) ^ key[round][i]) + 48);
		//SBOX 48->32압축
		for (i = 0;i < 48;i += 6)
		{
			row = (int(xorout[i + 5]) - 48) + (int(xorout[i]) - 48) * 2;
			col = (int(xorout[i + 1]) - 48) * 8 + (int(xorout[i + 2]) - 48) * 4 + (int(xorout[i + 3]) - 48) * 2 + (int(xorout[i + 4]) - 48);
			temp = s[i / 6][row][col];
			soutt = "";
			while (temp > 0)
			{
				soutt += char(temp % 2 + 48);
				temp /= 2;
			}
			while (soutt.length() != 4)
				soutt += '0';
			for (j = soutt.length() - 1;j >= 0;j--)
				sout += soutt[j];
		}
		//PBOX 고정순열
		char pc[32];
		for (i = 0;i < 32;i++)
			pc[i] = sout[per[i] - 1];
		l = "";
		for (i = 0;i < 32;i++)
			l += char(((int(pc[i]) - 48) ^ (int(r[i]) - 48)) + 48);
		r = ltem;
		cip = "";
		for (i = 0;i < 32;i += 8)
		{
			int te;
			te = te = ((int(l[i]) - 48) * 8 + (int(l[i + 1]) - 48) * 4 + (int(l[i + 2]) - 48) * 2 + (int(l[i + 3]) - 48)) * 16 + (int(l[i + 4]) - 48) * 8 + (int(l[i + 5]) - 48) * 4 + (int(l[i + 6]) - 48) * 2 + (int(l[i + 7]) - 48);;
			cip += char(te);
		}
		for (i = 0;i < 32;i += 8)
		{
			int te;
			te = ((int(r[i]) - 48) * 8 + (int(r[i + 1]) - 48) * 4 + (int(r[i + 2]) - 48) * 2 + (int(r[i + 3]) - 48)) * 16 + (int(r[i + 4]) - 48) * 8 + (int(r[i + 5]) - 48) * 4 + (int(r[i + 6]) - 48) * 2 + (int(r[i + 7]) - 48);;
			cip += char(te);
		}
	}
	string cip2 = cip;

	return cip1 + cip2;
}

int main()
{
	string ke, p, cip, cip1, cip2="";
	// 소스 파일과 목적 파일 열기
	const char* srcFile = "동의대교가.txt";
	const char* destFile1 = "암호화.txt";
	const char* destFile2 = "복호화.txt";
	ofstream cryp(destFile1, ios::out | ios::binary);
	ofstream plain(destFile2, ios::out | ios::binary);
	ifstream fsrc(srcFile, ios::in | ios::binary);
	// 열기 실패 검사
	if (!cryp) {
		cout << destFile1 << " 열기 오류" << endl;
		return 0;
	}
	if (!plain) {
		cout << destFile2 << " 열기 오류" << endl;
		return 0;
	}
	if (!fsrc) {
		cout << srcFile << " 열기 오류" << endl;
		return 0;
	}

	char buf[1024];
	int n;
	while (!fsrc.eof()) { // 파일 끝까지
		fsrc.read(buf, 1024);
		n = fsrc.gcount(); // 실제 읽은 바이트 수 계산
	}
	if (n % 8 != 0) {
		for (int i = 0;i < 8 - n % 8;i++)
		{
			buf[n + i] = NULL;
		}
	}
pr:;
	cout << "16진수 형태의 12자리 키를 입력하세요.\n";
	cin >> ke;
	if (ke.length() != 12)
	{
		cout << "12자리가 아닙니다.\n";
		goto pr;
	}
	for (int i = 0;i < 12;i++)
	{
		if ((ke[i] >= '0' && ke[i] <= '9') || (ke[i] >= 'A' && ke[i] <= 'F'))
			;
		else
		{
			cout << "유효한 키값이 아닙니다.\n";
			goto pr;
		}
	}
	for (int bcount = 0;bcount < (n + 8 - n % 8) / 8;bcount++)
	{
		p = "";
		for (int i = 0;i <8;i++)
		{
			p = p + buf[bcount * 8 + i];
		}
		cip = crypto(p, ke);
		cip1 += cip.substr(0, 8);
		cip2 += cip.substr(8, 8);
	}
	cip1 = cip1.substr(0, n);
	cip2 = cip2.substr(0,n);
	cryp.write(cip1.c_str(), cip1.size());
	plain.write(cip2.c_str(), cip2.size());
	fsrc.close();
	cryp.close();
	plain.close();
}