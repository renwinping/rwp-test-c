// telnet_parser.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "../common/BytesTools.h"

#define SCEnter() 
#define SCLogDebug(msgFmt, ...) do { \
			fprintf(stderr, msgFmt, ##__VA_ARGS__); fprintf(stderr,"\n");\
    } while(0)

#define TCP_PORT_TELNET 23

/*telnet state*/
#define TELNET_CMD_IAC	                         0
#define TELNET_CMD_LOGIN_USER          1
#define TELNET_CMD_LOGIN_PASS          2
#define TELNET_CMD_LOGIN_PASSWD     3
#define TELNET_CMD_LOGIN_ACK	          4
#define TELNET_CMD_LOGIN_FAIL           5
#define TELNET_CMD_LOGIN_DONE	   6
#define TELNET_CMD_OTHER	                 7
#define TELNET_CMD_LOGIN_EXIT           8
#define TELNET_CMD_REPLAY_CATCHE    9
#define TELNET_CMD_REQUEST_CATCHE  10

//IAC相关宏
#define TELNET_IAC   255
#define TELNET_SB    250
#define TELNET_WILL  251
#define TELNET_WONT  252
#define TELNET_DO    253
#define TELNET_DONT  254
#define TELNET_SE    240

#define ISO_nl       0x0a
#define ISO_cr       0x0d
#define STATE_NORMAL      0
#define STATE_IAC_RCVD    1
#define STATE_WILL_RCVD   2
#define STATE_WONT_RCVD   3
#define STATE_DO_RCVD     4
#define STATE_DONT_RCVD   5
#define STATE_CLOSE  6
#define TELNET_MAX_CMD_LEN      (8*1024)

/* TTY input chars */
#define IN_NULL     '\0'
#define IN_BS       '\x8'
#define IN_DEL      0x7F
#define IN_EOL      '\r'
#define IN_SKIP     '\3'
#define IN_EOF      '\x1A'
#define IN_ESC      '\033'

/* TTY output translation */
#define OUT_DEL     "\x8 \x8"
#define OUT_EOL     "\r\n"
#define OUT_SKIP    "^C\n"
#define OUT_EOF     "^Z"
#define OUT_BEL     "\7"


//find 'substr' from a fixed-length buffer 
//('full_data' will be treated as binary data buffer)
//return NULL if not found
static const char* memstr(const char* full_data, int full_data_len, const char* substr, int sublen)
{
	if (full_data == NULL || full_data_len <= 0 || substr == NULL) {
		return NULL;
	}
	int i;
	const char* cur = full_data;
	int last_possible = full_data_len - sublen + 1;
	for (i = 0; i < last_possible; i++) {
		if (*cur == *substr) {
			//assert(full_data_len - i >= sublen);
			if (memcmp(cur, substr, sublen) == 0) {
				//found
				return cur;
			}
		}
		cur++;
	}

	return NULL;
}

static char* tohex(const uint8_t* input, uint32_t len)
{
#define  BUF_MAX_SIZE 100
	static char buf[BUF_MAX_SIZE + 1];
	int lengh = 0;
	size_t x = 0;
	uint8_t* p = (uint8_t*)input;
	uint8_t c = 0;
	char print_buf[BUF_MAX_SIZE + 1] = ""; int id = 0;
	for (; (x < len) && (lengh < BUF_MAX_SIZE); x++) {
		c = *p++;
		lengh += snprintf(&buf[lengh], BUF_MAX_SIZE - lengh, "%02x ", c);
		if ((isprint(c)) || ((c >= 192) && (c <= 255))) {
			print_buf[id++] = c;
		}
	}
	buf[lengh] = '\0'; print_buf[id] = '\0';
	SCLogDebug("msg_content(bytes:%d):asscii[%d]:%s,(hex:%s)\n", len, id, print_buf, buf);
	return buf;
}

static int TelnetFetchUserInfo_new(uint8_t* negopt_buf, int buf_len, char* user, int usr_len)
{
	/*wireshark pcap
	0060   ff fa 27 00 00 44 49 53 50 4c 41 59 01 6c 6f   ..'..DISPLAY.lo
	0070   63 61 6c 68 6f 73 74 3a 31 31 2e 30 00 55 53 45   calhost:11.0.USE
	0080   52 01 66 74 70 74 65 73 74 ff f0
	//序列解释如下:	 IAC SB NEW-ENVIRON IS type ... [ VALUE ... ] [ type ... [ VALUE ... ] [ ... ] ] IAC SE
	*/
	SCEnter();
	int Found = 0;
	if (buf_len < 8) {//至少应包含NEW-ENVIRON IS type USER VALUE
		return Found;
	}
#define	NEW_ENVIRON_OPT_TYPE 0x27 
#define VAR              0
#define	VALUE            1
#define IS               0
#define	SEND             1
#define	INFO             2

	char* spos = (char*)&negopt_buf[1];//跳到IS
	char const_user_var[] = "\x00""USER""\x01";

	const char* pos = memstr(spos, buf_len - 2, const_user_var, 6);
	if (pos)
	{
		int l = buf_len - 1 - (pos - spos + 6);//移动(NEW-ENVIRON IS +pos+4);
		spos = (char*)pos;
		spos += 6;
		int c = 0;
		while (l > 0) {
			if ((*spos == VAR) || (*spos == VALUE)) {
				break;
			}
			if (c < usr_len) {
				user[c++] = *spos;
			}
			l--; spos++;
		}
		Found = 1;
	}
	return Found;
}


static int TelnetFetchUserInfo(uint8_t* negopt_buf, int buf_len, char* user, int usr_len)
{
	/*wireshark pcap
	0060   ff fa 27 00 00 44 49 53 50 4c 41 59 01 6c 6f   ..'..DISPLAY.lo
	0070   63 61 6c 68 6f 73 74 3a 31 31 2e 30 00 55 53 45   calhost:11.0.USE
	0080   52 01 66 74 70 74 65 73 74 ff f0
	//序列解释如下:	 IAC SB NEW-ENVIRON IS type ... [ VALUE ... ] [ type ... [ VALUE ... ] [ ... ] ] IAC SE
	*/
	SCEnter();
	int Found = 0;
	if (buf_len < 8) {//至少应包含NEW-ENVIRON IS type USER VALUE
		return Found;
	}

	uint8_t opt_byte = negopt_buf[0];
#define	NEW_ENVIRON_OPT_TYPE 0x27 
#define VAR              0
#define	VALUE            1
#define IS               0
#define	SEND             1
#define	INFO             2
	if (opt_byte == NEW_ENVIRON_OPT_TYPE)//RFC 1572
	{
		char* spos = (char*)&negopt_buf[2];//跳到IS
		char const_user_var[] = "\x00""USER""\x01";

		const char* pos = memstr(spos, buf_len - 2, const_user_var, 6);
		if (pos)
		{
			int l = buf_len - 2 - (pos - spos + 6);//移动(NEW-ENVIRON IS +pos+4);
			spos = (char*)pos;
			spos += 6;
			int c = 0;
			while (l > 0) {
				if ((*spos == VAR) || (*spos == VALUE)) {
					break;
				}
				if (c < usr_len) {
					user[c++] = *spos;
				}
				l--; spos++;
			}
			Found = 1;
		}
	}
	return Found;
}

static int tvb_find_guint8(uint8_t* tvb, const int maxlength, const int offset, const uint8_t needle)
{
	const uint8_t* result = (const uint8_t*)memchr(tvb + offset, needle, maxlength);
	if (result == NULL) {
		return -1;
	}
	else {
		return (int)(result - tvb);
	}
}

static uint8_t tvb_get_guint8(uint8_t* tvb, const int offset)
{
	return *(tvb + offset);
}

static int find_unescaped_iac(const uint8_t* tvb, int tvb_lengh, int offset, int len)
{
	int iac_offset = offset;

	/* If we find an IAC (0XFF), make sure it is not followed by another 0XFF.
	   Such cases indicate that it is not an IAC at all */
	while ((iac_offset = tvb_find_guint8((uint8_t*)tvb, tvb_lengh, iac_offset, TELNET_IAC)) != -1 &&
		(tvb_get_guint8((uint8_t*)tvb, iac_offset + 1) == TELNET_IAC))
	{
		iac_offset += 2;//ff fa 23跳到23
		len = iac_offset - offset;
	}
	return iac_offset;
}

static void telnet_suboption_name(uint8_t* tvb, int tvb_lengh,int* offset)
{
	uint8_t      opt_byte;
	opt_byte = tvb_get_guint8(tvb, *offset);
	(*offset)++;
}

static int telnet_command(uint8_t* tvb, int tvb_lengh, int start_offset)
{
	static int s_index = 0;
	SCLogDebug("telnet_command[%d] start_offset:%d",s_index++, start_offset);
	int    offset = start_offset;
	uint8_t cmd_code;

	offset += 1;  /* skip IAC */
	cmd_code = tvb_get_guint8(tvb, offset);

	offset++;//skip cmdcode

	switch (cmd_code) {
	case TELNET_WILL:
		SCLogDebug("0x%0x-<Will>", cmd_code);
		telnet_suboption_name(tvb, tvb_lengh, &offset);
		break;

	case TELNET_WONT:
		SCLogDebug("0x%0x-<Won't>", cmd_code);
		telnet_suboption_name(tvb, tvb_lengh, &offset);
		break;

	case TELNET_DO:
		SCLogDebug("0x%0x-<Do>", cmd_code);
		telnet_suboption_name(tvb, tvb_lengh, &offset);
		break;

	case TELNET_DONT:
		SCLogDebug("0x%0x-<Don't>", cmd_code);
		telnet_suboption_name(tvb, tvb_lengh, &offset);
		break;

	case TELNET_SB:
	{
		SCLogDebug("0x%0x-<Suboption>", cmd_code);
		int iac_found = 1;
		do {
			int iac_offset = tvb_find_guint8(tvb, tvb_lengh, offset, TELNET_IAC);
			if (iac_offset == -1) {
				/* None found - run to the end of the packet. */
				offset = tvb_lengh - 1;
			}
			else {
				if (((iac_offset + 1) >= tvb_lengh) ||
					(tvb_get_guint8(tvb, iac_offset + 1) != TELNET_IAC)) {
					/* We really found a single IAC, so we're done */
					offset = iac_offset;
				}
				else {
					/*
					 * We saw an escaped IAC, so we have to move ahead to the
					 * next section
					 */
					iac_found = 0;
					offset = iac_offset + 2;
				}
			}

		} while (!iac_found);

		int subneg_len = offset - start_offset;
		start_offset += 3;    /* skip IAC, SB, and option code */
		subneg_len -= 3;
		SCLogDebug("Suboption content lengh:%d", subneg_len);
		if (subneg_len > 0) {
			//提取子项协商内容
			uint8_t opt_byte = tvb_get_guint8(tvb, start_offset - 1);
			SCLogDebug("get opt code:0x%0x", opt_byte);
			if (NEW_ENVIRON_OPT_TYPE == opt_byte)
			{
				char negotiation_option[255] = "";
				memcpy(negotiation_option, tvb + start_offset, subneg_len);//复制opt-code以后的值

				//当以telnet -l xxx方式登录时，可能通过“IAC协商”方式传递用户名，须要提取之否则没有用户绑定
				char user[256] = "";
				if (TelnetFetchUserInfo_new((uint8_t*)negotiation_option, subneg_len, user, 255)) {
					SCLogDebug("fetch user info from negotition,user:%s", user);
					//strncpy(telnet_status.user, user, 32);
				}
			}
		}
	}
	break;

	default:
		SCLogDebug("0x%0x-<unknown option>", cmd_code);
		break;
	}

	return offset;
}

void TelnetClientParse(const uint8_t* input, uint32_t input_len)
{
	SCEnter();
	const uint8_t* current_input = NULL;

	current_input = input;


	char* endptr = strpbrk((char*)current_input, "\n\r");
	if (endptr != NULL) {
		*endptr = '\0';
		SCLogDebug("inspect new line, input_len:%u", input_len);
		int len = endptr - (char*)current_input;
		if (len > 0) {
			// 			memcpy(state->telnet_head_ts_db + state->telnet_head_ts_len, current_input, len);
			// 			state->telnet_head_ts_len += len;
		}

	}
	else
	{
		int iac_width = 0;
		int offset = 0;

		int tvb_lengh = /*state->telnet_head_ts_len*/input_len;
		uint8_t* tvb = /*state->telnet_head_ts_db*/(uint8_t*)input;
		int lengh = /*state->telnet_head_ts_len*/input_len;
		while (lengh > 0)
		{
			int iac_offset = find_unescaped_iac(tvb, tvb_lengh, offset, iac_width);
			if (iac_offset != -1) {
				/*
				 * We found an IAC byte.
				 * If there's any data before it, add that data to the
				 * tree, a line at a time.
				 */
				int data_len = iac_offset - offset;
				if (data_len > 0) {
					SCLogDebug(" If there's any data before IAC, igored these bytes");
				}

				//lengh -= iac_offset;
				/*
				 * Now interpret the command.
				 */
				offset = telnet_command(tvb, tvb_lengh, iac_offset);

				lengh = (tvb_lengh-offset);

				SCLogDebug("telnet_command: start_offset:%d, offset:%d, remain bytes:%d", iac_offset, offset,lengh);

			}
			else
			{
				//未找到“IAC”跳出
				break;
			}
		}

		int remaining = (tvb_lengh - offset);
		if (remaining > 0)
		{
			SCLogDebug("telnet copy remaining bytes to ringbuffer, length(bytes):%d, total_leng:%d, offset:%d", remaining, tvb_lengh, offset);
			//memcpy(state->telnet_head_ts_db + state->telnet_head_ts_len, input + offset, remaining);
			//state->telnet_head_ts_len += remaining;
		}
	}

	if (endptr)
	{
		// 	{
		// 		//发现换行时，解析之前接收的字符，并清空行缓冲区
		// 		if (telnet_status.status == TELNET_CMD_LOGIN_USER)
		// 		{
		// 		}
		// 		else if (telnet_status.status == TELNET_CMD_LOGIN_PASSWD)
		// 		{
		// 			TelnetParsePASS(state);
		// 		}
		// 		else if (telnet_status.status == TELNET_CMD_LOGIN_FAIL)
		// 		{
		// 			state->telnet_status = TELNET_CMD_LOGIN_USER;
		// 			telnet_status.status = TELNET_CMD_LOGIN_USER;
		// 		}
		// 		else if (telnet_status.status == TELNET_CMD_LOGIN_DONE)
		// 		{
		// 			TelnetParseOTHER(state);
		// 		}
		// 		else if (telnet_status.status == TELNET_CMD_OTHER)
		// 		{
		// 			TelnetParseOTHER(state);
		// 		}
		// 		else if (telnet_status.status == TELNET_CMD_LOGIN_EXIT)
		// 		{
		// 			TelnetParseEXIT(state);
		// 		}
		// 		SCLogDebug("find telnet new line char,clear command line buffer, telnet status:%d(%s)",
		// 			telnet_status.status, TelnetStatusName(telnet_status.status));
		// 		memset(state->telnet_head_ts_db, 0, TELNET_MAX_CMD_LEN);
		// 		state->telnet_head_ts_len = 0;
		// 	}
	}
}
int main()
{
	char stream[] = "fffa2000302c30fff0fffa23006c6f63616c686f73743a31312e30fff0fffa270000444953504c4159016c6f63616c686f73743a31312e3000555345520166747074657374fff0fffa1800585445524dfff0";
	int bin_lengh = 0;
	char* buf = NULL;
	bin_lengh = readableHexStreamToBytes(stream, strlen(stream),&buf);
	if (bin_lengh)	{
		TelnetClientParse((uint8_t*)buf, bin_lengh);
	}

	char  errmsg[] = "fffd03fffb18fffb1ffffb20fffb21fffb22fffb27fffd05fffb23";
	char* buff_ls = NULL;
	bin_lengh = readableHexStreamToBytes(errmsg, strlen(errmsg), &buff_ls);
	if (bin_lengh) {
		TelnetClientParse((uint8_t*)buff_ls, bin_lengh);
	}
    std::cout << "Hello World!\n";
}

