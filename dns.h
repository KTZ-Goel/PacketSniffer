#ifndef DNS_H
#define DNS_H

#include <stdint.h>

#include <QList>
#include <QStandardItem>

//DNS Header
struct sniff_dns {
	uint16_t dh_id;
	uint16_t dh_flags;
	uint16_t dh_question_count;
	uint16_t dh_answer_count;
	uint16_t dh_name_server_count;
	uint16_t dh_additional_record_count;
};

#define DH_IS_RESPONSE(flags)        ((flags) & 0x8000)    // 1000 0000 0000 0000 - If query, returns 0, if response, returns non-zero
#define DH_OPCODE(flags)             ((flags) & 0x7800)    // 0111 1000 0000 0000 - Returns the operation code of this dns packet
#define DH_IS_AUTHORITATIVE(flags)   ((flags) & 0x0400)    // 0000 0100 0000 0000 - Returns non-zero if this response is authoritative
#define DH_IS_TRUNC(flags)           ((flags) & 0x0200)    // 0000 0010 0000 0000 - Returns non-zero if this packet was truncated
#define DH_REC_DESIRED(flags)        ((flags) & 0x0100)    // 0000 0001 0000 0000 - Returns non-zero if this packet desires recursion
#define DH_REC_AVAILABLE(flags)      ((flags) & 0x0080)    // 0000 0000 1000 0000 - Returns non-zero if the server supports recursive name resolution
#define DH_RESERVED(flags)           ((flags) & 0x0070)    // 0000 0000 0111 0000 - Returns the value of the reserved bits
#define DH_RCODE(flags)              ((flags) & 0x000F)    // 0000 0000 0000 1111 - Returns the response code

#define DH_IS_POINTER(name)          (((name) & 0xC000) == 0xC000 ? 1 : 0)     // RFC 4.1.4 - Message Compression
#define DH_NAME_OFFSET(ptr)          (((ptr) & 0x3FFF))                        // RFC 4.1.4 - Message Compression


#define DH_OPCODE_QUERY              0
#define DH_OPCODE_IQUERY             1
#define DH_OPCODE_STATUS             2
#define DH_OPCODE_RESERVED           3
#define DH_OPCODE_NOTIFY             4
#define DH_OPCODE_UPDATE             5

/* RFC 1035 for explanations */
#define DH_RCODE_NO_ERR              0
#define DH_RCODE_FMT_ERR             1
#define DH_RCODE_SERV_ERR            2
#define DH_RCODE_NAME_ERR            3
#define DH_RCODE_NOT_IMPL            4
#define DH_RCODE_REFUSED             5
#define DH_RCODE_YX_DOMAIN           6
#define DH_RCODE_YX_RR_SET           7
#define DH_RCODE_NX_RR_SET           8
#define DH_RCODE_NOT_AUTH            9
#define DH_RCODE_NOTZONE             10

#define DH_RECORD_A                  1
#define DH_RECORD_CNAME              5

#define DNS_CLASS_IN                 1

void handle_dns(QList<QStandardItem *> *row, const struct sniff_dns *dns);
void handle_dns_fill(QString *infoStr, const struct sniff_dns *dns);

#endif // DNS_H

