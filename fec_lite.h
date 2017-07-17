


#ifndef FEC_LITE
#define FEC_LITE

#include <glib.h>

#define kIPPacketSize 1500
#define kMaxMediaPackets 48
#define kMaxFecPackets (kMaxMediaPackets>>1)
#define kRedPrimaryHeaderSize 1

#define kFecSequenceMapSize 64
typedef struct fec_sequence_map {
	guint16		map[kFecSequenceMapSize];		//init  as all 0
	guint16		loop_count;									//init as 0
	guint8			cur_index;				//max fec count is (loop_count*kFecSequenceMapSize + cur_index ),		init as 0
}fec_sequence_map;
void		updateFecMap(fec_sequence_map* smap, guint16 last_pkt_seq, guint8 fec_num);
guint32	getSequencePlusFromFecMap(fec_sequence_map* smap, guint16 pkt_seq) ;

typedef struct packet{
	unsigned char data[kIPPacketSize];
	int length;
} packet;
typedef struct janus_fec_lite {
		packet fec_packets[kMaxFecPackets];
		GList* media_packet_reorder_bucket;
		fec_sequence_map	seq_map;
} janus_fec_lite;



/* sample code:
 unsigned char* buf;
 janus_fec_input_media_packet(fec, buf, buf_len);
 GList* media_packet_list = NULL;
 if (janus_fec_get_good_media_packet_list(fec, &media_packet_list) > 0) {
	guint rate = 25;
   GList* fec_packet_list = NULL;
	janus_fec_generate_fec(fec, media_packet_list, rate, &fec_packet_list);
	janus_red_encode_fec_packet_list(media_packet_list, fec_packet_list, rtp_header_len, red, fec);
	//send fec packets
}
*/

janus_fec_lite*	janus_fec_create();
void		janus_fec_destory(janus_fec_lite* fec);

//-1 fail, 0 success
int		janus_fec_input_media_packet(janus_fec_lite* fec, unsigned char* packet, int length);

//-1 fail, >=0 the size of media  packet list
int 		janus_fec_get_good_media_packet_list(janus_fec_lite* fec, GList**  media_packet_list);

//-1 fail, 0 success
int		janus_fec_generate_fec(janus_fec_lite* fec, GList* media_packet_list, guint fec_rate, GList** fec_packet_list );

/////////// RED function
//-1 fail, >0 the size of red packet
int	janus_red_encode_media_packet(guint8* buffer, guint payload_length, guint rtp_header_length, guint red_pl_type);

//-1 fail, 0 success
int  janus_red_encode_fec_packet_list(GList* media_packet_list, GList* fec_packet_list, guint rtp_header_length, guint  red_pl_type, guint  fec_pl_type);

#endif		//FEC_LITE
