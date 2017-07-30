


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
/*last_pkt_seq is  the original sequence number of the last rtp packet
fec_num is the number of new fec packets this time, not accumulated*/
void		updateFecMap(fec_sequence_map* smap, guint16 last_pkt_seq, guint8 fec_num);
/*pkt_seq is the original  sequence number of the rtp  packet
return value is the accumulated plus*/
guint32	getSequencePlusFromFecMap(fec_sequence_map* smap, guint16 pkt_seq) ;

typedef struct packet{
	unsigned char 	data[kIPPacketSize];
	int 						length;
} packet;

/*encoder*/
typedef struct janus_fec_enc {
		packet		fec_packets[kMaxFecPackets];	
		GList*		media_packet_reorder_bucket;
		fec_sequence_map	seq_map;
} janus_fec_enc;

/*decoder*/
typedef struct received_packet {
		packet 		pkt;
		//gboolean	is_fec;
		guint32		ssrc;			//must be set for FEC packet, but not required for media packet
		guint16		seq;
} received_packet;
//this is media  packet, not FEC
typedef  struct recovered_packet {
		received_packet*	rpkt;					//responsible  of "release"
		gboolean	was_recovered;
		gboolean 	returned;
		guint8			length_recovery[2];
} recovered_packet;
typedef struct protected_packet {
		packet*						pkt;					//NOT responsible  of "release"
		guint16						target_seq;
} protected_packet;
typedef  struct fec_packet {
		//gboolean				deprecated;				//flag to indicate this fec goup will never be complete, we can delete the fec packet
		received_packet* 	rpkt;							//responsible  of "release"
		GList*						protected_packet_list;		/*type of protected_packet*/
} fec_packet;
typedef struct janus_fec_dec {
		GList* 	fec_packet_list;					/*type  of fec_packet*/
		GList* 	recovered_packet_list;		/*type  of recovered_packet*/
} janus_fec_dec;


/*										FEC 			ENCODER															*/
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

janus_fec_enc*	janus_fec_enc_create();
void		janus_fec_enc_destory(janus_fec_enc* fec);

//-1 fail, 0 success
int		janus_fec_input_media_packet(janus_fec_enc* fec, unsigned char* packet, int length);

//-1 fail, >=0 the size of media  packet list
int 		janus_fec_get_good_media_packet_list(janus_fec_enc* fec, GList**  media_packet_list);

//-1 fail, 0 success
int		janus_fec_generate_fec(janus_fec_enc* fec, GList* media_packet_list, guint fec_rate, GList** fec_packet_list );

/////////// RED function
//-1 fail, >0 the size of red packet
int	janus_red_encode_media_packet(guint8* buffer, guint payload_length, guint rtp_header_length, guint red_pl_type);

//-1 fail, 0 success
int  janus_red_encode_fec_packet_list(GList* media_packet_list, GList* fec_packet_list, guint rtp_header_length, guint  red_pl_type, guint  fec_pl_type);

/*								FEC 		DECODER															*/
/*	sample code		
janus_fec_input_red_packet(fec, data, len, 117);
packet* p = (packet*)malloc(sizeof(packet));
memset(p, 0, sizeof(packet));
if (0 == janus_fec_recover_media_packet(fec, p)) {
	//it is a media packet, push to next process
 }
 if (1 == janus_fec_recover_media_packet()) {
	//success of recovering one media  packet
}
*/
janus_fec_dec*	janus_fec_dec_create();
void		janus_fec_dec_destory(janus_fec_dec* fec);

//-1 fail, 0 media  packet, 1 fec packet
int 		janus_fec_input_red_packet(janus_fec_dec* fec, /*inout*/unsigned char* packet, /*inout*/int* length, guint32 fec_pl_type);

//-1 fail, 0 sucess but not ready, 1 sucess and ready
int		janus_fec_recover_media_packet(janus_fec_dec* fec, /*out*/packet*  pkt);
#endif		//FEC_LITE
