
#include "debug.h"
#include "fec_lite.h"
#include "fec_private_tables_random.h"
#include "rtp.h"

#define kMaskSizeLBitClear 2
#define kMaskSizeLBitSet 6
#define kUlpHeaderSizeLBitSet	 (2 + kMaskSizeLBitSet)
#define kUlpHeaderSizeLBitClear	 (2 + kMaskSizeLBitClear)
#define kRtpHeaderSize  12
#define kFecHeaderSize  10
#define kRtpMarkerBitMask (0x80)

#define mSizeFecGroup 5

void		updateFecMap(fec_sequence_map* smap, guint16 last_pkt_seq, guint8 fec_num)
{
	if (smap) {
		guint8	cur_index = smap->cur_index;
		cur_index += fec_num;
		smap->loop_count += cur_index/kFecSequenceMapSize;
		if (cur_index >= kFecSequenceMapSize) {
			//loop  over
			guint8 left = kFecSequenceMapSize-smap->cur_index-1;
			memset(&smap->map[smap->cur_index+1], 0, left);
			memset(&smap->map[0], 0, fec_num-left);
		}
		else {
			memset(&smap->map[smap->cur_index+1], 0, fec_num);
		}
		smap->cur_index = cur_index%kFecSequenceMapSize;
		smap->map[smap->cur_index] = last_pkt_seq;
	}
}

guint32	getSequencePlusFromFecMap(fec_sequence_map* smap, guint16 pkt_seq) {
	if (smap) {
		guint32 total_index = smap->loop_count*kFecSequenceMapSize + smap->cur_index;
		if (pkt_seq >= smap->map[smap->cur_index]) {
			//todo: consider loop
			return total_index;
		}
		else {
			guint32 i = total_index;
			while(i > 0) {
				if (smap->loop_count > 0 && i <= total_index-kFecSequenceMapSize) {
					//one loop search over
					JANUS_LOG(LOG_WARN, "cannot find corresponding record in fec map, packet seq:%d\n", pkt_seq);
					break;
				}
				guint16 seq = smap->map[i%kFecSequenceMapSize];
				if (seq && seq < pkt_seq) {
					//find it!
					JANUS_LOG(LOG_INFO, "find corresponding record in fec map, seq:%d, plus:%d\n", pkt_seq, i);
					return i;
				}
				i--;
			}
		}
	}
	return 0;
}

guint		get_num_of_fec_packets(guint num_media_packets, guint fec_rate) {
	int num_fec_packets = (num_media_packets*fec_rate + (1<<7)) >> 8;
	if (fec_rate > 0 && num_fec_packets == 0)
		num_fec_packets = 1;	//at least
	return num_fec_packets;
}

void 	generate_packet_masks(guint num_media_packets, guint num_fec_packets, guint8* packet_mask, guint num_mask_bytes) {
	//do not support ULP FEC
	memcpy(packet_mask, kPacketMaskRandomTbl[num_media_packets-1][num_fec_packets-1], num_fec_packets*num_mask_bytes);
}

guint16 parse_sequence_number(guint8* packet) {
	return (packet[2]<<8) + packet[3];
}

gint	seq_diff(guint16 seq1, guint16 seq2) {
	if (abs(seq1-seq2) < 0x7fff) {
		return seq1-seq2;
	} else {
		return (seq1<seq2) ? (seq1+0xffff-seq2) : (seq1-0xffff-seq2);
	}
}

gint 	is_sequence_number_bigger_packet(gconstpointer a, gconstpointer b) {
	packet* pkt1 = (packet*)a;
	packet* pkt2 = (packet*)b;
	return seq_diff(parse_sequence_number(pkt1->data), parse_sequence_number(pkt2->data));
}

gint 	is_sequence_number_bigger_fec_packet(gconstpointer a, gconstpointer b) {
	fec_packet* pkt1 = (fec_packet*)a;
	fec_packet* pkt2 = (fec_packet*)b;
	return seq_diff(pkt1->rpkt->seq, pkt2->rpkt->seq);
}

gint		is_sequence_number_bigger_recovered_packet(gconstpointer a, gconstpointer b) {
	recovered_packet* pkt1 = (recovered_packet*)a;
	recovered_packet* pkt2 = (recovered_packet*)b;
	return seq_diff(pkt1->rpkt->seq, pkt2->rpkt->seq);
}

janus_fec_enc*	janus_fec_enc_create()
{
	janus_fec_enc* fec = (janus_fec_enc*)malloc(sizeof(janus_fec_enc));
	if (fec) {
		memset(fec, 0, sizeof(janus_fec_enc));
	}
	return fec;
}

void		janus_fec_enc_destory(janus_fec_enc* fec)
{
	if (fec) {
		free(fec);
	}
}

void 	generate_fec_bit_strings(janus_fec_enc* fec, GList* media_packet_list, guint8* packet_mask, guint num_fec_packets, gboolean l_bit) {
	guint16 media_payload_length = 0;		//including CSRC list, rtp extension, rtp padding and rtp  payload
	gint num_mask_bytes = l_bit ? kMaskSizeLBitSet : kMaskSizeLBitClear;
	gint ulp_header_size = l_bit ? kUlpHeaderSizeLBitSet : kUlpHeaderSizeLBitClear;
	gint fec_rtp_offset = kFecHeaderSize + ulp_header_size - kRtpHeaderSize;
	
	for(int i=0; i<num_fec_packets; i++) {
		//JANUS_LOG(LOG_INFO, "generate_fec_bit_strings, for one fec packet \n");
		packet* fec_pkt = &fec->fec_packets[i];
		GList* ite = media_packet_list;
		guint pkt_mask_idx = i*num_mask_bytes;
		guint media_pkt_idx = 0;
		guint fec_pkt_length = 0;
		guint prev_seq_num = parse_sequence_number(((packet*)ite->data)->data);
		while(ite) {
			if (packet_mask[pkt_mask_idx] & (1<<(7-media_pkt_idx))) {
				packet* media_pkt = (packet*)ite->data;
				media_payload_length = media_pkt->length - kRtpHeaderSize;
				fec_pkt_length = media_pkt->length + fec_rtp_offset;
				if (fec_pkt->length == 0) {
					//JANUS_LOG(LOG_INFO, "generate_fec_bit_strings, mask map 1st media packet\n");
					memcpy(fec_pkt->data, media_pkt->data, 2);
					//leave room for "SN base"
					memcpy(&fec_pkt->data[4], &media_pkt->data[4], 4);
					guint16 mpl_n = htons(media_payload_length);
					memcpy(&fec_pkt->data[8], &mpl_n, 2);
					//JANUS_LOG(LOG_INFO, "generate_fec_bit_strings 1, media_payload_length:0x%x, 8:0x%x, 9:0x%x\n", media_payload_length, fec_pkt->data[8], fec_pkt->data[9]);
					//leave room for ulp header
					memcpy(&fec_pkt->data[kFecHeaderSize+ulp_header_size], &media_pkt->data[kRtpHeaderSize], media_pkt->length-kRtpHeaderSize);
				}
				else {
					//JANUS_LOG(LOG_INFO, "generate_fec_bit_strings, mask map other media packet\n");
					fec_pkt->data[0] ^= media_pkt->data[0];
					fec_pkt->data[1] ^= media_pkt->data[1];
					//leave room for "SN base"
					fec_pkt->data[4] ^= media_pkt->data[4];
					fec_pkt->data[5] ^= media_pkt->data[5];
					fec_pkt->data[6] ^= media_pkt->data[6];
					fec_pkt->data[7] ^= media_pkt->data[7];
					fec_pkt->data[8] ^= (media_payload_length >> 8);
					fec_pkt->data[9] ^= (media_payload_length&0xFF);
					//JANUS_LOG(LOG_INFO, "generate_fec_bit_strings 2, media_payload_length:0x%x, 8:0x%x, 9:0x%x\n", media_payload_length, fec_pkt->data[8], fec_pkt->data[9]);
					//leave room for ulp header
					for(int j=kFecHeaderSize+ulp_header_size; j<fec_pkt_length; j++) {
						fec_pkt->data[j] ^= media_pkt->data[j-fec_rtp_offset];
					}
				}
				//JANUS_LOG(LOG_INFO, "generate_fec_bit_strings, fec pkt length:%d, media pkt length:%d\n", fec_pkt_length, media_pkt->length - kRtpHeaderSize);
				//store the max length
				if (fec_pkt_length > fec_pkt->length) {
					fec_pkt->length = fec_pkt_length;
				}
			}
			ite = ite->next;
			if (ite) {
				guint seq_num = parse_sequence_number(((packet*)ite->data)->data);
				media_pkt_idx += seq_num - prev_seq_num;
				prev_seq_num = seq_num;
			}
			pkt_mask_idx += media_pkt_idx/8;
			media_pkt_idx %= 8;
		}
		//guint16 len_rec = ((fec_pkt->data[8]<<8)|fec_pkt->data[9]);
		//JANUS_LOG(LOG_INFO, "generate_fec_bit_strings over, length_recovery:%d, 8:0x%x, 9:0x%x\n", len_rec, fec_pkt->data[8], fec_pkt->data[9]); 
	}
}

void 	generate_fec_ulp_headers(janus_fec_enc* fec, GList* media_packet_list, guint8* packet_mask, guint num_fec_packets, gboolean l_bit) {
	if (!fec || !media_packet_list || !packet_mask) {
		return -1;
	}
	gint num_mask_bytes = l_bit ? kMaskSizeLBitSet : kMaskSizeLBitClear;
	gint ulp_header_size = l_bit ? kUlpHeaderSizeLBitSet : kUlpHeaderSizeLBitClear;
	packet*  media_pkt = (packet*)media_packet_list->data;		//1st media RTP packet
	for(int i=0; i<num_fec_packets; i++) {
		packet* fec_pkt = &fec->fec_packets[i];
		
		// -------FEC header--------
		fec_pkt->data[0] &= 0x7f;		//set E to zero
		if (l_bit == 0) {
			fec_pkt->data[0] &= 0xbf;		//clear the L bit
		} else {
			fec_pkt->data[0] |= 0x40;		//set the L bit
		}
		//webrtc use the same sequence number for every FEC packets, that is the sequence  number of the 1st media RTP packet
		memcpy(&fec_pkt->data[2], &media_pkt->data[2], 2);
		
		// ------ULP header-------
		//the "protection length" can only be calculated after all FEC operations done
		guint16 protection_len = htons(fec_pkt->length - kFecHeaderSize - ulp_header_size);
		memcpy(&fec_pkt->data[10], &protection_len, 2);
		//copy the mask
		memcpy(&fec_pkt->data[12], &packet_mask[i*num_mask_bytes], num_mask_bytes);
	}
}

int		janus_fec_generate_fec(janus_fec_enc* fec, GList* media_packet_list, guint fec_rate, GList** fec_packet_list )
{
	if (!fec || !media_packet_list) {
		return -1;
	}
	if (!fec_packet_list || *fec_packet_list) {
		return -1;
	}
	
	//todo: necessary data length check of media packets
	
	//assume media packet list is contured and in order
	guint num_media_packets = g_list_length(media_packet_list);
	if (num_media_packets > kMaxFecPackets) {
		JANUS_LOG(LOG_WARN, "[fec enc]media packets too long \n");
		return -1;
	}
	gboolean l_bit = (num_media_packets > 8*kMaskSizeLBitClear);
	guint num_mask_bytes = l_bit ? kMaskSizeLBitSet : kMaskSizeLBitClear;
	
	//JANUS_LOG(LOG_INFO, "[fec enc]will calculate FEC number, rate:%d \n", fec_rate);
	guint num_fec_packets = get_num_of_fec_packets(num_media_packets, fec_rate);
	if (num_fec_packets == 0)
		return 0;		//no need to protect
	
	for(int i=0;i<num_fec_packets;i++) {
		memset(fec->fec_packets[i].data, 0, sizeof(char)*kIPPacketSize);
		fec->fec_packets[i].length = 0;
		*fec_packet_list = g_list_append(*fec_packet_list, &fec->fec_packets[i]);
	}
	guint8* packet_mask = (guint8*)malloc(num_fec_packets*num_mask_bytes);
	generate_packet_masks(num_media_packets, num_fec_packets, packet_mask, num_mask_bytes);
	//JANUS_LOG(LOG_INFO, "[fec enc]generate FEC packet masks, %d, %d \n", num_fec_packets, num_media_packets);
	
	//XOR for every FEC packet payload
	generate_fec_bit_strings(fec, media_packet_list, packet_mask, num_fec_packets, l_bit);
	//write FEC packet header
	generate_fec_ulp_headers(fec, media_packet_list, packet_mask, num_fec_packets, l_bit);
	
	//zzy, debug
	//JANUS_LOG(LOG_INFO, "[fec enc]generate FEC packets done,  len:%d\n", fec->fec_packets[0].length);
	return 0;
}

int		janus_fec_input_media_packet(janus_fec_enc* fec, unsigned char* buffer, int length)
{
	if (!fec || !buffer || !length || length > kIPPacketSize)
		return -1;
	
	//todo: alloc pkt from pool
	packet* pkt = (packet*)malloc(sizeof(packet));
	if (!pkt)
		return -1;
	memcpy(pkt->data, buffer, length);
	pkt->length = length;

	//JANUS_LOG(LOG_INFO, "[fec enc]input one media packet, seq:%d(%d,%d) \n", parse_sequence_number(buffer), buffer[2], buffer[3]);
	//insert the packet to where it belongs
	fec->media_packet_reorder_bucket = g_list_insert_sorted(fec->media_packet_reorder_bucket, pkt, &is_sequence_number_bigger_packet);
	return 0;
}

int 		janus_fec_get_good_media_packet_list(janus_fec_enc* fec, GList**  media_packet_list)
{
	if (!fec|| *media_packet_list) {
		return -1;
	}
	
	int candidate_cnt = 0;
	GList* ite = g_list_last(fec->media_packet_reorder_bucket);
	if (ite) {
		guint16 bef_seq = 0xffff;
		gboolean marker_bit = (((packet*)ite->data)->data[1]&kRtpMarkerBitMask) ? TRUE : FALSE;
		if (marker_bit) {
			//the last element is marker bit set
			while(ite) {
				guint8* pkt = (guint8*)((packet*)ite->data)->data;
				guint16* seq_p = (guint16*)(&pkt[2]);
				guint16 cur_seq = ntohs(*seq_p);
				if (bef_seq == 0xffff || bef_seq == cur_seq+1) {
					candidate_cnt++;
				}
				else {
					break;
				}
				bef_seq = cur_seq;
				ite = ite->prev;
			}
		}
		
		if (candidate_cnt >= mSizeFecGroup) {
			//JANUS_LOG(LOG_INFO, "good media packet list is found, %d\n", candidate_cnt);
			 ite = g_list_last(fec->media_packet_reorder_bucket);		//begin from the last
			 int i = 0;
			 while (ite) {
				 if (i++ < candidate_cnt) {
					*media_packet_list = g_list_prepend(*media_packet_list, ite->data);
				 }
				 else {
					free((packet*)ite->data);		//free "malloc" data
				 }
				 ite = ite->prev;
			 }
			 g_list_free(fec->media_packet_reorder_bucket);
			 fec->media_packet_reorder_bucket = NULL;
		}
		else {
			candidate_cnt = 0;
		}
	}
	return candidate_cnt;
}


int  janus_red_encode_fec_packet_list(GList* media_packet_list, GList* fec_packet_list, guint rtp_header_length, guint  red_pl_type, guint  fec_pl_type)
{
	if (!media_packet_list || !fec_packet_list) {
		return -1;
	}
	
	GList* last_media_packet = g_list_last(media_packet_list);
	guint16 sequence_number = parse_sequence_number(((packet*)last_media_packet->data)->data);
	GList*  ite = fec_packet_list;
	while (ite) {
		unsigned char*  data = ((packet*)ite->data)->data;
		int len = ((packet*)ite->data)->length;
		if (len + kRedPrimaryHeaderSize+rtp_header_length > kIPPacketSize) {
			JANUS_LOG(LOG_ERR, "FEC packet length is TOO large\n");
			return -1;
		}
		memmove(data+kRedPrimaryHeaderSize+rtp_header_length, data, len);				//data shift backward
		memcpy(data, ((packet*)last_media_packet->data)->data, rtp_header_length);	//copy media packet header to me
		//set rtp payload to RED
		data[1] = 0;  //clear marker bit BTW
		data[1] += red_pl_type;	
		//set FEC payload of RED header
		data[rtp_header_length] = fec_pl_type;
		//set sequence number
		guint16 seq_n = htons(++sequence_number);
		memcpy(&data[2], &seq_n, 2);
		((packet*)ite->data)->length += (kRedPrimaryHeaderSize+rtp_header_length);
		//JANUS_LOG(LOG_INFO, "build one RED packet(FEC), seq:%d, fec_pl:%d, len:%d \n", sequence_number, fec_pl_type, ((packet*)ite->data)->length);
		ite = ite->next;
	}
	
	return 0;
}

int	janus_red_encode_media_packet(guint8* buffer, guint payload_length, guint rtp_header_length, guint red_pl_type)
{
	if (!buffer || !payload_length || !rtp_header_length) {
		return -1;
	}
	
	memmove(buffer+rtp_header_length+kRedPrimaryHeaderSize, buffer+rtp_header_length, payload_length);
	//set RED header
	memcpy(&buffer[rtp_header_length], &buffer[1], 1);
	buffer[rtp_header_length] &= 0x7F;		//f-bit always 0
	//set rtp payload
	buffer[1] &= 0x80;
	buffer[1] += red_pl_type;
	//JANUS_LOG(LOG_INFO, "build one RED packet(media), seq:%d, red_pl:%d \n", parse_sequence_number(buffer), red_pl_type);
	return rtp_header_length+kRedPrimaryHeaderSize+payload_length;
}

janus_fec_dec*	janus_fec_dec_create() {
	janus_fec_dec* p = (janus_fec_dec*)malloc(sizeof(janus_fec_dec));
	memset(p, 0, sizeof(janus_fec_dec));
	return p;
}

void		janus_fec_dec_destory(janus_fec_dec* fec)
{
	if (fec) {
		//release fec packet list
		GList* fec_ite = fec->fec_packet_list;
		while(fec_ite) {
			fec_packet* fpkt = (fec_packet*)fec_ite->data;
			free_fec_packet(fpkt);
			fec_ite = fec_ite->next;
		}
		g_list_free(fec->fec_packet_list);
		fec->fec_packet_list = NULL;
		
		//release media packet list
		while(fec->recovered_packet_list) {
			GList* head = fec->recovered_packet_list;
			fec->recovered_packet_list = g_list_remove_link(fec->recovered_packet_list, head);
			recovered_packet* repkt = (recovered_packet*)head->data;
			free(repkt->rpkt);		//I am the owner of received_packet
			free(repkt);
			g_list_free(head);
		}
	}
}

void free_fec_packet(fec_packet* fec_pkt) {
	if (fec_pkt) {
		GList*  ite = fec_pkt->protected_packet_list;
		while(ite) {
			protected_packet*  ppkt = (protected_packet*)ite->data;
			//we don't need to free "pkt" of "protected_packet", cause  I am not the owner
			if (ppkt)
				free(ppkt);
			ite = ite->next;
		}
		g_list_free(fec_pkt->protected_packet_list);
		free(fec_pkt->rpkt);		//I am the owner of received_packet
		free(fec_pkt);
	}
}

int		insert_fec_packet(janus_fec_dec* fec, received_packet* received_pkt) {
	//check seq diff between head and toe, and remove fec packet if need
	GList* head = fec->fec_packet_list;
	if (head) {
		fec_packet*  fpkt = (fec_packet*)head->data;
		if ((fpkt->rpkt->seq)^(received_pkt->seq) > 0x3fff) {
			JANUS_LOG(LOG_WARN,  "fec packet list is too big at sequence number level\n");
			fec->fec_packet_list = g_list_remove_link(fec->fec_packet_list, head);
			free_fec_packet((fec_packet*)head->data);
			g_list_free(head);
		}
	}
	
	//todo: check for seq duplicate
	
	//generate protected_packet_list, according to mask in ulp header
	fec_packet* fec_pkt = (fec_packet*)malloc(sizeof(fec_packet));
	if (!fec_pkt)
		return -1;
	fec_pkt->rpkt = received_pkt;					//owner transfer
	fec_pkt->protected_packet_list = NULL;
	guint16 seq_base = ntohs(*((guint16*)&(received_pkt->pkt.data[2])));
	guint16 maskSizeBytes = (received_pkt->pkt.data[0]&0x40) ? kMaskSizeLBitSet : kMaskSizeLBitClear;
	for (int i=0;i<maskSizeBytes;i++) {
		guint8 packet_mask = received_pkt->pkt.data[12+i];
		for (int j=0;j<8;j++) {
			if (packet_mask&(1<<(7-j))) {
				protected_packet* ppkt = (protected_packet*)malloc(sizeof(protected_packet));
				ppkt->pkt = NULL;
				ppkt->target_seq = seq_base+(i<<3)+j;
				fec_pkt->protected_packet_list = g_list_append(fec_pkt->protected_packet_list, ppkt);
			}
		}
	}
	
	if (g_list_length(fec_pkt->protected_packet_list) == 0) {
		//all-zero packet mask, we can discard this FEC packet
		free(fec_pkt);
		fec_pkt = NULL;
		JANUS_LOG(LOG_WARN, "[fec dec] insert fec packet, with all-zero mask\n");
	} else {
		//assign recovered packets
		GList* protect_ite = fec_pkt->protected_packet_list;
		while(protect_ite) {
			protected_packet* pro_pkt = (protected_packet*)protect_ite->data;
			GList*  recovered_ite = fec->recovered_packet_list;
			while(recovered_ite) {
				recovered_packet* repkt = (recovered_packet*)recovered_ite->data;
				if (pro_pkt->target_seq == repkt->rpkt->seq)
				{
					pro_pkt->pkt = &repkt->rpkt->pkt;		//share
					break;
				}
				recovered_ite = recovered_ite->next;
			}
			protect_ite = protect_ite->next;
		}
		fec->fec_packet_list = g_list_insert_sorted(fec->fec_packet_list, fec_pkt, is_sequence_number_bigger_fec_packet);
		if (g_list_length(fec->fec_packet_list) > kMaxFecPackets) {
			//fec packet list is too large, discard one packet
			head = fec->fec_packet_list;
			fec->fec_packet_list = g_list_remove_link(fec->fec_packet_list, head);
			JANUS_LOG(LOG_WARN,  "fec packet list is too big at size level, remove its head, seq:%d\n",  ((fec_packet*)head->data)->rpkt->seq);
			free_fec_packet((fec_packet*)head->data);
			g_list_free(head);
		}
		JANUS_HUGE(LOG_INFO, "[fec dec] insert fec packet, seq:%d\n", received_pkt->seq);
	}
	return 0;
}

void		update_covering_packets(janus_fec_dec* fec, recovered_packet* repkt) {
	GList* fec_ite = fec->fec_packet_list;
	while(fec_ite) {
		fec_packet*  fec_pkt = (fec_packet*)fec_ite->data;
		GList* pro_ite = fec_pkt->protected_packet_list;
		while(pro_ite) {
			protected_packet* pro_pkt = (protected_packet*)pro_ite->data;
			if (pro_pkt->target_seq == repkt->rpkt->seq) {
				JANUS_LOG(LOG_INFO, "update covering packet, seq:%d\n", repkt->rpkt->seq);
				pro_pkt->pkt = &repkt->rpkt->pkt;		//share
				break;		//no need to loop again
			}
			pro_ite = pro_ite->next;
		}
		fec_ite = fec_ite->next;
	}
}

int 		insert_media_packet(janus_fec_dec* fec, received_packet*  rpkt) {
	//search for duplicate packet
	GList* ite = fec->recovered_packet_list;
	while(ite) {
		recovered_packet* repkt = (recovered_packet*)ite->data;
		if(repkt->rpkt->seq == rpkt->seq) {
			JANUS_LOG(LOG_INFO, "[fec dec] insert media packet, same packet, seq:%d\n", rpkt->seq);
			free(rpkt);
			return 0;
		}
		ite = ite->next;
	}
	
	//transfer to recovered_packet, and to list
	recovered_packet* repkt = (recovered_packet*)malloc(sizeof(recovered_packet));
	memset(repkt, 0, sizeof(recovered_packet));
	repkt->rpkt = rpkt;			//transfer ownership
	repkt->was_recovered = FALSE;
	repkt->returned = TRUE;
	fec->recovered_packet_list = g_list_insert_sorted(fec->recovered_packet_list, repkt, is_sequence_number_bigger_recovered_packet);
	
	//update covering packets
	update_covering_packets(fec, repkt);
	//JANUS_LOG(LOG_INFO, "[fec dec] insert media packet, seq:%d\n", rpkt->seq);
	return 0;
}

//discard old recovered packets
void		discard_old_packets(janus_fec_dec* fec) {
	while(g_list_length(fec->recovered_packet_list) > kMaxMediaPackets) {
		GList* head = fec->recovered_packet_list;
		fec->recovered_packet_list = g_list_remove_link(fec->recovered_packet_list, head);
		recovered_packet* repkt = (recovered_packet*)head->data;
		//JANUS_LOG(LOG_INFO, "[fec dec]discard one old media pacekt, seq:%d\n", repkt->rpkt->seq);
		
		//find the involved fec packet
		GList* fec_ite = fec->fec_packet_list;
		while(fec_ite) {
			fec_packet*  fpkt = (fec_packet*)fec_ite->data;
			GList* pro_ite = fpkt->protected_packet_list;
			while(pro_ite) {
				protected_packet* ppkt = (protected_packet*)pro_ite->data;
				if (ppkt->target_seq == repkt->rpkt->seq) {
					JANUS_LOG(LOG_WARN, "this media packet has been involved in existing fec packet(0x%x, 0x%x), seq:%d\n", ppkt->pkt, &repkt->rpkt->pkt, fpkt->rpkt->seq);
					ppkt->pkt = NULL;		//reset the packet
					break;
				}
				pro_ite = pro_ite->next;
			}
			fec_ite = fec_ite->next;
		}
		
		free(repkt->rpkt);		//I am the owner of received_packet
		free(repkt);
		g_list_free(head);
	}
}

int 		janus_fec_input_red_packet(janus_fec_dec* fec, unsigned char* packet, int *length, guint32 fec_pl_type)
{
	int ret = 0;
	if (!fec || !packet || !length)
		return -1;
	//JANUS_LOG(LOG_INFO, "[fec dec] input red packet\n");
	rtp_header* header = (rtp_header*)packet;
	gint32 rtp_header_len = janus_rtp_header_length(header);
	guint8 pl_type = packet[rtp_header_len] & 0x7f;
	gboolean is_fec = pl_type == fec_pl_type;
	//1. store packet, and remove RED header for fec packet / media packet
	received_packet* rpkt = (received_packet*)malloc(sizeof(received_packet));
	if (!rpkt)
		return -1;
	memset(rpkt, 0, sizeof(received_packet));
	//rpkt->is_fec = is_fec;
	rpkt->ssrc = ntohl(header->ssrc);
	rpkt->seq = ntohs(header->seq_number);
	if (is_fec) {
		//everything behind the RED header
		rpkt->pkt.length = *length-rtp_header_len-kRedPrimaryHeaderSize;
		memcpy(rpkt->pkt.data, packet+rtp_header_len+kRedPrimaryHeaderSize, rpkt->pkt.length);
	} else {
		memcpy(rpkt->pkt.data, packet, rtp_header_len);
		rpkt->pkt.data[1] &= 0x80;
		rpkt->pkt.data[1] += pl_type;
		//skip the RED header
		memcpy(rpkt->pkt.data+rtp_header_len, packet+rtp_header_len+kRedPrimaryHeaderSize, *length-rtp_header_len-kRedPrimaryHeaderSize);
		rpkt->pkt.length =*length-kRedPrimaryHeaderSize;
		
		//for output
		memcpy(packet, rpkt->pkt.data, rpkt->pkt.length);
		*length = rpkt->pkt.length;
	}
	//return 0;		//debug, disable fec recovery
	
	//2. todo: if recovered_packet_list is too large, drop some packets
	
	if (is_fec) {
		//3. put fec packet into fec list
		insert_fec_packet(fec, rpkt);
		ret = 1;
	} else {
		//4. put media  packet into fec's protection list and recover list
		insert_media_packet(fec, rpkt);
		ret = 0;
	}
	
	//5. clean old recovered packets
	discard_old_packets(fec);
	
	//JANUS_LOG(LOG_INFO, "[fec dec] input red packet done\n");
	return ret;
}

int 		num_covered_packet_missing(fec_packet* fpkt) {
	GList* pro_ite = fpkt->protected_packet_list;
	int packets_missing = 0;
	while(pro_ite) {
		protected_packet*  ppkt = (protected_packet*)pro_ite->data;
		if (ppkt->pkt == NULL) {
			if (++packets_missing > 1) {
				//we can't recover  more than one packet
				break;
			}
		}
		pro_ite = pro_ite->next;
	}
	return packets_missing;
}

int		XorPacket(packet*  src_pkt, recovered_packet* repkt) {
	//JANUS_LOG(LOG_INFO, "XorPacket ++\n");
	guint8* recover_data = repkt->rpkt->pkt.data;
	//xor with the 1st two bytes of rtp header
	recover_data[0] ^= src_pkt->data[0];
	recover_data[1] ^= src_pkt->data[1];
	//xor with the timestamp 4 bytes
	recover_data[4] ^= src_pkt->data[4];
	recover_data[5] ^= src_pkt->data[5];
	recover_data[6] ^= src_pkt->data[6];
	recover_data[7] ^= src_pkt->data[7];
	//xor with length recovery
	//JANUS_LOG(LOG_INFO, "XorPacket 1\n");
	guint16 payload_length = src_pkt->length-kRtpHeaderSize;	//including CSRC, rtp extension, rtp  padding, rtp payload
	repkt->length_recovery[0] ^= (payload_length >> 8);
	repkt->length_recovery[1] ^= (payload_length&0xff);
	//xor with payload
	//JANUS_LOG(LOG_INFO, "XorPacket 2\n");
	for (guint i=kRtpHeaderSize; i<src_pkt->length; i++) {
		recover_data[i] ^= src_pkt->data[i];
	}
	//JANUS_LOG(LOG_INFO, "XorPacket --\n");
}

int		recover_packet(fec_packet*  fpkt, /*inout*/recovered_packet* repkt) {
	//step1: init recovery
	guint8* fec_data = fpkt->rpkt->pkt.data;
	guint16 ulp_header_size = (fec_data[0]&0x40) ? kUlpHeaderSizeLBitSet : kUlpHeaderSizeLBitClear;
	if (fpkt->rpkt->pkt.length < kFecHeaderSize+ulp_header_size)
		return -1;
	//create received packet from the  air
	received_packet* rpkt = (received_packet*)malloc(sizeof(received_packet));
	if (!rpkt)
		return -1;
	memset(rpkt, 0, sizeof(received_packet));
	repkt->rpkt = rpkt;
	guint16 protection_length = ntohs(*((guint16*)&(fec_data[kFecHeaderSize])));
	//check the validation of protection length, is it  too big?
	if (protection_length > sizeof(rpkt->pkt.data)-kRtpHeaderSize ||
			protection_length > fpkt->rpkt->pkt.length-kFecHeaderSize-ulp_header_size) {
		JANUS_LOG(LOG_ERR, "recover_packet, protection length too large:%d\n", protection_length);
		return -1;
	}
	//rpkt->pkt.length = protection_length + kRtpHeaderSize;		//fake length, just the value  of fec packet length
	//copy fec level 0 payload, skiping level 0 header
	memcpy(&rpkt->pkt.data[kRtpHeaderSize], &fec_data[kFecHeaderSize+ulp_header_size], protection_length);
	//copy length recovery  field
	memcpy(repkt->length_recovery, &fec_data[8], 2);
	//copy the 1st two bytes of fec packet
	memcpy(rpkt->pkt.data, fec_data, 2);
	//copy 5-8 bytes of fec packet
	memcpy(&rpkt->pkt.data[4], &fec_data[4], 4);
	//set ssrc field
	rpkt->ssrc = fpkt->rpkt->ssrc;
	*((guint32*)&rpkt->pkt.data[8]) = htonl(rpkt->ssrc);
	
	//step2: do XOR
	//JANUS_LOG(LOG_INFO, "[fec dec]recover packet, do XOR \n");
	GList* pro_ite = fpkt->protected_packet_list;
	while(pro_ite) {
		protected_packet* ppkt = (protected_packet*)pro_ite->data;
		if (ppkt->pkt == NULL) {
			//this is the packet we want to recover
			rpkt->seq = ppkt->target_seq;
		} else {
			XorPacket(ppkt->pkt, repkt);
		}
		pro_ite = pro_ite->next;
	}
	//JANUS_LOG(LOG_INFO, "[fec dec]recover packet, do XOR done\n");
	
	//step3: finish recovery
	//JANUS_LOG(LOG_INFO, "[fec dec]recover packet, finish recovery \n");
	rpkt->pkt.data[0] |= 0x80;			//set the 1st bit
	rpkt->pkt.data[0] &= 0xbf;			//clear the 2nd bit
	*((guint16*)&rpkt->pkt.data[2]) = htons(rpkt->seq);		//set the SN field
	rpkt->pkt.length = ntohs(*((guint16*)repkt->length_recovery)) + kRtpHeaderSize;
	if (rpkt->pkt.length > sizeof(rpkt->pkt.data)) {
		JANUS_LOG(LOG_ERR, "recover_packet, recovered pakcet length wrong:%d\n", rpkt->pkt.length);
		return -1;
	}
	
	return 0;
}

int		janus_fec_recover_media_packet(janus_fec_dec* fec, /*inout*/packet*  pkt)
{
	//JANUS_LOG(LOG_INFO, "[fec dec] recover media packet\n");
	if (!fec || !pkt) 
		return -1;
	
	GList* fec_ite = fec->fec_packet_list;
	while(fec_ite) {
		fec_packet* fpkt = (fec_packet*)fec_ite->data;
		int packets_missing = num_covered_packet_missing(fpkt);
		if (packets_missing == 1) {
			//possible of recovering, maybe packet disorder
			recovered_packet* repkt = (recovered_packet*)malloc(sizeof(recovered_packet));
			if (!repkt)
				return -1;
			memset(repkt, 0, sizeof(recovered_packet));
			repkt->rpkt = NULL;
			repkt->was_recovered = TRUE;
			repkt->returned = FALSE;
			//do actual XOR to recover a packet
			if (recover_packet(fpkt, repkt)<0) {
				JANUS_LOG(LOG_WARN, "fail to recover one packet, what a pity");
				//release this fec  packet
				fec->fec_packet_list = g_list_remove_link(fec->fec_packet_list, fec_ite);
				free_fec_packet(fpkt);
				g_list_free(fec_ite);
				if (repkt->rpkt) {
					free(repkt->rpkt);
					repkt->rpkt = NULL;
				}
				free(repkt);
				fec_ite = fec->fec_packet_list;
				continue;
			}
			JANUS_LOG(LOG_INFO, "recover one packet, seq:%d\n", repkt->rpkt->seq);
			//copy to output
			memcpy(pkt->data, repkt->rpkt->pkt.data, repkt->rpkt->pkt.length);
			pkt->length = repkt->rpkt->pkt.length;
			//insert recovered packet to list
			fec->recovered_packet_list = g_list_insert_sorted(fec->recovered_packet_list, repkt, is_sequence_number_bigger_recovered_packet);
			//the recovered  packet  may be involved by other fec packet, so should  update
			update_covering_packets(fec, repkt);
			//clean  old media packets
			discard_old_packets(fec);
			//release this fec  packet
			fec->fec_packet_list = g_list_remove_link(fec->fec_packet_list, fec_ite);
			free_fec_packet(fpkt);
			g_list_free(fec_ite);
			fec_ite = fec->fec_packet_list;
			return 1;
		} else if  (packets_missing == 0) {
			JANUS_LOG(LOG_HUGE, "[fec dec] fec group is complete\n");
			//the fec group is completely received
			//release this fec packet
			fec->fec_packet_list = g_list_remove_link(fec->fec_packet_list, fec_ite);
			free_fec_packet(fpkt);
			g_list_free(fec_ite);
			fec_ite = fec->fec_packet_list;
		} else {
			fec_ite = fec_ite->next;
		}
	}
	//JANUS_LOG(LOG_INFO, "[fec dec] recover media packet over\n");
	return 0;
}
