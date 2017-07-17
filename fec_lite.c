
#include "debug.h"
#include "fec_lite.h"
#include "fec_private_tables_random.h"

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

guint parse_sequence_number(guint8* packet) {
	return (packet[2]<<8) + packet[3];
}

gint is_sequence_number_bigger(gconstpointer a, gconstpointer b) {
	packet* pkt1 = (packet*)a;
	packet* pkt2 = (packet*)b;
	return parse_sequence_number(pkt1->data) - parse_sequence_number(pkt2->data);
}

janus_fec_lite*	janus_fec_create()
{
	janus_fec_lite* fec = (janus_fec_lite*)malloc(sizeof(janus_fec_lite));
	if (fec) {
		memset(fec, 0, sizeof(janus_fec_lite));
	}
	return fec;
}

void		janus_fec_destory(janus_fec_lite* fec)
{
	if (fec) {
		free(fec);
	}
}

void 	generate_fec_bit_strings(janus_fec_lite* fec, GList* media_packet_list, guint8* packet_mask, guint num_fec_packets, gboolean l_bit) {
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

void 	generate_fec_ulp_headers(janus_fec_lite* fec, GList* media_packet_list, guint8* packet_mask, guint num_fec_packets, gboolean l_bit) {
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

int		janus_fec_generate_fec(janus_fec_lite* fec, GList* media_packet_list, guint fec_rate, GList** fec_packet_list )
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

int		janus_fec_input_media_packet(janus_fec_lite* fec, unsigned char* buffer, int length)
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
	fec->media_packet_reorder_bucket = g_list_insert_sorted(fec->media_packet_reorder_bucket, pkt, &is_sequence_number_bigger);
	
	/*
	//pop the head element when the list is full, and free it
	if (g_list_length(fec->media_packet_reorder_bucket) == mSizeReorderBucket) {
		JANUS_LOG(LOG_WARN, "[fec enc]media packet list overflow, will remove one\n");
		GList* head = fec->media_packet_reorder_bucket;
		fec->media_packet_reorder_bucket = g_list_remove_link(fec->media_packet_reorder_bucket, head);	//remove the node from list
		free((packet*)head->data);		//free the node's user data
		g_list_free(head);	//free the node itself
	}
	*/
	return 0;
}

int 		janus_fec_get_good_media_packet_list(janus_fec_lite* fec, GList**  media_packet_list)
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
	
	
	
	/*
	//check if the 1st sub list is continous. if yes, pop them
	int sublist_count = 1;
	GList* ite = fec->media_packet_reorder_bucket;
	if (!ite)
		return 0;
	while(sublist_count < mSizeFecGroup) {
		if (ite->next) {
			unsigned  char* buf1 = ((packet*)ite->data)->data;
			unsigned  char* buf2 = ((packet*)ite->next->data)->data;
			if (parse_sequence_number(buf1) + 1 != parse_sequence_number(buf2))
				break;
			sublist_count++;
			ite = ite->next;
		}
		else {
			break;
		}
	}
	
	if (sublist_count == mSizeFecGroup) {
		//found the good sub list
		JANUS_LOG(LOG_INFO, "[fec enc]get good media packet list, 1st seq:%d \n", parse_sequence_number(((packet*)fec->media_packet_reorder_bucket->data)->data));
		for(sublist_count=0; sublist_count<mSizeFecGroup;sublist_count++) {
			ite = fec->media_packet_reorder_bucket;
			fec->media_packet_reorder_bucket = g_list_remove_link(fec->media_packet_reorder_bucket, ite);	//remove the node from list
			*media_packet_list = g_list_append(*media_packet_list, ite->data);	//append the node's user data to another list
			//JANUS_LOG(LOG_INFO, "[fec enc]get good media packet list, media_packet_list:0x%x\n", media_packet_list);
			g_list_free(ite);	//free the node itself
		}
	}
	else {
		//JANUS_LOG(LOG_INFO, "[fec enc]good media packet list NOT ready, %d\n", sublist_count);
		return 0;
	}
	*/
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

