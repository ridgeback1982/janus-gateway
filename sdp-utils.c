/*! \file    sdp-utils.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    SDP utilities
 * \details  Implementation of an internal SDP representation. Allows
 * to parse SDP strings to an internal janus_sdp object, the manipulation
 * of such object by playing with its properties, and a serialization
 * to an SDP string that can be passed around. Since they don't have any
 * core dependencies, these utilities can be used by plugins as well.
 * 
 * \ingroup core
 * \ref core
 */

#include <string.h>
 
#include "sdp-utils.h"
#include "utils.h"
#include "debug.h"

#define JANUS_BUFSIZE	8192

void janus_sdp_free(janus_sdp *sdp) {
	if(!sdp)
		return;
	g_free(sdp->o_name);
	g_free(sdp->o_addr);
	g_free(sdp->s_name);
	g_free(sdp->c_addr);
	GList *temp = sdp->attributes;
	while(temp) {
		janus_sdp_attribute *a = (janus_sdp_attribute *)temp->data;
		janus_sdp_attribute_destroy(a);
		temp = temp->next;
	}
	g_list_free(sdp->attributes);
	sdp->attributes = NULL;
	temp = sdp->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		janus_sdp_mline_destroy(m);
		temp = temp->next;
	}
	g_list_free(sdp->m_lines);
	sdp->m_lines = NULL;
	g_free(sdp);
}

janus_sdp_mline *janus_sdp_mline_create(janus_sdp_mtype type, guint16 port, const char *proto, janus_sdp_mdirection direction) {
	janus_sdp_mline *m = g_malloc0(sizeof(janus_sdp_mline));
	m->type = type;
	const char *type_str = janus_sdp_mtype_str(type);
	if(type_str == NULL) {
		JANUS_LOG(LOG_WARN, "Unknown media type, type_str will have to be set manually\n");
	} else {
		m->type_str = g_strdup(type_str);
	}
	m->port = port;
	m->proto = proto ? g_strdup(proto) : NULL;
	m->direction = direction;
	return m;
}

void janus_sdp_mline_destroy(janus_sdp_mline *mline) {
	if(!mline)
		return;
	g_free(mline->type_str);
	g_free(mline->proto);
	g_free(mline->c_addr);
	g_free(mline->b_name);
	g_list_free_full(mline->fmts, (GDestroyNotify)g_free);
	mline->fmts = NULL;
	g_list_free(mline->ptypes);
	mline->ptypes = NULL;
	GList *temp = mline->attributes;
	while(temp) {
		janus_sdp_attribute *a = (janus_sdp_attribute *)temp->data;
		janus_sdp_attribute_destroy(a);
		temp = temp->next;
	}
	g_list_free(mline->attributes);
	g_free(mline);
}

janus_sdp_mline *janus_sdp_mline_find(janus_sdp *sdp, janus_sdp_mtype type) {
	if(sdp == NULL)
		return NULL;
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		if(m->type == type)
			return m;
		ml = ml->next;
	}
	return NULL;
}

janus_sdp_attribute *janus_sdp_attribute_create(const char *name, const char *value, ...) {
	if(!name)
		return NULL;
	janus_sdp_attribute *a = g_malloc0(sizeof(janus_sdp_attribute));
	a->name = g_strdup(name);
	a->direction = JANUS_SDP_DEFAULT;
	if(value) {
		char buffer[512];
		va_list ap;
		va_start(ap, value);
		g_vsnprintf(buffer, sizeof(buffer), value, ap);
		va_end(ap);
		a->value = g_strdup(buffer);
	}
	return a;
}

void janus_sdp_attribute_destroy(janus_sdp_attribute *attr) {
	if(!attr)
		return;
	g_free(attr->name);
	g_free(attr->value);
	g_free(attr);
}

int janus_sdp_attribute_add_to_mline(janus_sdp_mline *mline, janus_sdp_attribute *attr) {
	if(!mline || !attr)
		return -1;
	mline->attributes = g_list_append(mline->attributes, attr);
	return 0;
}

janus_sdp_mtype janus_sdp_parse_mtype(const char *type) {
	if(type == NULL)
		return JANUS_SDP_OTHER;
	if(!strcasecmp(type, "audio"))
		return JANUS_SDP_AUDIO;
	if(!strcasecmp(type, "video"))
		return JANUS_SDP_VIDEO;
	if(!strcasecmp(type, "application"))
		return JANUS_SDP_APPLICATION;
	return JANUS_SDP_OTHER;
}

const char *janus_sdp_mtype_str(janus_sdp_mtype type) {
	switch(type) {
		case JANUS_SDP_AUDIO:
			return "audio";
		case JANUS_SDP_VIDEO:
			return "video";
		case JANUS_SDP_APPLICATION:
			return "application";
		case JANUS_SDP_OTHER:
		default:
			break;
	}
	return NULL;
}

janus_sdp_mdirection janus_sdp_parse_mdirection(const char *direction) {
	if(direction == NULL)
		return JANUS_SDP_INVALID;
	if(!strcasecmp(direction, "sendrecv"))
		return JANUS_SDP_SENDRECV;
	if(!strcasecmp(direction, "sendonly"))
		return JANUS_SDP_SENDONLY;
	if(!strcasecmp(direction, "recvonly"))
		return JANUS_SDP_RECVONLY;
	if(!strcasecmp(direction, "inactive"))
		return JANUS_SDP_INACTIVE;
	return JANUS_SDP_INVALID;
}

const char *janus_sdp_mdirection_str(janus_sdp_mdirection direction) {
	switch(direction) {
		case JANUS_SDP_DEFAULT:
		case JANUS_SDP_SENDRECV:
			return "sendrecv";
		case JANUS_SDP_SENDONLY:
			return "sendonly";
		case JANUS_SDP_RECVONLY:
			return "recvonly";
		case JANUS_SDP_INACTIVE:
			return "inactive";
		case JANUS_SDP_INVALID:
		default:
			break;
	}
	return NULL;
}

janus_sdp *janus_sdp_parse(const char *sdp, char *error, size_t errlen) {
	if(!sdp)
		return NULL;
	if(strstr(sdp, "v=") != sdp) {
		if(error)
			g_snprintf(error, errlen, "Invalid SDP (doesn't start with v=)");
		return NULL;
	}
	janus_sdp *imported = g_malloc0(sizeof(janus_sdp));
	imported->o_ipv4 = TRUE;
	imported->c_ipv4 = TRUE;

	gboolean success = TRUE;
	janus_sdp_mline *mline = NULL;

	gchar **parts = g_strsplit(sdp, "\r\n", -1);
	if(parts) {
		int index = 0;
		char *line = NULL;
		while(success && (line = parts[index]) != NULL) {
			if(*line == '\0') {
				index++;
				continue;
			}
			if(strlen(line) < 3) {
				if(error)
					g_snprintf(error, errlen, "Invalid line (%zu bytes): %s", strlen(line), line);
				success = FALSE;
				break;
			}
			if(*(line+1) != '=') {
				if(error)
					g_snprintf(error, errlen, "Invalid line (2nd char is not '='): %s", line);
				success = FALSE;
				break;
			}
			char c = *line;
			if(mline == NULL) {
				/* Global stuff */
				switch(c) {
					case 'v': {
						if(sscanf(line, "v=%d", &imported->version) != 1) {
							if(error)
								g_snprintf(error, errlen, "Invalid v= line: %s", line);
							success = FALSE;
							break;
						}
						break;
					}
					case 'o': {
						char name[256], addrtype[6], addr[256];
						if(sscanf(line, "o=%255s %"SCNu64" %"SCNu64" IN %5s %255s",
								name, &imported->o_sessid, &imported->o_version, addrtype, addr) != 5) {
							if(error)
								g_snprintf(error, errlen, "Invalid o= line: %s", line);
							success = FALSE;
							break;
						}
						if(!strcasecmp(addrtype, "IP4"))
							imported->o_ipv4 = TRUE;
						else if(!strcasecmp(addrtype, "IP6"))
							imported->o_ipv4 = FALSE;
						else {
							if(error)
								g_snprintf(error, errlen, "Invalid o= line (unsupported protocol %s): %s", addrtype, line);
							success = FALSE;
							break;
						}
						imported->o_name = g_strdup(name);
						imported->o_addr = g_strdup(addr);
						break;
					}
					case 's': {
						imported->s_name = g_strdup(line+2);
						break;
					}
					case 't': {
						if(sscanf(line, "t=%"SCNu64" %"SCNu64, &imported->t_start, &imported->t_stop) != 2) {
							if(error)
								g_snprintf(error, errlen, "Invalid t= line: %s", line);
							success = FALSE;
							break;
						}
						break;
					}
					case 'c': {
						char addrtype[6], addr[256];
						if(sscanf(line, "c=IN %5s %255s", addrtype, addr) != 2) {
							if(error)
								g_snprintf(error, errlen, "Invalid c= line: %s", line);
							success = FALSE;
							break;
						}
						if(!strcasecmp(addrtype, "IP4"))
							imported->c_ipv4 = TRUE;
						else if(!strcasecmp(addrtype, "IP6"))
							imported->c_ipv4 = FALSE;
						else {
							if(error)
								g_snprintf(error, errlen, "Invalid c= line (unsupported protocol %s): %s", addrtype, line);
							success = FALSE;
							break;
						}
						imported->c_addr = g_strdup(addr);
						break;
					}
					case 'a': {
						janus_sdp_attribute *a = g_malloc0(sizeof(janus_sdp_attribute));
						line += 2;
						char *semicolon = strchr(line, ':');
						if(semicolon == NULL) {
							a->name = g_strdup(line);
							a->value = NULL;
						} else {
							if(*(semicolon+1) == '\0') {
								if(error)
									g_snprintf(error, errlen, "Invalid a= line: %s", line);
								success = FALSE;
								break;
							}
							*semicolon = '\0';
							a->name = g_strdup(line);
							a->value = g_strdup(semicolon+1);
							a->direction = JANUS_SDP_DEFAULT;
							*semicolon = ':';
							if(strstr(line, "/sendonly"))
								a->direction = JANUS_SDP_SENDONLY;
							else if(strstr(line, "/recvonly"))
								a->direction = JANUS_SDP_RECVONLY;
							if(strstr(line, "/inactive"))
								a->direction = JANUS_SDP_INACTIVE;
						}
						imported->attributes = g_list_append(imported->attributes, a);
						break;
					}
					case 'm': {
						janus_sdp_mline *m = g_malloc0(sizeof(janus_sdp_mline));
						/* Start with media type, port and protocol */
						char type[32];
						char proto[64];
						if(sscanf(line, "m=%31s %"SCNu16" %63s %*s", type, &m->port, proto) != 3) {
							if(error)
								g_snprintf(error, errlen, "Invalid m= line: %s", line);
							success = FALSE;
							break;
						}
						m->type = janus_sdp_parse_mtype(type);
						m->type_str = g_strdup(type);
						m->proto = g_strdup(proto);
						m->direction = JANUS_SDP_SENDRECV;
						m->c_ipv4 = TRUE;
						if(m->port > 0) {
							/* Now let's check the payload types/formats */
							gchar **mline_parts = g_strsplit(line+2, " ", -1);
							if(!mline_parts) {
								if(error)
									g_snprintf(error, errlen, "Invalid m= line (no payload types/formats): %s", line);
								success = FALSE;
								break;
							}
							int mindex = 0;
							while(mline_parts[mindex]) {
								if(mindex < 3) {
									/* We've parsed these before */
									mindex++;
									continue;
								}
								/* Add string fmt */
								m->fmts = g_list_append(m->fmts, g_strdup(mline_parts[mindex]));
								/* Add numeric payload type */
								int ptype = atoi(mline_parts[mindex]);
								m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(ptype));
								mindex++;
							}
							g_strfreev(mline_parts);
							if(m->fmts == NULL || m->ptypes == NULL) {
								if(error)
									g_snprintf(error, errlen, "Invalid m= line (no payload types/formats): %s", line);
								success = FALSE;
								break;
							}
						}
						/* Append to the list of m-lines */
						imported->m_lines = g_list_append(imported->m_lines, m);
						/* From now on, we parse this m-line */
						mline = m;
						break;
					}
					default:
						JANUS_LOG(LOG_WARN, "Ignoring '%c' property\n", c);
						break;
				}
			} else {
				/* m-line stuff */
				switch(c) {
					case 'c': {
						char addrtype[6], addr[256];
						if(sscanf(line, "c=IN %5s %255s", addrtype, addr) != 2) {
							if(error)
								g_snprintf(error, errlen, "Invalid c= line: %s", line);
							success = FALSE;
							break;
						}
						if(!strcasecmp(addrtype, "IP4"))
							mline->c_ipv4 = TRUE;
						else if(!strcasecmp(addrtype, "IP6"))
							mline->c_ipv4 = FALSE;
						else {
							if(error)
								g_snprintf(error, errlen, "Invalid c= line (unsupported protocol %s): %s", addrtype, line);
							success = FALSE;
							break;
						}
						mline->c_addr = g_strdup(addr);
						break;
					}
					case 'b': {
						line += 2;
						char *semicolon = strchr(line, ':');
						if(semicolon == NULL || (*(semicolon+1) == '\0')) {
							if(error)
								g_snprintf(error, errlen, "Invalid b= line: %s", line);
							success = FALSE;
							break;
						}
						*semicolon = '\0';
						mline->b_name = g_strdup(line);
						mline->b_value = atoi(semicolon+1);
						*semicolon = ':';
						break;
					}
					case 'a': {
						janus_sdp_attribute *a = g_malloc0(sizeof(janus_sdp_attribute));
						line += 2;
						char *semicolon = strchr(line, ':');
						if(semicolon == NULL) {
							/* Is this a media direction attribute? */
							janus_sdp_mdirection direction = janus_sdp_parse_mdirection(line);
							if(direction != JANUS_SDP_INVALID) {
								g_free(a);
								mline->direction = direction;
								break;
							}
							a->name = g_strdup(line);
							a->value = NULL;
						} else {
							if(*(semicolon+1) == '\0') {
								if(error)
									g_snprintf(error, errlen, "Invalid a= line: %s", line);
								success = FALSE;
								break;
							}
							*semicolon = '\0';
							a->name = g_strdup(line);
							a->value = g_strdup(semicolon+1);
							a->direction = JANUS_SDP_DEFAULT;
							*semicolon = ':';
							if(strstr(line, "/sendonly"))
								a->direction = JANUS_SDP_SENDONLY;
							else if(strstr(line, "/recvonly"))
								a->direction = JANUS_SDP_RECVONLY;
							if(strstr(line, "/inactive"))
								a->direction = JANUS_SDP_INACTIVE;
						}
						mline->attributes = g_list_append(mline->attributes, a);
						break;
					}
					case 'm': {
						/* Current m-line ended, back to global parsing */
						mline = NULL;
						continue;
					}
					default:
						JANUS_LOG(LOG_WARN, "Ignoring '%c' property (m-line)\n", c);
						break;
				}
			}
			index++;
		}
		g_strfreev(parts);
	}
	/* FIXME Do a last check: is all the stuff that's supposed to be there available? */
	if(imported->o_name == NULL || imported->o_addr == NULL || imported->s_name == NULL || imported->m_lines == NULL) {
		success = FALSE;
		if(error)
			g_snprintf(error, errlen, "Missing mandatory lines (o=, s= or m=)");
	}
	/* If something wrong happened, free and return a failure */
	if(!success) {
		if(error)
			JANUS_LOG(LOG_ERR, "%s\n", error);
		janus_sdp_free(imported);
		imported = NULL;
	}
	return imported;
}

int janus_sdp_remove_payload_type(janus_sdp *sdp, int pt) {
	if(!sdp || pt < 0)
		return -1;
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		/* Remove any reference from the m-line */
		m->ptypes = g_list_remove(m->ptypes, GINT_TO_POINTER(pt));
		/* Also remove all attributes that reference the same payload type */
		GList *ma = m->attributes;
		while(ma) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
			if(atoi(a->value) == pt) {
				m->attributes = g_list_remove(m->attributes, a);
				ma = m->attributes;
				janus_sdp_attribute_destroy(a);
				continue;
			}
			ma = ma->next;
		}
		ml = ml->next;
	}
	return 0;
}

int janus_sdp_get_codec_pt(janus_sdp *sdp, const char *codec) {
	if(sdp == NULL || codec == NULL)
		return -1;
	/* Check the format string (note that we only parse what browsers can negotiate) */
	gboolean video = FALSE;
	const char *format = NULL, *format2 = NULL;
	if(!strcasecmp(codec, "opus")) {
		format = "opus/48000/2";
		format2 = "OPUS/48000/2";
	} else if(!strcasecmp(codec, "pcmu")) {
		/* We know the payload type is 0: we just need to make sure it's there */
		format = "pcmu/8000";
		format2 = "PCMU/8000";
	} else if(!strcasecmp(codec, "pcma")) {
		/* We know the payload type is 8: we just need to make sure it's there */
		format = "pcma/8000";
		format2 = "PCMA/8000";
	} else if(!strcasecmp(codec, "g722")) {
		/* We know the payload type is 9: we just need to make sure it's there */
		format = "g722/8000";
		format2 = "G722/8000";
	} else if(!strcasecmp(codec, "isac16")) {
		format = "isac/16000";
		format2 = "ISAC/16000";
	} else if(!strcasecmp(codec, "isac32")) {
		format = "isac/32000";
		format2 = "ISAC/32000";
	} else if(!strcasecmp(codec, "dtmf")) {
		format = "telephone-event/8000";
		format2 = "TELEPHONE-EVENT/8000";
	} else if(!strcasecmp(codec, "vp8")) {
		video = TRUE;
		format = "vp8/90000";
		format2 = "VP8/90000";
	} else if(!strcasecmp(codec, "vp9")) {
		video = TRUE;
		format = "vp9/90000";
		format2 = "VP9/90000";
	} else if(!strcasecmp(codec, "h264")) {
		video = TRUE;
		format = "h264/90000";
		format2 = "H264/90000";
	} else {
		JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", codec);
		return -1;
	}
	/* Check all m->lines */
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		if((!video && m->type != JANUS_SDP_AUDIO) || (video && m->type != JANUS_SDP_VIDEO)) {
			ml = ml->next;
			continue;
		}
		/* Look in all rtpmap attributes */
		GList *ma = m->attributes;
		while(ma) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
			if(a->name != NULL && a->value != NULL && !strcasecmp(a->name, "rtpmap")) {
				int pt = atoi(a->value);
				if(strstr(a->value, format) || strstr(a->value, format2))
					return pt;
			}
			ma = ma->next;
		}
		ml = ml->next;
	}
	return -1;
}

const char *janus_sdp_get_codec_name(janus_sdp *sdp, int pt) {
	if(sdp == NULL || pt < 0)
		return NULL;
	if(pt == 0)
		return "pcmu";
	if(pt == 8)
		return "pcma";
	if(pt == 9)
		return "g722";
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		/* Look in all rtpmap attributes */
		GList *ma = m->attributes;
		while(ma) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
			if(a->name != NULL && a->value != NULL && !strcasecmp(a->name, "rtpmap")) {
				int a_pt = atoi(a->value);
				if(a_pt == pt) {
					/* Found! */
					if(strstr(a->value, "vp8") || strstr(a->value, "VP8"))
						return "vp8";
					if(strstr(a->value, "vp9") || strstr(a->value, "VP9"))
						return "vp9";
					if(strstr(a->value, "h264") || strstr(a->value, "H264"))
						return "h264";
					if(strstr(a->value, "opus") || strstr(a->value, "OPUS"))
						return "opus";
					if(strstr(a->value, "pcmu") || strstr(a->value, "PMCU"))
						return "pcmu";
					if(strstr(a->value, "pcma") || strstr(a->value, "PMCA"))
						return "pcma";
					if(strstr(a->value, "g722") || strstr(a->value, "G722"))
						return "g722";
					if(strstr(a->value, "isac/16") || strstr(a->value, "ISAC/16"))
						return "isac16";
					if(strstr(a->value, "isac/32") || strstr(a->value, "ISAC/32"))
						return "isac32";
					if(strstr(a->value, "telephone-event/8000") || strstr(a->value, "telephone-event/8000"))
						return "dtmf";
					JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", a->value);
					return NULL;
				}
			}
			ma = ma->next;
		}
		ml = ml->next;
	}
	return NULL;
}

//zzy, get corresponding rtx payload
gint32	janus_sdp_get_codec_rtx_payload(janus_sdp *sdp, gint32 pt)
{
	if(sdp == NULL || pt < 0)
		return -1;
	
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		/* Look in all rtpmap attributes */
		GList *ma = m->attributes;
		while(ma) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
			if(a->name != NULL && a->value != NULL && !strcasecmp(a->name, "fmtp") && strstr(a->value, "apt")) {
				gint32 rtx_payload, original_payload;
				rtx_payload = original_payload = 0;
				sscanf(a->value, "%"SCNd32" apt=%"SCNd32"", &rtx_payload, &original_payload);
				if (original_payload == pt) {
					JANUS_LOG(LOG_INFO, "janus_sdp_get_codec_rtx_payload, get right RTX payload:%d \n", rtx_payload);
					return rtx_payload;
				}
			}
			ma = ma->next;
		}
		ml = ml->next;
	}
	return -1;
}

//zzy, get red payload
gint32	janus_sdp_get_red_payload(janus_sdp *sdp)
{
	if(sdp == NULL)
		return -1;
	
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		/* Look in all rtpmap attributes */
		GList *ma = m->attributes;
		while(ma) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
			if(a->name != NULL && a->value != NULL && !strcasecmp(a->name, "rtpmap") && strstr(a->value, "red/90000")) {
				gint32 red_payload = 0;
				sscanf(a->value, "%"SCNd32" red/90000", &red_payload);
				return red_payload;
			}
			ma = ma->next;
		}
		ml = ml->next;
	}
	return -1;
}

//zzy, get fec payload
gint32	janus_sdp_get_fec_payload(janus_sdp *sdp)
{
	if(sdp == NULL)
		return -1;
	
	GList *ml = sdp->m_lines;
	while(ml) {
		janus_sdp_mline *m = (janus_sdp_mline *)ml->data;
		/* Look in all rtpmap attributes */
		GList *ma = m->attributes;
		while(ma) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)ma->data;
			if(a->name != NULL && a->value != NULL && !strcasecmp(a->name, "rtpmap") && strstr(a->value, "ulpfec/90000")) {
				gint32 fec_payload = 0;
				sscanf(a->value, "%"SCNd32" ulpfec/90000", &fec_payload);
				return fec_payload;
			}
			ma = ma->next;
		}
		ml = ml->next;
	}
	return -1;
}

const char *janus_sdp_get_codec_rtpmap(const char *codec) {
	if(codec == NULL)
		return NULL;
	if(!strcasecmp(codec, "opus"))
		return "opus/48000/2";
	if(!strcasecmp(codec, "pcmu"))
		return "PCMU/8000";
	if(!strcasecmp(codec, "pcma"))
		return "PCMA/8000";
	if(!strcasecmp(codec, "g722"))
		return "G722/8000";
	if(!strcasecmp(codec, "isac16"))
		return "ISAC/16000";
	if(!strcasecmp(codec, "isac32"))
		return "ISAC/32000";
	if(!strcasecmp(codec, "dtmf"))
		return "telephone-event/8000";
	if(!strcasecmp(codec, "vp8"))
		return "VP8/90000";
	if(!strcasecmp(codec, "vp9"))
		return "VP9/90000";
	if(!strcasecmp(codec, "h264"))
		return "H264/90000";
	JANUS_LOG(LOG_ERR, "Unsupported codec '%s'\n", codec);
	return NULL;
}

char *janus_sdp_write(janus_sdp *imported) {
	if(!imported)
		return NULL;
	gboolean success = TRUE;
	char *sdp = g_malloc0(JANUS_BUFSIZE), buffer[512];
	*sdp = '\0';
	/* v= */
	g_snprintf(buffer, sizeof(buffer), "v=%d\r\n", imported->version);
	g_strlcat(sdp, buffer, JANUS_BUFSIZE);
	/* o= */
	g_snprintf(buffer, sizeof(buffer), "o=%s %"SCNu64" %"SCNu64" IN %s %s\r\n",
		imported->o_name, imported->o_sessid, imported->o_version,
		imported->o_ipv4 ? "IP4" : "IP6", imported->o_addr);
	g_strlcat(sdp, buffer, JANUS_BUFSIZE);
	/* s= */
	g_snprintf(buffer, sizeof(buffer), "s=%s\r\n", imported->s_name);
	g_strlcat(sdp, buffer, JANUS_BUFSIZE);
	/* t= */
	g_snprintf(buffer, sizeof(buffer), "t=%"SCNu64" %"SCNu64"\r\n", imported->t_start, imported->t_stop);
	g_strlcat(sdp, buffer, JANUS_BUFSIZE);
	/* c= */
	if(imported->c_addr != NULL) {
		g_snprintf(buffer, sizeof(buffer), "c=IN %s %s\r\n",
			imported->c_ipv4 ? "IP4" : "IP6", imported->c_addr);
		g_strlcat(sdp, buffer, JANUS_BUFSIZE);
	}
	/* a= */
	GList *temp = imported->attributes;
	while(temp) {
		janus_sdp_attribute *a = (janus_sdp_attribute *)temp->data;
		if(a->value != NULL) {
			g_snprintf(buffer, sizeof(buffer), "a=%s:%s\r\n", a->name, a->value);
		} else {
			g_snprintf(buffer, sizeof(buffer), "a=%s\r\n", a->name);
		}
		g_strlcat(sdp, buffer, JANUS_BUFSIZE);
		temp = temp->next;
	}
	/* m= */
	temp = imported->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		g_snprintf(buffer, sizeof(buffer), "m=%s %d %s", m->type_str, m->port, m->proto);
		g_strlcat(sdp, buffer, JANUS_BUFSIZE);
		if(m->port == 0) {
			/* Remove all payload types/formats if we're rejecting the media */
			g_list_free_full(m->fmts, (GDestroyNotify)g_free);
			m->fmts = NULL;
			g_list_free(m->ptypes);
			m->ptypes = NULL;
			m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(0));
			g_strlcat(sdp, " 0", JANUS_BUFSIZE);
		} else {
			if(m->proto != NULL && strstr(m->proto, "RTP") != NULL) {
				/* RTP profile, use payload types */
				GList *ptypes = m->ptypes;
				while(ptypes) {
					g_snprintf(buffer, sizeof(buffer), " %d", GPOINTER_TO_INT(ptypes->data));
					g_strlcat(sdp, buffer, JANUS_BUFSIZE);
					ptypes = ptypes->next;
				}
			} else {
				/* Something else, use formats */
				GList *fmts = m->fmts;
				while(fmts) {
					g_snprintf(buffer, sizeof(buffer), " %s", (char *)(fmts->data));
					g_strlcat(sdp, buffer, JANUS_BUFSIZE);
					fmts = fmts->next;
				}
			}
		}
		g_strlcat(sdp, "\r\n", JANUS_BUFSIZE);
		/* c= */
		if(m->c_addr != NULL) {
			g_snprintf(buffer, sizeof(buffer), "c=IN %s %s\r\n",
				m->c_ipv4 ? "IP4" : "IP6", m->c_addr);
			g_strlcat(sdp, buffer, JANUS_BUFSIZE);
		}
		if(m->port > 0) {
			/* b= */
			if(m->b_name != NULL) {
				g_snprintf(buffer, sizeof(buffer), "b=%s:%d\r\n", m->b_name, m->b_value);
				g_strlcat(sdp, buffer, JANUS_BUFSIZE);
			}
		}
		/* a= (note that we don't format the direction if it's JANUS_SDP_DEFAULT) */
		const char *direction = m->direction != JANUS_SDP_DEFAULT ? janus_sdp_mdirection_str(m->direction) : NULL;
		if(direction != NULL) {
			g_snprintf(buffer, sizeof(buffer), "a=%s\r\n", direction);
			g_strlcat(sdp, buffer, JANUS_BUFSIZE);
		}
		if(m->port == 0) {
			/* No point going on */
			temp = temp->next;
			continue;
		}
		GList *temp2 = m->attributes;
		while(temp2) {
			janus_sdp_attribute *a = (janus_sdp_attribute *)temp2->data;
			if(a->value != NULL) {
				g_snprintf(buffer, sizeof(buffer), "a=%s:%s\r\n", a->name, a->value);
			} else {
				g_snprintf(buffer, sizeof(buffer), "a=%s\r\n", a->name);
			}
			g_strlcat(sdp, buffer, JANUS_BUFSIZE);
			temp2 = temp2->next;
		}
		temp = temp->next;
	}
	if(!success) {
		/* FIXME Never happens right now? */
		g_free(sdp);
		sdp = NULL;
	}
	return sdp;
}

janus_sdp *janus_sdp_new(const char *name, const char *address) {
	janus_sdp *sdp = g_malloc0(sizeof(janus_sdp));
	/* Fill in some predefined stuff */
	sdp->version = 0;
	sdp->o_name = g_strdup("-");
	sdp->o_sessid = janus_get_real_time();
	sdp->o_version = 1;
	sdp->o_ipv4 = TRUE;
	sdp->o_addr = g_strdup(address ? address : "127.0.0.1");
	sdp->s_name = g_strdup(name ? name : "Janus session");
	sdp->t_start = 0;
	sdp->t_stop = 0;
	sdp->c_ipv4 = TRUE;
	sdp->c_addr = g_strdup(address ? address : "127.0.0.1");
	/* Done */
	return sdp;
}

janus_sdp *janus_sdp_generate_offer(const char *name, const char *address, ...) {
	/* This method has a variable list of arguments, telling us what we should offer */
	va_list args;
	va_start(args, address);
	/* Let's see what we should do with the media */
	gboolean do_audio = TRUE, do_video = TRUE, do_data = TRUE,
		audio_dtmf = FALSE, video_rtcpfb = TRUE, h264_fmtp = TRUE;
	const char *audio_codec = NULL, *video_codec = NULL;
	int audio_pt = 111, video_pt = 100;
	janus_sdp_mdirection audio_dir = JANUS_SDP_SENDRECV, video_dir = JANUS_SDP_SENDRECV;
	int property = va_arg(args, int);
	while(property != JANUS_SDP_OA_DONE) {
		if(property == JANUS_SDP_OA_AUDIO) {
			do_audio = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_VIDEO) {
			do_video = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_DATA) {
			do_data = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_AUDIO_DIRECTION) {
			audio_dir = va_arg(args, janus_sdp_mdirection);
		} else if(property == JANUS_SDP_OA_VIDEO_DIRECTION) {
			video_dir = va_arg(args, janus_sdp_mdirection);
		} else if(property == JANUS_SDP_OA_AUDIO_CODEC) {
			audio_codec = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_VIDEO_CODEC) {
			video_codec = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_AUDIO_PT) {
			audio_pt = va_arg(args, int);
		} else if(property == JANUS_SDP_OA_VIDEO_PT) {
			video_pt = va_arg(args, int);
		} else if(property == JANUS_SDP_OA_AUDIO_DTMF) {
			audio_dtmf = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_VIDEO_RTCPFB_DEFAULTS) {
			video_rtcpfb = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_VIDEO_H264_FMTP) {
			h264_fmtp = va_arg(args, gboolean);
		} else {
			JANUS_LOG(LOG_WARN, "Unknown property %d for preparing SDP answer, ignoring...\n", property);
		}
		property = va_arg(args, int);
	}
	if(audio_codec == NULL)
		audio_codec = "opus";
	const char *audio_rtpmap = janus_sdp_get_codec_rtpmap(audio_codec);
	if(do_audio && audio_rtpmap == NULL) {
		JANUS_LOG(LOG_ERR, "Unsupported audio codec '%s', can't prepare an offer\n", audio_codec);
		return NULL;
	}
	if(video_codec == NULL)
		video_codec = "vp8";
	const char *video_rtpmap = janus_sdp_get_codec_rtpmap(video_codec);
	if(do_video && video_rtpmap == NULL) {
		JANUS_LOG(LOG_ERR, "Unsupported video codec '%s', can't prepare an offer\n", video_codec);
		return NULL;
	}
#ifndef HAVE_SCTP
	do_data = FALSE;
#endif

	/* Create a new janus_sdp object */
	janus_sdp *offer = janus_sdp_new(name, address);
	/* Now add all the media we should */
	if(do_audio) {
		janus_sdp_mline *m = janus_sdp_mline_create(JANUS_SDP_AUDIO, 1, "UDP/TLS/RTP/SAVPF", audio_dir);
		m->c_ipv4 = TRUE;
		m->c_addr = g_strdup(offer->c_addr);
		/* Add the selected audio codec */
		m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(audio_pt));
		janus_sdp_attribute *a = janus_sdp_attribute_create("rtpmap", "%d %s", audio_pt, audio_rtpmap);
		m->attributes = g_list_append(m->attributes, a);
		/* Check if we need to add a payload type for DTMF tones (telephone-event/8000) */
		if(audio_dtmf) {
			/* We do */
			int dtmf_pt = 126;
			m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(dtmf_pt));
			janus_sdp_attribute *a = janus_sdp_attribute_create("rtpmap", "%d %s", dtmf_pt, janus_sdp_get_codec_rtpmap("dtmf"));
			m->attributes = g_list_append(m->attributes, a);
		}
		offer->m_lines = g_list_append(offer->m_lines, m);
	}
	if(do_video) {
		janus_sdp_mline *m = janus_sdp_mline_create(JANUS_SDP_VIDEO, 1, "UDP/TLS/RTP/SAVPF", video_dir);
		m->c_ipv4 = TRUE;
		m->c_addr = g_strdup(offer->c_addr);
		/* Add the selected video codec */
		m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(video_pt));
		janus_sdp_attribute *a = janus_sdp_attribute_create("rtpmap", "%d %s", video_pt, video_rtpmap);
		m->attributes = g_list_append(m->attributes, a);
		if(!strcasecmp(video_codec, "h264") && h264_fmtp) {
			/* If it's H.264 and we were asked to, add the default fmtp profile as well */
			a = janus_sdp_attribute_create("fmtp", "%d profile-level-id=42e01f;packetization-mode=1", video_pt);
			m->attributes = g_list_append(m->attributes, a);
		}
		if(video_rtcpfb) {
			/* Add rtcp-fb attributes */
			a = janus_sdp_attribute_create("rtcp-fb", "%d ccm fir", video_pt);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("rtcp-fb", "%d nack", video_pt);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("rtcp-fb", "%d nack pli", video_pt);
			m->attributes = g_list_append(m->attributes, a);
			a = janus_sdp_attribute_create("rtcp-fb", "%d goog-remb", video_pt);
			m->attributes = g_list_append(m->attributes, a);
		}
		
		//zzy,  support RTX
		int rtx_pt = INNER_RTX_PAYLOAD;
		m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(rtx_pt));
		a = janus_sdp_attribute_create("rtpmap", "%d rtx/90000", rtx_pt);
		m->attributes = g_list_append(m->attributes, a);
		a = janus_sdp_attribute_create("fmtp", "%d apt=%d", rtx_pt, video_pt);
		m->attributes = g_list_append(m->attributes, a);
		JANUS_LOG(LOG_INFO, "[rtx]support RTX with payload:%d in offer \n", rtx_pt);
		
		//zzy,  support RED
		int red_pt = INNER_RED_PAYLOAD;
		m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(red_pt));
		a = janus_sdp_attribute_create("rtpmap", "%d red/90000", red_pt);
		m->attributes = g_list_append(m->attributes, a);
		int fec_pt = INNER_ULP_FEC_PAYLOAD;
		m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(fec_pt));
		a = janus_sdp_attribute_create("rtpmap", "%d ulpfec/90000", fec_pt);
		m->attributes = g_list_append(m->attributes, a);
		
		int rtx_red_pt = INNER_RTX_RED_PAYLOAD;
		m->ptypes = g_list_append(m->ptypes, GINT_TO_POINTER(rtx_red_pt));
		a = janus_sdp_attribute_create("rtpmap", "%d rtx/90000", rtx_red_pt);
		m->attributes = g_list_append(m->attributes, a);
		a = janus_sdp_attribute_create("fmtp", "%d apt=%d", rtx_red_pt, red_pt);
		m->attributes = g_list_append(m->attributes, a);
		JANUS_LOG(LOG_INFO, "[rtx]support RTX-RED with payload:%d in offer \n", rtx_red_pt);
		
		offer->m_lines = g_list_append(offer->m_lines, m);
	}
	if(do_data) {
		janus_sdp_mline *m = janus_sdp_mline_create(JANUS_SDP_APPLICATION, 1, "DTLS/SCTP", JANUS_SDP_DEFAULT);
		m->c_ipv4 = TRUE;
		m->c_addr = g_strdup(offer->c_addr);
		m->fmts = g_list_append(m->fmts, g_strdup("5000"));
		/* Add an sctmap attribute */
		janus_sdp_attribute *aa = janus_sdp_attribute_create("sctmap", "5000 webrtc-datachannel 16");
		m->attributes = g_list_append(m->attributes, aa);
		offer->m_lines = g_list_append(offer->m_lines, m);
	}

	/* Done */
	va_end(args);

	return offer;
}

janus_sdp *janus_sdp_generate_answer(janus_sdp *offer, ...) {
	if(offer == NULL)
		return NULL;

	/* This method has a variable list of arguments, telling us how we should respond */
	va_list args;
	va_start(args, offer);
	/* Let's see what we should do with the media */
	gboolean do_audio = TRUE, do_video = TRUE, do_data = TRUE,
		audio_dtmf = FALSE, video_rtcpfb = TRUE, h264_fmtp = TRUE;
	const char *audio_codec = NULL, *video_codec = NULL;
	janus_sdp_mdirection audio_dir = JANUS_SDP_SENDRECV, video_dir = JANUS_SDP_SENDRECV;
	int property = va_arg(args, int);
	while(property != JANUS_SDP_OA_DONE) {
		if(property == JANUS_SDP_OA_AUDIO) {
			do_audio = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_VIDEO) {
			do_video = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_DATA) {
			do_data = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_AUDIO_DIRECTION) {
			audio_dir = va_arg(args, janus_sdp_mdirection);
		} else if(property == JANUS_SDP_OA_VIDEO_DIRECTION) {
			video_dir = va_arg(args, janus_sdp_mdirection);
		} else if(property == JANUS_SDP_OA_AUDIO_CODEC) {
			audio_codec = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_VIDEO_CODEC) {
			video_codec = va_arg(args, char *);
		} else if(property == JANUS_SDP_OA_AUDIO_DTMF) {
			audio_dtmf = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_VIDEO_RTCPFB_DEFAULTS) {
			video_rtcpfb = va_arg(args, gboolean);
		} else if(property == JANUS_SDP_OA_VIDEO_H264_FMTP) {
			h264_fmtp = va_arg(args, gboolean);
		} else {
			JANUS_LOG(LOG_WARN, "Unknown property %d for preparing SDP answer, ignoring...\n", property);
		}
		property = va_arg(args, int);
	}
#ifndef HAVE_SCTP
	do_data = FALSE;
#endif

	janus_sdp *answer = g_malloc0(sizeof(janus_sdp));
	/* Start by copying some of the headers */
	answer->version = offer->version;
	answer->o_name = g_strdup(offer->o_name ? offer->o_name : "-");
	answer->o_sessid = offer->o_sessid;
	answer->o_version = offer->o_version;
	answer->o_ipv4 = offer->o_ipv4;
	answer->o_addr = g_strdup(offer->o_addr ? offer->o_addr : "127.0.0.1");
	answer->s_name = g_strdup(offer->s_name ? offer->s_name : "Janus session");
	answer->t_start = 0;
	answer->t_stop = 0;
	answer->c_ipv4 = offer->c_ipv4;
	answer->c_addr = g_strdup(offer->c_addr ? offer->c_addr : "127.0.0.1");

	/* Now iterate on all media, and let's see what we should do */
	int audio = 0, video = 0, data = 0;
	GList *temp = offer->m_lines;
	while(temp) {
		janus_sdp_mline *m = (janus_sdp_mline *)temp->data;
		/* For each m-line we parse, we'll need a corresponding one in the answer */
		janus_sdp_mline *am = g_malloc0(sizeof(janus_sdp_mline));
		am->type = m->type;
		am->type_str = m->type_str ? g_strdup(m->type_str) : NULL;
		am->proto = g_strdup(m->proto ? m->proto : "UDP/TLS/RTP/SAVPF");
		am->port = m->port;
		am->c_ipv4 = m->c_ipv4;
		am->c_addr = g_strdup(am->c_addr ? am->c_addr : "127.0.0.1");
		am->direction = JANUS_SDP_INACTIVE;	/* We'll change this later */
		/* Append to the list of m-lines in the answer */
		answer->m_lines = g_list_append(answer->m_lines, am);
		/* Let's see what this is */
		if(m->type == JANUS_SDP_AUDIO) {
			if(m->port > 0) {
				audio++;
			}
			if(!do_audio || audio > 1) {
				/* Reject */
				am->port = 0;
				temp = temp->next;
				continue;
			}
		} else if(m->type == JANUS_SDP_VIDEO && m->port > 0) {
			if(m->port > 0) {
				video++;
			}
			if(!do_video || video > 1) {
				/* Reject */
				am->port = 0;
				temp = temp->next;
				continue;
			}
		} else if(m->type == JANUS_SDP_APPLICATION && m->port > 0) {
			if(m->port > 0) {
				data++;
			}
			if(!do_data || data > 1) {
				/* Reject */
				am->port = 0;
				temp = temp->next;
				continue;
			}
		}
		if(m->type == JANUS_SDP_AUDIO || m->type == JANUS_SDP_VIDEO) {
			janus_sdp_mdirection target_dir = m->type == JANUS_SDP_AUDIO ? audio_dir : video_dir;
			/* What is the direction we were offered? And how were we asked to react?
			 * Adapt the direction in our answer accordingly */
			switch(m->direction) {
				case JANUS_SDP_RECVONLY:
					if(target_dir == JANUS_SDP_SENDRECV || target_dir == JANUS_SDP_SENDONLY) {
						/* Peer is recvonly, we'll only send */
						am->direction = JANUS_SDP_SENDONLY;
					} else {
						/* Peer is recvonly, but we're not ok to send, so reply with inactive */
						JANUS_LOG(LOG_WARN, "%s offered as '%s', but we need '%s': using 'inactive'\n",
							m->type == JANUS_SDP_AUDIO ? "Audio" : "Video",
							janus_sdp_mdirection_str(m->direction), janus_sdp_mdirection_str(target_dir));
						am->direction = JANUS_SDP_INACTIVE;
					}
					break;
				case JANUS_SDP_SENDONLY:
					if(target_dir == JANUS_SDP_SENDRECV || target_dir == JANUS_SDP_RECVONLY) {
						/* Peer is sendonly, we'll only receive */
						am->direction = JANUS_SDP_RECVONLY;
					} else {
						/* Peer is sendonly, but we're not ok to receive, so reply with inactive */
						JANUS_LOG(LOG_WARN, "%s offered as '%s', but we need '%s': using 'inactive'\n",
							m->type == JANUS_SDP_AUDIO ? "Audio" : "Video",
							janus_sdp_mdirection_str(m->direction), janus_sdp_mdirection_str(target_dir));
						am->direction = JANUS_SDP_INACTIVE;
					}
					break;
				case JANUS_SDP_INACTIVE:
					/* Peer inactive, set inactive in the answer to */
					am->direction = JANUS_SDP_INACTIVE;
					break;
				case JANUS_SDP_SENDRECV:
				default:
					/* The peer is fine with everything, so use our constraint */
					am->direction = target_dir;
					break;
			}
			/* Look for the right codec and stick to that */
			const char *codec = m->type == JANUS_SDP_AUDIO ? audio_codec : video_codec;
			if(codec == NULL) {
				/* FIXME User didn't provide a codec to accept? Let's see if Opus (for audio)
				 * of VP8 (for video) were negotiated: if so, use them, otherwise let's
				 * pick some other codec we know about among the ones that were offered.
				 * Notice that if it's not a codec we understand, we reject the medium,
				 * as browsers would reject it anyway. If you need more flexibility you'll
				 * have to generate an answer yourself, rather than automatically... */
				codec = m->type == JANUS_SDP_AUDIO ? "opus" : "vp8";
				if(janus_sdp_get_codec_pt(offer, codec) < 0) {
					/* We couldn't find our preferred codec, let's try something else */
					if(m->type == JANUS_SDP_AUDIO) {
						/* Opus not found, maybe mu-law? */
						codec = "pcmu";
						if(janus_sdp_get_codec_pt(offer, codec) < 0) {
							/* mu-law not found, maybe a-law? */
							codec = "pcma";
							if(janus_sdp_get_codec_pt(offer, codec) < 0) {
								/* a-law not found, maybe G.722? */
								codec = "722";
								if(janus_sdp_get_codec_pt(offer, codec) < 0) {
									/* G.722 not found, maybe isac32? */
									codec = "isac32";
									if(janus_sdp_get_codec_pt(offer, codec) < 0) {
										/* isac32 not found, maybe isac16? */
										codec = "isac16";
									}
								}
							}
						}
					} else {
						/* VP8 not found, maybe VP9? */
						codec = "vp9";
						if(janus_sdp_get_codec_pt(offer, codec) < 0) {
							/* VP9 not found either, maybe H.264? */
							codec = "h264";
						}
					}
				}
			}
			int pt = janus_sdp_get_codec_pt(offer, codec);
			if(pt < 0) {
				/* Reject */
				JANUS_LOG(LOG_WARN, "Couldn't find codec we needed (%s) in the offer, rejecting %s\n",
					codec, m->type == JANUS_SDP_AUDIO ? "audio" : "video");
				am->port = 0;
				am->direction = JANUS_SDP_INACTIVE;
				temp = temp->next;
				continue;
			}
			am->ptypes = g_list_append(am->ptypes, GINT_TO_POINTER(pt));
			/* Add the related attributes */
			if(m->type == JANUS_SDP_AUDIO) {
				/* Add rtpmap attribute */
				janus_sdp_attribute *a = janus_sdp_attribute_create("rtpmap", "%d %s", pt, janus_sdp_get_codec_rtpmap(codec));
				am->attributes = g_list_append(am->attributes, a);
				/* Check if we need to add a payload type for DTMF tones (telephone-event/8000) */
				if(audio_dtmf) {
					int dtmf_pt = janus_sdp_get_codec_pt(offer, "dtmf");
					if(dtmf_pt >= 0) {
						/* We do */
						am->ptypes = g_list_append(am->ptypes, GINT_TO_POINTER(dtmf_pt));
						janus_sdp_attribute *a = janus_sdp_attribute_create("rtpmap", "%d %s", dtmf_pt, janus_sdp_get_codec_rtpmap("dtmf"));
						am->attributes = g_list_append(am->attributes, a);
					}
				}
			} else {
				/* Add rtpmap attribute */
				janus_sdp_attribute *a = janus_sdp_attribute_create("rtpmap", "%d %s", pt, janus_sdp_get_codec_rtpmap(codec));
				am->attributes = g_list_append(am->attributes, a);
				if(!strcasecmp(codec, "h264") && h264_fmtp) {
					/* If it's H.264 and we were asked to, add the default fmtp profile as well */
					a = janus_sdp_attribute_create("fmtp", "%d profile-level-id=42e01f;packetization-mode=1", pt);
					am->attributes = g_list_append(am->attributes, a);
				}
				if(video_rtcpfb) {
					/* Add rtcp-fb attributes */
					a = janus_sdp_attribute_create("rtcp-fb", "%d ccm fir", pt);
					am->attributes = g_list_append(am->attributes, a);
					a = janus_sdp_attribute_create("rtcp-fb", "%d nack", pt);
					am->attributes = g_list_append(am->attributes, a);
					a = janus_sdp_attribute_create("rtcp-fb", "%d nack pli", pt);
					am->attributes = g_list_append(am->attributes, a);
					a = janus_sdp_attribute_create("rtcp-fb", "%d goog-remb", pt);
					am->attributes = g_list_append(am->attributes, a);
				}
				
				//zzy, support RTX
				int rtx_pt = janus_sdp_get_codec_rtx_payload(offer, pt);
				JANUS_LOG(LOG_INFO, "[rtx]select RTX with payload:%d in answer \n", rtx_pt);
				if (rtx_pt > 0) {
					am->ptypes = g_list_append(am->ptypes, GINT_TO_POINTER(rtx_pt));
					a = janus_sdp_attribute_create("rtpmap", "%d rtx/90000", rtx_pt);
					am->attributes = g_list_append(am->attributes, a);
					a = janus_sdp_attribute_create("fmtp", "%d apt=%d", rtx_pt, pt);
					am->attributes = g_list_append(am->attributes, a);
				}
				
				//zzy, support RED
				int red_pt = janus_sdp_get_red_payload(offer);
				if (red_pt > 0) {
					am->ptypes = g_list_append(am->ptypes, GINT_TO_POINTER(red_pt));
					a = janus_sdp_attribute_create("rtpmap", "%d red/90000", red_pt);
					am->attributes = g_list_append(am->attributes, a);
				}
				
				//zzy, support RTX-RED
				if (red_pt > 0) {
					int rtx_pt = janus_sdp_get_codec_rtx_payload(offer, red_pt);
					JANUS_LOG(LOG_INFO, "[rtx]select RTX-RED with payload:%d in answer \n", rtx_pt);
					if (rtx_pt > 0) {
						am->ptypes = g_list_append(am->ptypes, GINT_TO_POINTER(rtx_pt));
						a = janus_sdp_attribute_create("rtpmap", "%d rtx/90000", rtx_pt);
						am->attributes = g_list_append(am->attributes, a);
						a = janus_sdp_attribute_create("fmtp", "%d apt=%d", rtx_pt, red_pt);
						am->attributes = g_list_append(am->attributes, a);
					}
				}
				
				//zzy, support FEC
				int fec_pt = janus_sdp_get_fec_payload(offer);
				if (fec_pt > 0) {
					am->ptypes = g_list_append(am->ptypes, GINT_TO_POINTER(fec_pt));
					a = janus_sdp_attribute_create("rtpmap", "%d ulpfec/90000", fec_pt);
					am->attributes = g_list_append(am->attributes, a);
				}
			}
		} else {
			/* This is for data, add formats and an sctmap attribute */
			am->direction = JANUS_SDP_DEFAULT;
			GList *fmt = m->fmts;
			while(fmt) {
				char *fmt_str = (char *)fmt->data;
				if(fmt_str)
					am->fmts = g_list_append(am->fmts, g_strdup(fmt_str));
				fmt = fmt->next;
			}
			janus_sdp_attribute *aa = janus_sdp_attribute_create("sctmap", "5000 webrtc-datachannel 16");
			am->attributes = g_list_append(am->attributes, aa);
		}
		temp = temp->next;
	}

	/* Done */
	va_end(args);

	return answer;
}
