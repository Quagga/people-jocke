/*
 * This is an implementation of draft-katz-yeung-ospf-traffic-06.txt
 * Copyright (C) 2001 KDD R&D Laboratories, Inc.
 * http://www.kddlabs.co.jp/
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * 
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_OSPF_MPLS_TE_H
#define _ZEBRA_OSPF_MPLS_TE_H

/*
 * Opaque LSA's link state ID for Traffic Engineering is
 * structured as follows.
 *
 *        24       16        8        0
 * +--------+--------+--------+--------+
 * |    1   |........|........|........|
 * +--------+--------+--------+--------+
 * |<-Type->|<------- Instance ------->|
 *
 *
 * Type:      IANA has assigned '1' for Traffic Engineering.
 * MBZ:       Reserved, must be set to zero.
 * Instance:  User may select an arbitrary 16-bit value.
 *
 */

#define	LEGAL_TE_INSTANCE_RANGE(i)	(0 <= (i) && (i) <= 0xffff)

/*
 *        24       16        8        0
 * +--------+--------+--------+--------+ ---
 * |   LS age        |Options |   10   |  A
 * +--------+--------+--------+--------+  |
 * |    1   |   0    |    Instance     |  |
 * +--------+--------+--------+--------+  |
 * |        Advertising router         |  |  Standard (Opaque) LSA header;
 * +--------+--------+--------+--------+  |  Only type-10 is used.
 * |        LS sequence number         |  |
 * +--------+--------+--------+--------+  |
 * |   LS checksum   |     Length      |  V
 * +--------+--------+--------+--------+ ---
 * |      Type       |     Length      |  A
 * +--------+--------+--------+--------+  |  TLV part for TE; Values might be
 * |              Values ...           |  V  structured as a set of sub-TLVs.
 * +--------+--------+--------+--------+ ---
 */

/*
 * Following section defines TLV (tag, length, value) structures,
 * used for Traffic Engineering.
 */
struct te_tlv_header
{
  u_int16_t	type;			/* TE_TLV_XXX (see below) */
  u_int16_t	length;			/* Value portion only, in octets */
};

#define TLV_HDR_SIZE \
	(sizeof (struct te_tlv_header))

#define TLV_BODY_SIZE(tlvh) \
	(ROUNDUP (ntohs ((tlvh)->length), sizeof (u_int32_t)))

#define TLV_SIZE(tlvh) \
	(TLV_HDR_SIZE + TLV_BODY_SIZE(tlvh))

#define TLV_HDR_TOP(lsah) \
	(struct te_tlv_header *)((char *)(lsah) + OSPF_LSA_HEADER_SIZE)

#define TLV_HDR_NEXT(tlvh) \
	(struct te_tlv_header *)((char *)(tlvh) + TLV_SIZE(tlvh))

/*
 * Following section defines TLV body parts.
 */
/* Router Address TLV *//* Mandatory */
#define	TE_TLV_ROUTER_ADDR		1
struct te_tlv_router_addr
{
  struct te_tlv_header	header;		/* Value length is 4 octets. */
  struct in_addr	value;
};

/* Link TLV */
#define	TE_TLV_LINK			2
struct te_tlv_link
{
  struct te_tlv_header	header;
  /* A set of link-sub-TLVs will follow. */
};

/* Link Type Sub-TLV *//* Mandatory */
#define	TE_LINK_SUBTLV_LINK_TYPE		1
struct te_link_subtlv_link_type
{
  struct te_tlv_header	header;		/* Value length is 1 octet. */
  struct {
#define	LINK_TYPE_SUBTLV_VALUE_PTP	1
#define	LINK_TYPE_SUBTLV_VALUE_MA	2
      u_char	value;
      u_char	padding[3];
  } link_type;
};

/* Link Sub-TLV: Link ID *//* Mandatory */
#define	TE_LINK_SUBTLV_LINK_ID			2
struct te_link_subtlv_link_id
{
  struct te_tlv_header	header;		/* Value length is 4 octets. */
  struct in_addr	value;		/* Same as router-lsa's link-id. */
};

/* Link Sub-TLV: Local Interface IP Address *//* Optional */
#define	TE_LINK_SUBTLV_LCLIF_IPADDR		3
struct te_link_subtlv_lclif_ipaddr
{
  struct te_tlv_header	header;		/* Value length is 4 x N octets. */
  struct in_addr	value[1];	/* Local IP address(es). */
};

/* Link Sub-TLV: Remote Interface IP Address *//* Optional */
#define	TE_LINK_SUBTLV_RMTIF_IPADDR		4
struct te_link_subtlv_rmtif_ipaddr
{
  struct te_tlv_header	header;		/* Value length is 4 x N octets. */
  struct in_addr	value[1];	/* Neighbor's IP address(es). */
};

/* Link Sub-TLV: Traffic Engineering Metric *//* Optional */
#define	TE_LINK_SUBTLV_TE_METRIC		5
struct te_link_subtlv_te_metric
{
  struct te_tlv_header	header;		/* Value length is 4 octets. */
  u_int32_t		value;		/* Link metric for TE purpose. */
};

/* Link Sub-TLV: Maximum Bandwidth *//* Optional */
#define	TE_LINK_SUBTLV_MAX_BW			6
struct te_link_subtlv_max_bw
{
  struct te_tlv_header	header;		/* Value length is 4 octets. */
  float			value;		/* bytes/sec */
};

/* Link Sub-TLV: Maximum Reservable Bandwidth *//* Optional */
#define	TE_LINK_SUBTLV_MAX_RSV_BW		7
struct te_link_subtlv_max_rsv_bw
{
  struct te_tlv_header	header;		/* Value length is 4 octets. */
  float			value;		/* bytes/sec */
};

/* Link Sub-TLV: Unreserved Bandwidth *//* Optional */
#define	TE_LINK_SUBTLV_UNRSV_BW			8
struct te_link_subtlv_unrsv_bw
{
  struct te_tlv_header	header;		/* Value length is 32 octets. */
  float			value[8];	/* One for each priority level. */
};

/* Link Sub-TLV: Resource Class/Color *//* Optional */
#define	TE_LINK_SUBTLV_RSC_CLSCLR		9
struct te_link_subtlv_rsc_clsclr
{
  struct te_tlv_header	header;		/* Value length is 4 octets. */
  u_int32_t		value;		/* Admin. group membership. */
};

/* GMPLS Link Sub-TLV: Link Local/Remote Identifiers *//* Optional */
#define GTE_LINK_SUBTLV_LRID			11
struct gte_link_subtlv_lrid
{
  struct te_tlv_header	header;		/* Value length is 8 octets. */
  struct in_addr	local;		/* Local ID (IP address) */
  struct in_addr	remote;		/* Remote ID (IP address) */
};

/* GMPLS Link Sub-TLV: Link Protection Type *//* Optional */
/* Link Protection TLV is encoded as follows:
   
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Protection Cap |                    Reserved                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#define GTE_LINK_SUBTLV_PROTECTION		14
struct gte_link_subtlv_protection
{
  struct te_tlv_header	header;

#define GTE_PROTECTION_TYPE_EXTRA_TRAFFIC	0x01
#define GTE_PROTECTION_TYPE_UNPROTECTED		0x02
#define GTE_PROTECTION_TYPE_SHARED		0x04
#define GTE_PROTECTION_TYPE_DEDICATED_ONE_TO_ONE	0x08
#define GTE_PROTECTION_TYPE_DEDICATED_ONE_PLUS_ONE	0x10
#define GTE_PROTECTION_TYPE_ENCHANCED		0x20
#define GTE_PROTECTION_TYPE_RESERVED1		0x40
#define GTE_PROTECTION_TYPE_RESERVED2		0x80
  u_char		value;		/* Protection type */
  u_char		padding[3];
};

/* Packet Switching specific info encoding for Capability Sub-TLV:
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Minimum LSP Bandwidth                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Interface MTU       |            Padding            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct gte_link_subtlv_capability_spec_psc
{
  float			minbw;		/* Min LSP Bandwidth */
  u_int16_t  		mtu;		/* Interface MTU */
  u_int16_t		padding;
};

/* TDM Switching specific info encoding for Capability Sub-TLV:
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Minimum LSP Bandwidth                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Indication  |                 Padding                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct gte_link_subtlv_capability_spec_tdm
{
  float			minbw;		/* Min LSP Bandwidth */

#define GTE_TDM_CAPABILITY_IND_STANDARD		0
#define GTE_TDM_CAPABILITY_IND_ARBITRARY	1
  u_char		indication;	/* Indication */
  u_char		padding[3];
};

/* GMPLS Link Sub-TLV: Interface Switching Capability Descriptor *//* Optional */
/* Interface Switching Capability Descriptor Sub-TLV is encoded as follows:
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Switching Cap |   Encoding    |           Reserved            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Max LSP Bandwidth at priority 0              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Max LSP Bandwidth at priority 1              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Max LSP Bandwidth at priority 2              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Max LSP Bandwidth at priority 3              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Max LSP Bandwidth at priority 4              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Max LSP Bandwidth at priority 5              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Max LSP Bandwidth at priority 6              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Max LSP Bandwidth at priority 7              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |        Switching Capability-specific information              |
  |                  (variable)                                   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define GTE_LINK_SUBTLV_CAPABILITY		15
struct gte_link_subtlv_capability
{
  struct te_tlv_header	header;

#define GTE_SWITCHING_TYPE_PSC1 		1
#define GTE_SWITCHING_TYPE_PSC2 		2
#define GTE_SWITCHING_TYPE_PSC3 		3
#define GTE_SWITCHING_TYPE_PSC4 		4
#define GTE_SWITCHING_TYPE_L2SC 		51
#define GTE_SWITCHING_TYPE_TDM	 		100
#define GTE_SWITCHING_TYPE_LSC 			150
#define GTE_SWITCHING_TYPE_FSC 			200
  u_char		capability;	/* Switching capability */

#define GTE_ENCODING_TYPE_PACKET		1
#define GTE_ENCODING_TYPE_ETHERNET		2
#define GTE_ENCODING_TYPE_PDH			3
#define GTE_ENCODING_TYPE_SDH_SONET		5
#define GTE_ENCODING_TYPE_DWRAPPER		7
#define GTE_ENCODING_TYPE_LAMBDA		8
#define GTE_ENCODING_TYPE_FIBER			9
#define GTE_ENCODING_TYPE_FIBERCHANNEL		11
  u_char		encoding;	/* Encoding */
  u_int16_t		reserved;
  float			maxbw[8];	/* Max LSP Bandwidth */
  struct gte_link_subtlv_capability_spec_psc	psc;	/* Packet Switching specific info. */
  struct gte_link_subtlv_capability_spec_tdm	tdm;	/* TDM/SDH/STM Switching specific info. */  
};


/* GMPLS Link Sub-TLV: Shared Risk Link Group (SRLG) *//* Optional */
/* Shared Risk Link Group (SRLG) Sub-TLV is encoded as follows:
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Shared Risk Link Group Value                 |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                        ............                           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Shared Risk Link Group Value                 |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define GTE_LINK_SUBTLV_SRLG			16
struct gte_link_subtlv_srlg
{
  struct te_tlv_header	header;
  struct list 		*srlg;		/* SRLG list. List nodes must be 'u_int32_t' type. */
};



/* Here are "non-official" architechtual constants. */
#define MPLS_TE_MINIMUM_BANDWIDTH	1.0	/* Reasonable? *//* XXX */

/* Prototypes. */
extern int ospf_mpls_te_init (void);
extern void ospf_mpls_te_term (void);

#endif /* _ZEBRA_OSPF_MPLS_TE_H */
