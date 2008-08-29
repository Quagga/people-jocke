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

/***** MTYPE definition is not reflected to "memory.h" yet. *****/
#define MTYPE_OSPF_MPLS_TE_LINKPARAMS	0

#include <zebra.h>

#ifdef HAVE_OSPF_TE
#ifndef HAVE_OPAQUE_LSA
#error "Wrong configure option"
#endif /* HAVE_OPAQUE_LSA */

#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "thread.h"
#include "hash.h"
#include "sockunion.h"		/* for inet_aton() */

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_te.h"

/* Following structure are internal use only. */
struct ospf_mpls_te
{
  enum { disabled, enabled } status;

  /* List elements are zebra-interfaces (ifp), not ospf-interfaces (oi). */
  struct list *iflist;

  /* Store Router-TLV in network byte order. */
  struct te_tlv_router_addr router_addr;
};

struct mpls_te_link
{
  /*
   * According to MPLS-TE (draft) specification, 24-bit Opaque-ID field
   * is subdivided into 8-bit "unused" field and 16-bit "instance" field.
   * In this implementation, each Link-TLV has its own instance.
   */
  u_int32_t instance;

  /* Reference pointer to a Zebra-interface. */
  struct interface *ifp;

  /* Area info in which this MPLS-TE link belongs to. */
  struct ospf_area *area;

  /* Flags to manage this link parameters. */
  u_int32_t flags;
#define LPFLG_LOOKUP_DONE		0x1
#define LPFLG_LSA_ENGAGED		0x2
#define LPFLG_LSA_FORCED_REFRESH	0x4

  /* Store Link-TLV in network byte order. */
  struct te_tlv_link link_header;
  struct te_link_subtlv_link_type link_type;
  struct te_link_subtlv_link_id link_id;
  struct te_link_subtlv_lclif_ipaddr *lclif_ipaddr;
  struct te_link_subtlv_rmtif_ipaddr *rmtif_ipaddr;
  struct te_link_subtlv_te_metric te_metric;
  struct te_link_subtlv_max_bw max_bw;
  struct te_link_subtlv_max_rsv_bw max_rsv_bw;
  struct te_link_subtlv_unrsv_bw unrsv_bw;
  struct te_link_subtlv_rsc_clsclr rsc_clsclr;
  struct gte_link_subtlv_lrid lrid;
  struct gte_link_subtlv_protection protection;
  struct gte_link_subtlv_capability capability; /* Only one capability TLV implemented */
  struct gte_link_subtlv_srlg srlg;
};

/*
 * Global variable to manage Opaque-LSA/MPLS-TE on this node.
 * Note that all parameter values are stored in network byte order.
 */
static struct ospf_mpls_te OspfMplsTE;

enum oifstate {
  OI_ANY, OI_DOWN, OI_UP
};

enum sched_opcode {
  REORIGINATE_PER_AREA, REFRESH_THIS_LSA, FLUSH_THIS_LSA
};

/*------------------------------------------------------------------------*
 * Followings are initialize/terminate functions for MPLS-TE handling.
 *------------------------------------------------------------------------*/

static int ospf_mpls_te_new_if (struct interface *ifp);
static int ospf_mpls_te_del_if (struct interface *ifp);
static void ospf_mpls_te_ism_change (struct ospf_interface *oi, int old_status);
static void ospf_mpls_te_nsm_change (struct ospf_neighbor *nbr, int old_status);
static void ospf_mpls_te_config_write_router (struct vty *vty);
static void ospf_mpls_te_config_write_if (struct vty *vty, struct interface *ifp);
static void ospf_mpls_te_show_info (struct vty *vty, struct ospf_lsa *lsa);
static int ospf_mpls_te_lsa_originate (void *arg);
static void ospf_mpls_te_lsa_refresh (struct ospf_lsa *lsa);
static void ospf_mpls_te_lsa_schedule (struct mpls_te_link *lp, enum sched_opcode);

static void del_mpls_te_link (void *val);
static void ospf_mpls_te_register_vty (void);

int
ospf_mpls_te_init (void)
{
  int rc;

  rc = ospf_register_opaque_functab (
                OSPF_OPAQUE_AREA_LSA,
                OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA,
		ospf_mpls_te_new_if,
		ospf_mpls_te_del_if,
		ospf_mpls_te_ism_change,
		ospf_mpls_te_nsm_change,
		ospf_mpls_te_config_write_router,
		ospf_mpls_te_config_write_if,
		NULL,/* ospf_mpls_te_config_write_debug */
                ospf_mpls_te_show_info,
                ospf_mpls_te_lsa_originate,
                ospf_mpls_te_lsa_refresh,
		NULL,/* ospf_mpls_te_new_lsa_hook */
		NULL /* ospf_mpls_te_del_lsa_hook */);
  if (rc != 0)
    {
      zlog_warn ("ospf_mpls_te_init: Failed to register functions");
      goto out;
    }

  memset (&OspfMplsTE, 0, sizeof (struct ospf_mpls_te));
  OspfMplsTE.status = disabled;
  OspfMplsTE.iflist = list_new ();
  OspfMplsTE.iflist->del = del_mpls_te_link;

  ospf_mpls_te_register_vty ();

out:
  return rc;
}

void
ospf_mpls_te_term (void)
{
  list_delete (OspfMplsTE.iflist);

  OspfMplsTE.iflist = NULL;
  OspfMplsTE.status = disabled;

  ospf_delete_opaque_functab (OSPF_OPAQUE_AREA_LSA,
                              OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA);
  return;
}

/*------------------------------------------------------------------------*
 * Followings are control functions for MPLS-TE parameters management.
 *------------------------------------------------------------------------*/

static void
del_mpls_te_link (void *val)
{
  struct mpls_te_link *lp = (struct mpls_te_link *) val;
  list_delete(lp->srlg.srlg); /* Free SRLG list */
  
  XFREE (MTYPE_OSPF_MPLS_TE_LINKPARAMS, val);
  return;
}

/* SLRG list deletion */
static void
del_srlg_list(void *val)
{
  XFREE (MTYPE_TMP, val);
  return;
}
  
static u_int32_t
get_mpls_te_instance_value (void)
{
  static u_int32_t seqno = 0;

  if (LEGAL_TE_INSTANCE_RANGE (seqno + 1))
    seqno += 1;
  else
    seqno  = 1; /* Avoid zero. */

  return seqno;
}

static struct ospf_interface *
lookup_oi_by_ifp (struct interface *ifp,
                  struct ospf_area *area, enum oifstate oifstate)
{
  struct ospf_interface *oi = NULL;
  struct route_node *rn;

  for (rn = route_top (IF_OIFS (ifp)); rn; rn = route_next (rn))
    {
      if ((oi = rn->info) == NULL)
        continue;

      switch (oifstate)
        {
        case OI_ANY:
          break;
        case OI_DOWN:
          if (ospf_if_is_enable (oi))
            continue;
          break;
        case OI_UP:
          if (! ospf_if_is_enable (oi))
            continue;
          break;
        default:
          zlog_warn ("lookup_oi_by_ifp: Unknown oifstate: %x", oifstate);
          goto out;
        }

      if (area == NULL || oi->area == area)
        return oi;
    }
out:
  return NULL;
}

static struct mpls_te_link *
lookup_linkparams_by_ifp (struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct mpls_te_link *lp;

  for (ALL_LIST_ELEMENTS (OspfMplsTE.iflist, node, nnode, lp))
    if (lp->ifp == ifp)
      return lp;

  return NULL;
}

static struct mpls_te_link *
lookup_linkparams_by_instance (struct ospf_lsa *lsa)
{
  struct listnode *node;
  struct mpls_te_link *lp;
  unsigned int key = GET_OPAQUE_ID (ntohl (lsa->data->id.s_addr));

  for (ALL_LIST_ELEMENTS_RO (OspfMplsTE.iflist, node, lp))
    if (lp->instance == key)
      return lp;

  zlog_warn ("lookup_linkparams_by_instance: Entry not found: key(%x)", key);
  return NULL;
}

static void
ospf_mpls_te_foreach_area (
  void (*func)(struct mpls_te_link *lp, enum sched_opcode),
  enum sched_opcode sched_opcode)
{
  struct listnode *node, *nnode; 
  struct listnode *node2;
  struct mpls_te_link *lp;
  struct ospf_area *area;

  for (ALL_LIST_ELEMENTS (OspfMplsTE.iflist, node, nnode, lp))
    {
      if ((area = lp->area) == NULL)
        continue;
      if (lp->flags & LPFLG_LOOKUP_DONE)
        continue;

      if (func != NULL)
        (* func)(lp, sched_opcode);

      for (node2 = listnextnode (node); node2; node2 = listnextnode (node2))
        if ((lp = listgetdata (node2)) != NULL)
          if (lp->area != NULL)
            if (IPV4_ADDR_SAME (&lp->area->area_id, &area->area_id))
              lp->flags |= LPFLG_LOOKUP_DONE;
    }

  for (ALL_LIST_ELEMENTS_RO (OspfMplsTE.iflist, node, lp))
    if (lp->area != NULL)
      lp->flags &= ~LPFLG_LOOKUP_DONE;

  return;
}

static void
set_mpls_te_router_addr (struct in_addr ipv4)
{
  OspfMplsTE.router_addr.header.type   = htons (TE_TLV_ROUTER_ADDR);
  OspfMplsTE.router_addr.header.length = htons (sizeof (ipv4));
  OspfMplsTE.router_addr.value = ipv4;
  return;
}

static void
set_linkparams_link_header (struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh;
  u_int16_t length = 0;

  /* TE_LINK_SUBTLV_LINK_TYPE */
  if (ntohs (lp->link_type.header.type) != 0)
    length += TLV_SIZE (&lp->link_type.header);

  /* TE_LINK_SUBTLV_LINK_ID */
  if (ntohs (lp->link_id.header.type) != 0)
    length += TLV_SIZE (&lp->link_id.header);

  /* TE_LINK_SUBTLV_LCLIF_IPADDR */
  if ((tlvh = (struct te_tlv_header *) lp->lclif_ipaddr) != NULL
  &&  ntohs (tlvh->type) != 0)
    length += TLV_SIZE (tlvh);

  /* TE_LINK_SUBTLV_RMTIF_IPADDR */
  if ((tlvh = (struct te_tlv_header *) lp->rmtif_ipaddr) != NULL
  &&  ntohs (tlvh->type) != 0)
    length += TLV_SIZE (tlvh);

  /* TE_LINK_SUBTLV_TE_METRIC */
  if (ntohs (lp->te_metric.header.type) != 0)
    length += TLV_SIZE (&lp->te_metric.header);

  /* TE_LINK_SUBTLV_MAX_BW */
  if (ntohs (lp->max_bw.header.type) != 0)
    length += TLV_SIZE (&lp->max_bw.header);

  /* TE_LINK_SUBTLV_MAX_RSV_BW */
  if (ntohs (lp->max_rsv_bw.header.type) != 0)
    length += TLV_SIZE (&lp->max_rsv_bw.header);

  /* TE_LINK_SUBTLV_UNRSV_BW */
  if (ntohs (lp->unrsv_bw.header.type) != 0)
    length += TLV_SIZE (&lp->unrsv_bw.header);

  /* TE_LINK_SUBTLV_RSC_CLSCLR */
  if (ntohs (lp->rsc_clsclr.header.type) != 0)
    length += TLV_SIZE (&lp->rsc_clsclr.header);

  /* GTE_LINK_SUBTLV_LRID */
  if (ntohs (lp->lrid.header.type) != 0)
    length += TLV_SIZE (&lp->lrid.header);

  /* GTE_LINK_SUBTLV_PROTECTION */
  if (ntohs (lp->protection.header.type) != 0)
    length += TLV_SIZE (&lp->protection.header);

  /* GTE_LINK_SUBTLV_CAPABILITY */
  if (ntohs (lp->capability.header.type) != 0)
    length += TLV_SIZE (&lp->capability.header);

  /* GTE_LINK_SUBTLV_SRLG */
  if (ntohs (lp->srlg.header.type) != 0)
    length += TLV_SIZE (&lp->srlg.header);

  lp->link_header.header.type   = htons (TE_TLV_LINK);
  lp->link_header.header.length = htons (length);

  return;
}

static void
set_linkparams_link_type (struct ospf_interface *oi, struct mpls_te_link *lp)
{
  lp->link_type.header.type   = htons (TE_LINK_SUBTLV_LINK_TYPE);
  lp->link_type.header.length = htons (sizeof (lp->link_type.link_type.value));

  switch (oi->type)
    {
    case OSPF_IFTYPE_POINTOPOINT:
      lp->link_type.link_type.value = LINK_TYPE_SUBTLV_VALUE_PTP;
      break;
    case OSPF_IFTYPE_BROADCAST:
    case OSPF_IFTYPE_NBMA:
      lp->link_type.link_type.value = LINK_TYPE_SUBTLV_VALUE_MA;
      break;
    default:
      /* Not supported yet. *//* XXX */
      lp->link_type.header.type = htons (0);
      break;
    }
  return;
}

static void
set_linkparams_link_id (struct ospf_interface *oi, struct mpls_te_link *lp)
{
  struct ospf_neighbor *nbr;
  int done = 0;

  lp->link_id.header.type   = htons (TE_LINK_SUBTLV_LINK_ID);
  lp->link_id.header.length = htons (sizeof (lp->link_id.value));

  /*
   * The Link ID is identical to the contents of the Link ID field
   * in the Router LSA for these link types.
   */
  switch (oi->type)
    {
    case OSPF_IFTYPE_POINTOPOINT:
      /* Take the router ID of the neighbor. */
      if ((nbr = ospf_nbr_lookup_ptop (oi))
	  && nbr->state == NSM_Full)
        {
          lp->link_id.value = nbr->router_id;
          done = 1;
        }
      break;
    case OSPF_IFTYPE_BROADCAST:
    case OSPF_IFTYPE_NBMA:
      /* Take the interface address of the designated router. */
      if ((nbr = ospf_nbr_lookup_by_addr (oi->nbrs, &DR (oi))) == NULL)
        break;

      if (nbr->state == NSM_Full
      || (IPV4_ADDR_SAME (&oi->address->u.prefix4, &DR (oi))
      &&  ospf_nbr_count (oi, NSM_Full) > 0))
        {
          lp->link_id.value = DR (oi);
          done = 1;
        }
      break;
    default:
      /* Not supported yet. *//* XXX */
      lp->link_id.header.type = htons (0);
      break;
    }

  if (! done)
    {
      struct in_addr mask;
      masklen2ip (oi->address->prefixlen, &mask);
      lp->link_id.value.s_addr = oi->address->u.prefix4.s_addr & mask.s_addr;
     }
  return;
}

static void
set_linkparams_te_metric (struct mpls_te_link *lp, u_int32_t te_metric)
{
  lp->te_metric.header.type   = htons (TE_LINK_SUBTLV_TE_METRIC);
  lp->te_metric.header.length = htons (sizeof (lp->te_metric.value));
  lp->te_metric.value = htonl (te_metric);
  return;
}

static void
set_linkparams_max_bw (struct mpls_te_link *lp, float *fp)
{
  lp->max_bw.header.type   = htons (TE_LINK_SUBTLV_MAX_BW);
  lp->max_bw.header.length = htons (sizeof (lp->max_bw.value));
  htonf (fp, &lp->max_bw.value);
  return;
}

static void
set_linkparams_max_rsv_bw (struct mpls_te_link *lp, float *fp)
{
  lp->max_rsv_bw.header.type   = htons (TE_LINK_SUBTLV_MAX_RSV_BW);
  lp->max_rsv_bw.header.length = htons (sizeof (lp->max_rsv_bw.value));
  htonf (fp, &lp->max_rsv_bw.value);
  return;
}

static void
set_linkparams_unrsv_bw (struct mpls_te_link *lp, int priority, float *fp)
{
  /* Note that TLV-length field is the size of array. */
  lp->unrsv_bw.header.type   = htons (TE_LINK_SUBTLV_UNRSV_BW);
  lp->unrsv_bw.header.length = htons (sizeof (lp->unrsv_bw.value));
  htonf (fp, &lp->unrsv_bw.value [priority]);
  return;
}

static void
set_linkparams_rsc_clsclr (struct mpls_te_link *lp, u_int32_t classcolor)
{
  lp->rsc_clsclr.header.type   = htons (TE_LINK_SUBTLV_RSC_CLSCLR);
  lp->rsc_clsclr.header.length = htons (sizeof (lp->rsc_clsclr.value));
  lp->rsc_clsclr.value = htonl (classcolor);
  return;
}

/* Set GMPLS lrid local ID */
static void
set_linkparams_lrid_local (struct mpls_te_link *lp, struct in_addr value)
{
  lp->lrid.header.type = htons(GTE_LINK_SUBTLV_LRID);
  lp->lrid.header.length = htons (sizeof (lp->lrid.local) + sizeof (lp->lrid.remote));
  
  lp->lrid.local = value;
}

/* Set GMPLS lrid local ID */
static void
set_linkparams_lrid_remote (struct mpls_te_link *lp, struct in_addr value)
{
  lp->lrid.header.type = htons(GTE_LINK_SUBTLV_LRID);
  lp->lrid.header.length = htons (sizeof (lp->lrid.local) + sizeof (lp->lrid.remote));
  
  lp->lrid.remote = value;
}
  
static void
set_linkparams_protection (struct mpls_te_link *lp, u_char p)
{
  lp->protection.header.type = htons(GTE_LINK_SUBTLV_PROTECTION);
  lp->protection.header.length = htons (sizeof (lp->protection.value));
  lp->protection.value = p; 
}

static void
set_linkparams_capability (struct mpls_te_link *lp, u_char c, u_char e, \
    int i, float maxb, float minb)
{
  lp->capability.header.type = htons(GTE_LINK_SUBTLV_CAPABILITY);
  
  lp->capability.header.length = htons (sizeof (lp->capability.capability) + \
      sizeof (lp->capability.encoding) + sizeof (lp->capability.reserved) + \
      sizeof (lp->capability.maxbw) + sizeof(lp->capability.psc)); 
	    /* Should variate depending on psc or tdm *//* XXX Fix this */
  
  lp->capability.capability = c;
  lp->capability.encoding = e;
  lp->capability.reserved = 0;
  htonf(&maxb, &lp->capability.maxbw[i]);
  htonf(&minb, &lp->capability.psc.minbw);
  
  
  
  
  if (c == (GTE_SWITCHING_TYPE_PSC1 || GTE_SWITCHING_TYPE_PSC2 \
	|| GTE_SWITCHING_TYPE_PSC3 || GTE_SWITCHING_TYPE_PSC4))
      lp->capability.psc.mtu = htons(lp->ifp->mtu); 
}

/* Set GMPLS maxbw per class */
static void
set_linkparams_capability_maxbw (struct mpls_te_link *lp, int class, float bw)
{
  if (lp != NULL && (ntohs(lp->capability.header.type) != 0))
    htonf(&bw, &lp->capability.maxbw[class]);
}

/* Set GMPLS minbw */
static void
set_linkparams_capability_minbw (struct mpls_te_link *lp, u_char cap, float bw)
{
  if (lp != NULL && (ntohs(lp->capability.header.type) != 0))
  {
    if (cap == GTE_SWITCHING_TYPE_TDM)
      htonf(&bw, &lp->capability.tdm.minbw);
    else
      htonf(&bw, &lp->capability.psc.minbw);
  }
}


/* Set GMPLS encoding */
static void
set_linkparams_capability_encoding(struct mpls_te_link *lp, u_char enc)
{
  if (lp != NULL && (ntohs(lp->capability.header.type) != 0))
    lp->capability.encoding = enc;
}

/* Set initial GMPLS lsa parameters. */
static void
set_linkparams_capability_init (struct mpls_te_link *lp)
{
  struct interface *ifp = lp->ifp;
  float bw,fval;
  int i;
  
  lp->capability.header.type = htons(GTE_LINK_SUBTLV_CAPABILITY);
  
  lp->capability.header.length = htons (sizeof (lp->capability.capability) + \
      sizeof (lp->capability.encoding) + sizeof (lp->capability.reserved) + \
      sizeof (lp->capability.maxbw) + sizeof(lp->capability.psc)); 
	    /* Should variate depending on psc or tdm *//* XXX Fix this */
  
  lp->capability.capability = GTE_SWITCHING_TYPE_PSC1;
  lp->capability.encoding = GTE_ENCODING_TYPE_ETHERNET;
  lp->capability.reserved = 0;
  
  fval = (float)((ifp->bandwidth ? ifp->bandwidth
                                 : OSPF_DEFAULT_BANDWIDTH) * 1000 / 8);

  
  for (i = 0; i < 8; i++)
    set_linkparams_capability_maxbw(lp, i, fval);

  bw = MPLS_TE_MINIMUM_BANDWIDTH; 
  htonf(&bw, &lp->capability.psc.minbw);
  
  lp->capability.psc.mtu = htons(lp->ifp->mtu); 

}

static void
set_linkparams_capability_mtu(struct mpls_te_link *lp, u_int16_t mtu)
{
  if (lp != NULL && (ntohs(lp->capability.header.type) != 0))
    lp->capability.psc.mtu = htons(mtu);
}

/* Set GMPLS capability type */
static void
set_linkparams_capability_cap (struct mpls_te_link *lp, u_char c)
{
  if (lp != NULL && (ntohs(lp->capability.header.type) != 0))
    lp->capability.capability = c;
}

/* Set GMPLS capability indication */
static void
set_linkparams_capability_indication(struct mpls_te_link *lp, u_char ind)
{
  if (lp != NULL && (ntohs(lp->capability.header.type) != 0))
    lp->capability.tdm.indication = ind;
}


static void
set_linkparams_srlg (struct mpls_te_link *lp, u_int32_t s)
{
  if (lp->srlg.header.type == 0)
  {
    lp->srlg.header.type = htons(GTE_LINK_SUBTLV_SRLG);
    lp->srlg.srlg = list_new();
    lp->srlg.srlg->del = del_srlg_list;
  }
    
  lp->srlg.header.length = htons (sizeof (s) * (1 + listcount(lp->srlg.srlg)));
  
  u_int32_t *sp;
  sp = XMALLOC (MTYPE_TMP, sizeof(u_int32_t)); 
  *sp = s;
  
  listnode_add (lp->srlg.srlg, sp);      
}

static void
initialize_linkparams (struct mpls_te_link *lp)
{
  struct interface *ifp = lp->ifp;
  struct ospf_interface *oi;
  float fval;
  int i;

  if ((oi = lookup_oi_by_ifp (ifp, NULL, OI_ANY)) == NULL)
    return;

  /*
   * Try to set initial values those can be derived from
   * zebra-interface information.
   */
  set_linkparams_link_type (oi, lp);

  /*
   * Linux and *BSD kernel holds bandwidth parameter as an "int" type.
   * We may have to reconsider, if "ifp->bandwidth" type changes to float.
   */
  fval = (float)((ifp->bandwidth ? ifp->bandwidth
                                 : OSPF_DEFAULT_BANDWIDTH) * 1000 / 8);

  set_linkparams_max_bw (lp, &fval);
  set_linkparams_max_rsv_bw (lp, &fval);

  for (i = 0; i < 8; i++)
    set_linkparams_unrsv_bw (lp, i, &fval);

  /* Try to set Capability */
  for (i = 0; i < 8; i++)
    set_linkparams_capability(lp, GTE_SWITCHING_TYPE_PSC1, \
        GTE_ENCODING_TYPE_ETHERNET, i, fval, MPLS_TE_MINIMUM_BANDWIDTH);
  return;
}

static int
is_mandated_params_set (struct mpls_te_link *lp)
{
  int rc = 0;

  if (ntohs (OspfMplsTE.router_addr.header.type) == 0)
    goto out;

  if (ntohs (lp->link_type.header.type) == 0)
    goto out;

  if (ntohs (lp->link_id.header.type) == 0)
    goto out;

  rc = 1;
out:
  return rc;
}

/*------------------------------------------------------------------------*
 * Followings are callback functions against generic Opaque-LSAs handling.
 *------------------------------------------------------------------------*/

static int
ospf_mpls_te_new_if (struct interface *ifp)
{
  struct mpls_te_link *new;
  int rc = -1;

  if (lookup_linkparams_by_ifp (ifp) != NULL)
    {
      zlog_warn ("ospf_mpls_te_new_if: ifp(%p) already in use?", ifp);
      rc = 0; /* Do nothing here. */
      goto out;
    }

  if ((new = XMALLOC (MTYPE_OSPF_MPLS_TE_LINKPARAMS,
                  sizeof (struct mpls_te_link))) == NULL)
    {
      zlog_warn ("ospf_mpls_te_new_if: XMALLOC: %s", safe_strerror (errno));
      goto out;
    }
  memset (new, 0, sizeof (struct mpls_te_link));

  new->area = NULL;
  new->flags = 0;
  new->instance = get_mpls_te_instance_value ();
  new->ifp = ifp;

  initialize_linkparams (new);

  listnode_add (OspfMplsTE.iflist, new);

  /* Schedule Opaque-LSA refresh. *//* XXX */

  rc = 0;
out:
  return rc;
}

static int
ospf_mpls_te_del_if (struct interface *ifp)
{
  struct mpls_te_link *lp;
  int rc = -1;

  if ((lp = lookup_linkparams_by_ifp (ifp)) != NULL)
    {
      struct list *iflist = OspfMplsTE.iflist;

      /* Dequeue listnode entry from the list. */
      listnode_delete (iflist, lp);

      /* Avoid misjudgement in the next lookup. */
      if (listcount (iflist) == 0)
        iflist->head = iflist->tail = NULL;

      XFREE (MTYPE_OSPF_MPLS_TE_LINKPARAMS, lp);
    }

  /* Schedule Opaque-LSA refresh. *//* XXX */

  rc = 0;
/*out:*/
  return rc;
}

static void
ospf_mpls_te_ism_change (struct ospf_interface *oi, int old_state)
{
  struct te_link_subtlv_link_type old_type;
  struct te_link_subtlv_link_id   old_id;
  struct mpls_te_link *lp;
  float fval;
  int i;

  if ((lp = lookup_linkparams_by_ifp (oi->ifp)) == NULL)
    {
      zlog_warn ("ospf_mpls_te_ism_change: Cannot get linkparams from OI(%s)?", IF_NAME (oi));
      goto out;
    }
  if (oi->area == NULL || oi->area->ospf == NULL)
    {
      zlog_warn ("ospf_mpls_te_ism_change: Cannot refer to OSPF from OI(%s)?",
IF_NAME (oi));
      goto out;
    }
#ifdef notyet
  if ((lp->area != NULL
  &&   ! IPV4_ADDR_SAME (&lp->area->area_id, &oi->area->area_id))
  || (lp->area != NULL && oi->area == NULL))
    {
      /* How should we consider this case? */
      zlog_warn ("MPLS-TE: Area for OI(%s) has changed to [%s], flush previous LSAs", IF_NAME (oi), oi->area ? inet_ntoa (oi->area->area_id) : "N/A");
      ospf_mpls_te_lsa_schedule (lp, FLUSH_THIS_LSA);
    }
#endif
  /* Keep Area information in conbination with linkparams. */
  lp->area = oi->area;

  switch (oi->state)
    {
    case ISM_PointToPoint:
    case ISM_DROther:
    case ISM_Backup:
    case ISM_DR:
      old_type = lp->link_type;
      old_id   = lp->link_id;

      set_linkparams_link_type (oi, lp);
      set_linkparams_link_id (oi, lp);

      fval = (float)((oi->ifp->bandwidth ? oi->ifp->bandwidth
                                 : OSPF_DEFAULT_BANDWIDTH) * 1000 / 8);


      
      for (i = 0; i < 8; i++)
	set_linkparams_capability(lp, GTE_SWITCHING_TYPE_PSC1, \
	  GTE_ENCODING_TYPE_ETHERNET, i, fval, MPLS_TE_MINIMUM_BANDWIDTH);
  
      
      
      if ((ntohs (old_type.header.type) != ntohs (lp->link_type.header.type)
      ||   old_type.link_type.value     != lp->link_type.link_type.value)
      ||  (ntohs (old_id.header.type)   != ntohs (lp->link_id.header.type)
      ||   ntohl (old_id.value.s_addr)  != ntohl (lp->link_id.value.s_addr)))
        {
          if (lp->flags & LPFLG_LSA_ENGAGED)
            ospf_mpls_te_lsa_schedule (lp, REFRESH_THIS_LSA);
          else
            ospf_mpls_te_lsa_schedule (lp, REORIGINATE_PER_AREA);
        }
      break;
    default:
      lp->link_type.header.type = htons (0);
      lp->link_id.header.type   = htons (0);

      if (lp->flags & LPFLG_LSA_ENGAGED)
        ospf_mpls_te_lsa_schedule (lp, FLUSH_THIS_LSA);
      break;
    }

out:
  return;
}

static void
ospf_mpls_te_nsm_change (struct ospf_neighbor *nbr, int old_state)
{
  /* So far, nothing to do here. */
  return;
}

/*------------------------------------------------------------------------*
 * Followings are OSPF protocol processing functions for MPLS-TE.
 *------------------------------------------------------------------------*/

static void
build_tlv_header (struct stream *s, struct te_tlv_header *tlvh)
{
  stream_put (s, tlvh, sizeof (struct te_tlv_header));
  return;
}

static void
build_router_tlv (struct stream *s)
{
  struct te_tlv_header *tlvh = &OspfMplsTE.router_addr.header;
  if (ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_link_type (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->link_type.header;
  if (ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_link_id (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->link_id.header;
  if (ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_lclif_ipaddr (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = (struct te_tlv_header *) lp->lclif_ipaddr;
  if (tlvh != NULL && ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_rmtif_ipaddr (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = (struct te_tlv_header *) lp->rmtif_ipaddr;
  if (tlvh != NULL && ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_te_metric (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->te_metric.header;
  if (ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_max_bw (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->max_bw.header;
  if (ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_max_rsv_bw (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->max_rsv_bw.header;
  if (ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_unrsv_bw (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->unrsv_bw.header;
  if (ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

static void
build_link_subtlv_rsc_clsclr (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->rsc_clsclr.header;
  if (ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

/* Build Local/Remote ID Sub-TLV */
static void
build_link_subtlv_lrid (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->lrid.header;
  if (ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

/* Build Protection Sub-TLV */
static void
build_link_subtlv_protection (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->protection.header;
  if (ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

/* Build Capability ID Sub-TLV */
static void
build_link_subtlv_capability (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->capability.header;
  if (ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
}

 /* Build SRLG ID Sub-TLV */
static void
build_link_subtlv_srlg (struct stream *s, struct mpls_te_link *lp)
{
  struct te_tlv_header *tlvh = &lp->srlg.header;
  if (ntohs (tlvh->type) != 0)
    {
      build_tlv_header (s, tlvh);
      stream_put (s, tlvh+1, TLV_BODY_SIZE (tlvh));
    }
  return;
} 
  
  
static void
build_link_tlv (struct stream *s, struct mpls_te_link *lp)
{
  set_linkparams_link_header (lp);
  build_tlv_header (s, &lp->link_header.header);

  build_link_subtlv_link_type (s, lp);
  build_link_subtlv_link_id (s, lp);
  build_link_subtlv_lclif_ipaddr (s, lp);
  build_link_subtlv_rmtif_ipaddr (s, lp);
  build_link_subtlv_te_metric (s, lp);
  build_link_subtlv_max_bw (s, lp);
  build_link_subtlv_max_rsv_bw (s, lp);
  build_link_subtlv_unrsv_bw (s, lp);
  build_link_subtlv_rsc_clsclr (s, lp);
  build_link_subtlv_lrid (s, lp);
  build_link_subtlv_protection (s, lp);
  build_link_subtlv_capability (s, lp);
  build_link_subtlv_srlg (s, lp);
  return;
}

static void
ospf_mpls_te_lsa_body_set (struct stream *s, struct mpls_te_link *lp)
{
  /*
   * The router address TLV is type 1, and ...
   *                                      It must appear in exactly one
   * Traffic Engineering LSA originated by a router.
   */
  build_router_tlv (s);

  /*
   * Only one Link TLV shall be carried in each LSA, allowing for fine
   * granularity changes in topology.
   */
  build_link_tlv (s, lp);
  return;
}

/* Create new opaque-LSA. */
static struct ospf_lsa *
ospf_mpls_te_lsa_new (struct ospf_area *area, struct mpls_te_link *lp)
{
  struct stream *s;
  struct lsa_header *lsah;
  struct ospf_lsa *new = NULL;
  u_char options, lsa_type;
  struct in_addr lsa_id;
  u_int32_t tmp;
  u_int16_t length;

  /* Create a stream for LSA. */
  if ((s = stream_new (OSPF_MAX_LSA_SIZE)) == NULL)
    {
      zlog_warn ("ospf_mpls_te_lsa_new: stream_new() ?");
      goto out;
    }
  lsah = (struct lsa_header *) STREAM_DATA (s);

  options  = LSA_OPTIONS_GET (area);
  options |= LSA_OPTIONS_NSSA_GET (area);
  options |= OSPF_OPTION_O; /* Don't forget this :-) */

  lsa_type = OSPF_OPAQUE_AREA_LSA;
  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, lp->instance);
  lsa_id.s_addr = htonl (tmp);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    zlog_debug ("LSA[Type%d:%s]: Create an Opaque-LSA/MPLS-TE instance", lsa_type, inet_ntoa (lsa_id));

  /* Set opaque-LSA header fields. */
  lsa_header_set (s, options, lsa_type, lsa_id, area->ospf->router_id);

  /* Set opaque-LSA body fields. */
  ospf_mpls_te_lsa_body_set (s, lp);

  /* Set length. */
  length = stream_get_endp (s);
  lsah->length = htons (length);

  /* Now, create an OSPF LSA instance. */
  if ((new = ospf_lsa_new ()) == NULL)
    {
      zlog_warn ("ospf_mpls_te_lsa_new: ospf_lsa_new() ?");
      stream_free (s);
      goto out;
    }
  if ((new->data = ospf_lsa_data_new (length)) == NULL)
    {
      zlog_warn ("ospf_mpls_te_lsa_new: ospf_lsa_data_new() ?");
      ospf_lsa_unlock (&new);
      new = NULL;
      stream_free (s);
      goto out;
    }

  new->area = area;
  SET_FLAG (new->flags, OSPF_LSA_SELF);
  memcpy (new->data, lsah, length);
  stream_free (s);

out:
  return new;
}

static int
ospf_mpls_te_lsa_originate1 (struct ospf_area *area, struct mpls_te_link *lp)
{
  struct ospf_lsa *new;
  int rc = -1;

  /* Create new Opaque-LSA/MPLS-TE instance. */
  if ((new = ospf_mpls_te_lsa_new (area, lp)) == NULL)
    {
      zlog_warn ("ospf_mpls_te_lsa_originate1: ospf_mpls_te_lsa_new() ?");
      goto out;
    }

  /* Install this LSA into LSDB. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
    {
      zlog_warn ("ospf_mpls_te_lsa_originate1: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }

  /* Now this linkparameter entry has associated LSA. */
  lp->flags |= LPFLG_LSA_ENGAGED;

  /* Update new LSA origination count. */
  area->ospf->lsa_originate_count++;

  /* Flood new LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    {
      char area_id[INET_ADDRSTRLEN];
      strcpy (area_id, inet_ntoa (area->area_id));
      zlog_debug ("LSA[Type%d:%s]: Originate Opaque-LSA/MPLS-TE: Area(%s), Link(%s)", new->data->type, inet_ntoa (new->data->id), area_id, lp->ifp->name);
      ospf_lsa_header_dump (new->data);
    }

  rc = 0;
out:
  return rc;
}

static int
ospf_mpls_te_lsa_originate (void *arg)
{
  struct ospf_area *area = (struct ospf_area *) arg;
  struct listnode *node, *nnode;
  struct mpls_te_link *lp;
  int rc = -1;

  if (OspfMplsTE.status == disabled)
    {
      zlog_info ("ospf_mpls_te_lsa_originate: MPLS-TE is disabled now.");
      rc = 0; /* This is not an error case. */
      goto out;
    }

  for (ALL_LIST_ELEMENTS (OspfMplsTE.iflist, node, nnode, lp))
    {
      if (lp->area == NULL)
        continue;
      if (! IPV4_ADDR_SAME (&lp->area->area_id, &area->area_id))
        continue;

      if (lp->flags & LPFLG_LSA_ENGAGED)
        {
          if (lp->flags & LPFLG_LSA_FORCED_REFRESH)
            {
              lp->flags &= ~LPFLG_LSA_FORCED_REFRESH;
              ospf_mpls_te_lsa_schedule (lp, REFRESH_THIS_LSA);
            }
          continue;
        }
      if (! is_mandated_params_set (lp))
        {
          zlog_warn ("ospf_mpls_te_lsa_originate: Link(%s) lacks some mandated MPLS-TE parameters.", lp->ifp ? lp->ifp->name : "?");
          continue;
        }

      /* Ok, let's try to originate an LSA for this area and Link. */
      if (ospf_mpls_te_lsa_originate1 (area, lp) != 0)
        goto out;
    }

  rc = 0;
out:
  return rc;
}

static void
ospf_mpls_te_lsa_refresh (struct ospf_lsa *lsa)
{
  struct mpls_te_link *lp;
  struct ospf_area *area = lsa->area;
  struct ospf_lsa *new = NULL;

  if (OspfMplsTE.status == disabled)
    {
      /*
       * This LSA must have flushed before due to MPLS-TE status change.
       * It seems a slip among routers in the routing domain.
       */
      zlog_info ("ospf_mpls_te_lsa_refresh: MPLS-TE is disabled now.");
      lsa->data->ls_age = htons (OSPF_LSA_MAXAGE); /* Flush it anyway. */
    }

  /* At first, resolve lsa/lp relationship. */
  if ((lp = lookup_linkparams_by_instance (lsa)) == NULL)
    {
      zlog_warn ("ospf_mpls_te_lsa_refresh: Invalid parameter?");
      lsa->data->ls_age = htons (OSPF_LSA_MAXAGE); /* Flush it anyway. */
    }

  /* If the lsa's age reached to MaxAge, start flushing procedure. */
  if (IS_LSA_MAXAGE (lsa))
    {
      lp->flags &= ~LPFLG_LSA_ENGAGED;
      ospf_opaque_lsa_flush_schedule (lsa);
      goto out;
    }

  /* Create new Opaque-LSA/MPLS-TE instance. */
  if ((new = ospf_mpls_te_lsa_new (area, lp)) == NULL)
    {
      zlog_warn ("ospf_mpls_te_lsa_refresh: ospf_mpls_te_lsa_new() ?");
      goto out;
    }
  new->data->ls_seqnum = lsa_seqnum_increment (lsa);

  /* Install this LSA into LSDB. */
  /* Given "lsa" will be freed in the next function. */
  if (ospf_lsa_install (area->ospf, NULL/*oi*/, new) == NULL)
    {
      zlog_warn ("ospf_mpls_te_lsa_refresh: ospf_lsa_install() ?");
      ospf_lsa_unlock (&new);
      goto out;
    }

  /* Flood updated LSA through area. */
  ospf_flood_through_area (area, NULL/*nbr*/, new);

  /* Debug logging. */
  if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
    {
      zlog_debug ("LSA[Type%d:%s]: Refresh Opaque-LSA/MPLS-TE",
		 new->data->type, inet_ntoa (new->data->id));
      ospf_lsa_header_dump (new->data);
    }

out:
  return;
}

static void
ospf_mpls_te_lsa_schedule (struct mpls_te_link *lp,
                           enum sched_opcode opcode)
{
  struct ospf_lsa lsa;
  struct lsa_header lsah;
  u_int32_t tmp;

  memset (&lsa, 0, sizeof (lsa));
  memset (&lsah, 0, sizeof (lsah));

  lsa.area = lp->area;
  lsa.data = &lsah;
  lsah.type = OSPF_OPAQUE_AREA_LSA;
  tmp = SET_OPAQUE_LSID (OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA, lp->instance);
  lsah.id.s_addr = htonl (tmp);

  switch (opcode)
    {
    case REORIGINATE_PER_AREA:
      ospf_opaque_lsa_reoriginate_schedule ((void *) lp->area,
          OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA);
      break;
    case REFRESH_THIS_LSA:
      ospf_opaque_lsa_refresh_schedule (&lsa);
      break;
    case FLUSH_THIS_LSA:
      lp->flags &= ~LPFLG_LSA_ENGAGED;
      ospf_opaque_lsa_flush_schedule (&lsa);
      break;
    default:
      zlog_warn ("ospf_mpls_te_lsa_schedule: Unknown opcode (%u)", opcode);
      break;
    }

  return;
}

/*------------------------------------------------------------------------*
 * Followings are vty session control functions.
 *------------------------------------------------------------------------*/

static u_int16_t
show_vty_router_addr (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_tlv_router_addr *top = (struct te_tlv_router_addr *) tlvh;

  if (vty != NULL)
    vty_out (vty, "  Router-Address: %s%s", inet_ntoa (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Router-Address: %s", inet_ntoa (top->value));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_header (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_tlv_link *top = (struct te_tlv_link *) tlvh;

  if (vty != NULL)
    vty_out (vty, "  Link: %u octets of data%s", ntohs (top->header.length), VTY_NEWLINE);
  else
    zlog_debug ("    Link: %u octets of data", ntohs (top->header.length));

  return TLV_HDR_SIZE;	/* Here is special, not "TLV_SIZE". */
}

static u_int16_t
show_vty_link_subtlv_link_type (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_link_type *top;
  const char *cp = "Unknown";

  top = (struct te_link_subtlv_link_type *) tlvh;
  switch (top->link_type.value)
    {
    case LINK_TYPE_SUBTLV_VALUE_PTP:
      cp = "Point-to-point";
      break;
    case LINK_TYPE_SUBTLV_VALUE_MA:
      cp = "Multiaccess";
      break;
    default:
      break;
    }

  if (vty != NULL)
    vty_out (vty, "  Link-Type: %s (%u)%s", cp, top->link_type.value, VTY_NEWLINE);
  else
    zlog_debug ("    Link-Type: %s (%u)", cp, top->link_type.value);

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_link_id (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_link_id *top;

  top = (struct te_link_subtlv_link_id *) tlvh;
  if (vty != NULL)
    vty_out (vty, "  Link-ID: %s%s", inet_ntoa (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Link-ID: %s", inet_ntoa (top->value));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_lclif_ipaddr (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_lclif_ipaddr *top;
  int i, n;

  top = (struct te_link_subtlv_lclif_ipaddr *) tlvh;
  n = ntohs (tlvh->length) / sizeof (top->value[0]);

  if (vty != NULL)
    vty_out (vty, "  Local Interface IP Address(es): %d%s", n, VTY_NEWLINE);
  else
    zlog_debug ("    Local Interface IP Address(es): %d", n);

  for (i = 0; i < n; i++)
    {
      if (vty != NULL)
        vty_out (vty, "    #%d: %s%s", i, inet_ntoa (top->value[i]), VTY_NEWLINE);
      else
        zlog_debug ("      #%d: %s", i, inet_ntoa (top->value[i]));
    }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_rmtif_ipaddr (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_rmtif_ipaddr *top;
  int i, n;

  top = (struct te_link_subtlv_rmtif_ipaddr *) tlvh;
  n = ntohs (tlvh->length) / sizeof (top->value[0]);
  if (vty != NULL)
    vty_out (vty, "  Remote Interface IP Address(es): %d%s", n, VTY_NEWLINE);
  else
    zlog_debug ("    Remote Interface IP Address(es): %d", n);

  for (i = 0; i < n; i++)
    {
      if (vty != NULL)
        vty_out (vty, "    #%d: %s%s", i, inet_ntoa (top->value[i]), VTY_NEWLINE);
      else
        zlog_debug ("      #%d: %s", i, inet_ntoa (top->value[i]));
    }
  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_te_metric (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_te_metric *top;

  top = (struct te_link_subtlv_te_metric *) tlvh;
  if (vty != NULL)
    vty_out (vty, "  Traffic Engineering Metric: %u%s", (u_int32_t) ntohl (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Traffic Engineering Metric: %u", (u_int32_t) ntohl (top->value));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_max_bw (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_max_bw *top;
  float fval;

  top = (struct te_link_subtlv_max_bw *) tlvh;
  ntohf (&top->value, &fval);

  if (vty != NULL)
    vty_out (vty, "  Maximum Bandwidth: %g (Bytes/sec)%s", fval, VTY_NEWLINE);
  else
    zlog_debug ("    Maximum Bandwidth: %g (Bytes/sec)", fval);

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_max_rsv_bw (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_max_rsv_bw *top;
  float fval;

  top = (struct te_link_subtlv_max_rsv_bw *) tlvh;
  ntohf (&top->value, &fval);

  if (vty != NULL)
    vty_out (vty, "  Maximum Reservable Bandwidth: %g (Bytes/sec)%s", fval, VTY_NEWLINE);
  else
    zlog_debug ("    Maximum Reservable Bandwidth: %g (Bytes/sec)", fval);

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_unrsv_bw (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_unrsv_bw *top;
  float fval;
  int i;

  top = (struct te_link_subtlv_unrsv_bw *) tlvh;
  for (i = 0; i < 8; i++)
    {
      ntohf (&top->value[i], &fval);
      if (vty != NULL)
        vty_out (vty, "  Unreserved Bandwidth (pri %d): %g (Bytes/sec)%s", i, fval, VTY_NEWLINE);
      else
        zlog_debug ("    Unreserved Bandwidth (pri %d): %g (Bytes/sec)", i, fval);
    }

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_rsc_clsclr (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct te_link_subtlv_rsc_clsclr *top;

  top = (struct te_link_subtlv_rsc_clsclr *) tlvh;
  if (vty != NULL)
    vty_out (vty, "  Resource class/color: 0x%x%s", (u_int32_t) ntohl (top->value), VTY_NEWLINE);
  else
    zlog_debug ("    Resource Class/Color: 0x%x", (u_int32_t) ntohl (top->value));

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_unknown_tlv (struct vty *vty, struct te_tlv_header *tlvh)
{
  if (vty != NULL)
    vty_out (vty, "  Unknown TLV: [type(0x%x), length(0x%x)]%s", ntohs (tlvh->type), ntohs (tlvh->length), VTY_NEWLINE);
  else
    zlog_debug ("    Unknown TLV: [type(0x%x), length(0x%x)]", ntohs (tlvh->type), ntohs (tlvh->length));

  return TLV_SIZE (tlvh);
}

/* Get GMPLS Capability description */
const char *
ospf_gmpls_get_capability_switching (int c)
{
  const char *cap = "Unkown";
  
  switch(c)
  {
    case GTE_SWITCHING_TYPE_PSC1:
      cap = "Packet-Switch Capable-1";
      break;
    case GTE_SWITCHING_TYPE_PSC2:
      cap = "Packet-Switch Capable-2";
      break;
    case GTE_SWITCHING_TYPE_PSC3:
      cap = "Packet-Switch Capable-3";
      break;
    case GTE_SWITCHING_TYPE_PSC4:
      cap = "Packet-Switch Capable-4";
      break;
    case GTE_SWITCHING_TYPE_L2SC:
      cap = "Layer-2 Switch Capable";
      break;
    case GTE_SWITCHING_TYPE_TDM:
      cap = "Time-Division-Multiplex Capable";
      break;
    case GTE_SWITCHING_TYPE_LSC:
      cap = "Lambda-Switch Capable";
      break;
    case GTE_SWITCHING_TYPE_FSC:
      cap = "Fiber-Switch Capable";
      break;
    default:
      break;
  }
  return cap;

}

/* Get GMPLS encoding capability string */
const char *
ospf_gmpls_get_capability_encoding (int e)
{
  const char *enc = "Unknown";
  
  switch(e)
  {
    case GTE_ENCODING_TYPE_PACKET:
      enc = "Packet";
      break;
    case GTE_ENCODING_TYPE_ETHERNET:
      enc = "Ethernet";
      break;
    case GTE_ENCODING_TYPE_PDH:
      enc = "ANSI/ETSI PDH";
      break;
    case GTE_ENCODING_TYPE_SDH_SONET:
      enc = "SDH ITU-T G.707";
      break;
    case GTE_ENCODING_TYPE_DWRAPPER:
      enc = "Digital Wrapper";
      break;
    case GTE_ENCODING_TYPE_LAMBDA:
      enc = "Lambda (photonic)";
      break;
    case GTE_ENCODING_TYPE_FIBER:
      enc = "Fiber";
      break;
    case GTE_ENCODING_TYPE_FIBERCHANNEL:
      enc = "FiberChannel";
      break;
    default:
      break;
  }

  return enc;
}



static u_int16_t
show_vty_link_subtlv_capability (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct gte_link_subtlv_capability *top;
  top = (struct gte_link_subtlv_capability *) tlvh;
  int i = 0;
  
  const char *tdm = "Standard";

  if (vty != NULL)
  {
    vty_out (vty, "  GMPLS Switching Capability: %s%s", \
	ospf_gmpls_get_capability_switching(top->capability), VTY_NEWLINE);
    vty_out (vty, "  GMPLS Interface Encoding: %s%s", \
	ospf_gmpls_get_capability_encoding(top->encoding), VTY_NEWLINE);

    for (i = 0; i < 8; i++)
    {
      float bw;
      ntohf(&top->maxbw[i], &bw);

      vty_out (vty, "  GMPLS Maximum LSP Bandwidth (pri %d): %g (bytes/sec)%s", i, \
	  bw, VTY_NEWLINE);
    }

    if (top->capability == (GTE_SWITCHING_TYPE_PSC1 || GTE_SWITCHING_TYPE_PSC2 \
	  || GTE_SWITCHING_TYPE_PSC3 || GTE_SWITCHING_TYPE_PSC4))
    {
      float bw;
      ntohf(&top->psc.minbw,&bw);
      
      vty_out (vty, "   GMPLS Minimum LSP Bandwidth: %g (bytes/sec)%s", bw, VTY_NEWLINE);
      vty_out (vty, "   GMPLS Interface MTU: %u%s", (u_int16_t) htons(top->psc.mtu), VTY_NEWLINE);
    }

    if (top->capability == GTE_SWITCHING_TYPE_TDM)
    {
      float bw;
      ntohf(&top->tdm.minbw, &bw);

      
      switch (top->tdm.indication)
      {
	case GTE_TDM_CAPABILITY_IND_STANDARD:
	  tdm = "Standard";
	  break;
	case GTE_TDM_CAPABILITY_IND_ARBITRARY:
	  tdm = "Arbitrary";
	  break;
	default:
	  break;
      }
	  
      vty_out (vty, "   GMPLS Minimum LSP Bandwidth: %g (bytes/sec)%s", bw, VTY_NEWLINE);
      vty_out (vty, "   GMPLS TDM Indication: %s%s", tdm, VTY_NEWLINE);
    }
  }
  else
  {
    zlog_debug ("    GMPLS Switching Capability: %s", \
	ospf_gmpls_get_capability_switching(top->capability));
    zlog_debug ("    GMPLS Interface Encoding: %s", \
	ospf_gmpls_get_capability_encoding(top->encoding));

    for (i = 0; i < 8; i++)
    {
      float bw;
      ntohf(&top->maxbw[i],&bw);
      
      zlog_debug ("    GMPLS Maximum LSP Bandwidth (pri %d): %g (bytes/sec)", i, \
	  bw);
    }

    if (top->capability == (GTE_SWITCHING_TYPE_PSC1 || GTE_SWITCHING_TYPE_PSC2 \
	  || GTE_SWITCHING_TYPE_PSC3 || GTE_SWITCHING_TYPE_PSC4))
    {
      float bw;
      ntohf(&top->psc.minbw,&bw);
      
      zlog_debug ("     GMPLS Minimum LSP Bandwidth: %g (bytes/sec)", bw);
      zlog_debug ("     GMPLS Interface MTU: %u", (u_int16_t) htons(top->psc.mtu));
    }

    if (top->capability == GTE_SWITCHING_TYPE_TDM)
    {
      float bw;
      ntohf(&top->tdm.minbw, &bw);

      
      switch (top->tdm.indication)
      {
	case GTE_TDM_CAPABILITY_IND_STANDARD:
	  tdm = "Standard";
	  break;
	case GTE_TDM_CAPABILITY_IND_ARBITRARY:
	  tdm = "Arbitrary";
	  break;
	default:
	  break;
      }
	  
      zlog_debug ("     GMPLS Minimum LSP Bandwidth: %g (bytes/sec)", bw);
      zlog_debug ("     GMPLS TDM Indication: %s", tdm);
    }
  }

  return TLV_SIZE (tlvh);
}

static u_int16_t
show_vty_link_subtlv_srlg (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct gte_link_subtlv_srlg *top;
  top = (struct gte_link_subtlv_srlg *) tlvh;
  struct listnode *node, *nnode;
  u_int32_t *data;
  struct list *l;

  l = top->srlg;

  for(ALL_LIST_ELEMENTS(l,node,nnode,data))
  {
    if (vty != NULL)
      vty_out (vty, "    SRLG:%u%s", (u_int32_t) htonl(*data), VTY_NEWLINE);
    else
      vty_out (vty, "    SRLG:%u", (u_int32_t) ntohl(*data));
  }
    
  return TLV_SIZE (tlvh);
}

/* Show GMPLS protection subtlv */
static u_int16_t
show_vty_link_subtlv_protection (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct gte_link_subtlv_protection *top;
  top = (struct gte_link_subtlv_protection *) tlvh;
  const char *cp = "Unknown";
  
  switch(top->value)
  {
    case GTE_PROTECTION_TYPE_EXTRA_TRAFFIC:
     cp = "Extra Traffic";
     break;
    case GTE_PROTECTION_TYPE_UNPROTECTED:
     cp = "Unprotected";
     break;
    case GTE_PROTECTION_TYPE_SHARED:
     cp = "Shared";
     break;
    case GTE_PROTECTION_TYPE_DEDICATED_ONE_TO_ONE:
     cp = "Dedicated 1:1";
     break;
    case GTE_PROTECTION_TYPE_DEDICATED_ONE_PLUS_ONE:
     cp = "Dedicated 1+1";
     break;
    case GTE_PROTECTION_TYPE_ENCHANCED:
     cp = "Enchanced";
     break;
    default:
     break;
  }
  
  if (vty != NULL)
  {
    vty_out (vty, "  GMPLS Protection: %s%s", cp, VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("    GMPLS Protection: %s", cp);
  }

  return TLV_SIZE (tlvh);
}

/* Show GMPLS local/remote ID subtlv */
static u_int16_t
show_vty_link_subtlv_lrid (struct vty *vty, struct te_tlv_header *tlvh)
{
  struct gte_link_subtlv_lrid *top;
  top = (struct gte_link_subtlv_lrid *) tlvh;
  
  if (vty != NULL)
  {
    vty_out (vty, "  GMPLS Local ID: %s%s", inet_ntoa (top->local), VTY_NEWLINE);
    vty_out (vty, "  GMPLS Remote ID: %s%s", inet_ntoa (top->remote), VTY_NEWLINE);
  }
  else
  {
    zlog_debug ("    GMPLS Local ID: %s", inet_ntoa (top->local));
    zlog_debug ("    GMPLS Remote ID: %s", inet_ntoa (top->remote));
  }

  return TLV_SIZE (tlvh);
}


  
static u_int16_t
ospf_mpls_te_show_link_subtlv (struct vty *vty, struct te_tlv_header *tlvh0,
                               u_int16_t subtotal, u_int16_t total)
{
  struct te_tlv_header *tlvh, *next;
  u_int16_t sum = subtotal;

  for (tlvh = tlvh0; sum < total; tlvh = (next ? next : TLV_HDR_NEXT (tlvh)))
    {
      next = NULL;
      switch (ntohs (tlvh->type))
        {
        case TE_LINK_SUBTLV_LINK_TYPE:
          sum += show_vty_link_subtlv_link_type (vty, tlvh);
          break;
        case TE_LINK_SUBTLV_LINK_ID:
          sum += show_vty_link_subtlv_link_id (vty, tlvh);
          break;
        case TE_LINK_SUBTLV_LCLIF_IPADDR:
          sum += show_vty_link_subtlv_lclif_ipaddr (vty, tlvh);
          break;
        case TE_LINK_SUBTLV_RMTIF_IPADDR:
          sum += show_vty_link_subtlv_rmtif_ipaddr (vty, tlvh);
          break;
        case TE_LINK_SUBTLV_TE_METRIC:
          sum += show_vty_link_subtlv_te_metric (vty, tlvh);
          break;
        case TE_LINK_SUBTLV_MAX_BW:
          sum += show_vty_link_subtlv_max_bw (vty, tlvh);
          break;
        case TE_LINK_SUBTLV_MAX_RSV_BW:
          sum += show_vty_link_subtlv_max_rsv_bw (vty, tlvh);
          break;
        case TE_LINK_SUBTLV_UNRSV_BW:
          sum += show_vty_link_subtlv_unrsv_bw (vty, tlvh);
          break;
        case TE_LINK_SUBTLV_RSC_CLSCLR:
          sum += show_vty_link_subtlv_rsc_clsclr (vty, tlvh);
          break;
	case GTE_LINK_SUBTLV_LRID:
	  sum += show_vty_link_subtlv_lrid (vty, tlvh);
	  break;
	case GTE_LINK_SUBTLV_PROTECTION:
	  sum += show_vty_link_subtlv_protection (vty, tlvh);
	  break;
	case GTE_LINK_SUBTLV_CAPABILITY:
	  sum += show_vty_link_subtlv_capability (vty, tlvh);
	  break;
	case GTE_LINK_SUBTLV_SRLG:
	  sum += show_vty_link_subtlv_srlg (vty, tlvh);
	  break;
        default:
          sum += show_vty_unknown_tlv (vty, tlvh);
          break;
        }
    }
  return sum;
}

static void
ospf_mpls_te_show_info (struct vty *vty, struct ospf_lsa *lsa)
{
  struct lsa_header *lsah = (struct lsa_header *) lsa->data;
  struct te_tlv_header *tlvh, *next;
  u_int16_t sum, total;
  u_int16_t (* subfunc)(struct vty *vty, struct te_tlv_header *tlvh,
                        u_int16_t subtotal, u_int16_t total) = NULL;

  sum = 0;
  total = ntohs (lsah->length) - OSPF_LSA_HEADER_SIZE;

  for (tlvh = TLV_HDR_TOP (lsah); sum < total;
			tlvh = (next ? next : TLV_HDR_NEXT (tlvh)))
    {
      if (subfunc != NULL)
        {
          sum = (* subfunc)(vty, tlvh, sum, total);
	  next = (struct te_tlv_header *)((char *) tlvh + sum);
          subfunc = NULL;
          continue;
        }

      next = NULL;
      switch (ntohs (tlvh->type))
        {
        case TE_TLV_ROUTER_ADDR:
          sum += show_vty_router_addr (vty, tlvh);
          break;
        case TE_TLV_LINK:
          sum += show_vty_link_header (vty, tlvh);
	  subfunc = ospf_mpls_te_show_link_subtlv;
	  next = tlvh + 1;
          break;
        default:
          sum += show_vty_unknown_tlv (vty, tlvh);
          break;
        }
    }
  return;
}

static void
ospf_mpls_te_config_write_router (struct vty *vty)
{
  if (OspfMplsTE.status == enabled)
    {
      vty_out (vty, "  mpls-te%s", VTY_NEWLINE);
      vty_out (vty, "  mpls-te router-address %s%s",
               inet_ntoa (OspfMplsTE.router_addr.value), VTY_NEWLINE);
    }
  return;
}

/* Get GMPLS Capability description */
const char *
ospf_gmpls_get_write_if_capability_switching (int c)
{
  const char *cap = "unkown";
  
  switch(c)
  {
    case GTE_SWITCHING_TYPE_PSC1:
      cap = "psc1";
      break;
    case GTE_SWITCHING_TYPE_PSC2:
      cap = "psc2";
      break;
    case GTE_SWITCHING_TYPE_PSC3:
      cap = "psc3";
      break;
    case GTE_SWITCHING_TYPE_PSC4:
      cap = "psc4";
      break;
    case GTE_SWITCHING_TYPE_L2SC:
      cap = "l2sc";
      break;
    case GTE_SWITCHING_TYPE_TDM:
      cap = "tdm";
      break;
    case GTE_SWITCHING_TYPE_LSC:
      cap = "lsc";
      break;
    case GTE_SWITCHING_TYPE_FSC:
      cap = "fsc";
      break;
    default:
      break;
  }
  return cap;

}

/* Get GMPLS encoding capability string */
const char *
ospf_gmpls_get_write_if_capability_encoding (int e)
{
  const char *enc = "unknown";
  
  switch(e)
  {
    case GTE_ENCODING_TYPE_PACKET:
      enc = "packet";
      break;
    case GTE_ENCODING_TYPE_ETHERNET:
      enc = "ethernet";
      break;
    case GTE_ENCODING_TYPE_PDH:
      enc = "pdh";
      break;
    case GTE_ENCODING_TYPE_SDH_SONET:
      enc = "sonet-sdh";
      break;
    case GTE_ENCODING_TYPE_DWRAPPER:
      enc = "dwrapper";
      break;
    case GTE_ENCODING_TYPE_LAMBDA:
      enc = "lambda";
      break;
    case GTE_ENCODING_TYPE_FIBER:
      enc = "fiber";
      break;
    case GTE_ENCODING_TYPE_FIBERCHANNEL:
      enc = "fiberchannel";
      break;
    default:
      break;
  }

  return enc;
}



/* GMPLS capability switching output */
static void
ospf_gmpls_te_config_write_if_cap_switching (struct vty *vty, struct mpls_te_link *lp)
{
  if (htons(lp->capability.header.type) == 0)
    return;

  if (lp->capability.capability != GTE_SWITCHING_TYPE_PSC1)
    vty_out(vty, " gmpls-te link capability switching %s%s", \
	ospf_gmpls_get_write_if_capability_switching(lp->capability.capability), VTY_NEWLINE);
}

/* GMPLS capabality encoding output */
static void
ospf_gmpls_te_config_write_if_cap_encoding (struct vty *vty, struct mpls_te_link *lp)
{
  if (htons(lp->capability.header.type) == 0)
    return;

  if (lp->capability.encoding != GTE_ENCODING_TYPE_ETHERNET)
    vty_out(vty, " gmpls-te link capability encoding %s%s", \
	ospf_gmpls_get_write_if_capability_encoding(lp->capability.encoding), VTY_NEWLINE);
 
}

/*GMPLS if lrid output */
static void 
ospf_gmpls_te_config_write_if_lrid(struct vty *vty,struct mpls_te_link *lp)
{

  if (ntohs(lp->lrid.header.type) == 0)
    return;

  if (inet_ntoa(lp->lrid.local) != "0.0.0.0")
    vty_out (vty, " gmpls-te link local-id %s%s", inet_ntoa(lp->lrid.local), VTY_NEWLINE);

  if (inet_ntoa(lp->lrid.remote) != "0.0.0.0")
    vty_out (vty, " gmpls-te link remote-id %s%s", inet_ntoa(lp->lrid.remote), VTY_NEWLINE);
 
}
      
/*GMPLS if capability output */
static void 
ospf_gmpls_te_config_write_if_capability(struct vty *vty, struct mpls_te_link *lp)
{
  float fval,defbw;
  int i;
  u_int16_t ui;
  
  if (ntohs(lp->capability.header.type) == 0)
    return;
  
  ospf_gmpls_te_config_write_if_cap_switching(vty,lp);
  ospf_gmpls_te_config_write_if_cap_encoding(vty,lp);
  
  defbw = OSPF_DEFAULT_BANDWIDTH * 1000 / 8;
  
  for (i = 0; i < 8; i++)
  {
    ntohf(&lp->capability.maxbw[i], &fval);
    if (fval != defbw)
      vty_out(vty, " gmpls-te link capability max-lsp-bw %d %g%s", i, fval, VTY_NEWLINE);
  }

  
  if (lp->capability.capability == (GTE_SWITCHING_TYPE_PSC1 || \
	      GTE_SWITCHING_TYPE_PSC2 || GTE_SWITCHING_TYPE_PSC3 || \
	      GTE_SWITCHING_TYPE_PSC4))
  {
    ntohf(&lp->capability.psc.minbw, &fval);
    if(fval != MPLS_TE_MINIMUM_BANDWIDTH)
      vty_out(vty, " gmpls-te link capability min-lsp-bw %g%s", fval, VTY_NEWLINE);
  
    ui = ntohs(lp->capability.psc.mtu);
    if (ui != lp->ifp->mtu)
      vty_out(vty, " gmpls-te link capability mtu %u%s", ui, VTY_NEWLINE);
  }

  if (lp->capability.capability == GTE_SWITCHING_TYPE_TDM)
  {
    ntohf(&lp->capability.tdm.minbw, &fval);
  
    if (lp->capability.tdm.indication != GTE_TDM_CAPABILITY_IND_STANDARD)
      vty_out(vty, " gmpls-te link capability indication arbitrary%s", VTY_NEWLINE);

  }
}
      
/*GMPLS if protection output */
static void 
ospf_gmpls_te_config_write_if_protection(struct vty *vty,struct mpls_te_link *lp)
{
  if (ntohs(lp->protection.header.type) == 0)
    return;

  const char *prot = "unknown";

  switch(lp->protection.value)
  {
    case GTE_PROTECTION_TYPE_EXTRA_TRAFFIC:
     prot="extra-traffic";
     break;
    case GTE_PROTECTION_TYPE_UNPROTECTED:
     prot="unprotected";
     break;
    case GTE_PROTECTION_TYPE_SHARED:
     prot="shared";
     break;
    case GTE_PROTECTION_TYPE_DEDICATED_ONE_TO_ONE:
     prot="dedicated one-to-one";
     break;
    case GTE_PROTECTION_TYPE_DEDICATED_ONE_PLUS_ONE:
     prot="dedicated one-plus-one";
     break;
    case GTE_PROTECTION_TYPE_ENCHANCED:
     prot="enchanced";
     break;
    default:
     break;
  }
  
  vty_out(vty, " gmpls-te link protection %s%s", prot, VTY_NEWLINE);
}
      
/*GMPLS if srlg output */
static void 
ospf_gmpls_te_config_write_if_srlg(struct vty *vty,struct mpls_te_link *lp)
{
  struct listnode *node,*nnode;
  u_int32_t *risk;
  
  if (ntohs(lp->srlg.header.type) == 0)
    return;

  for(ALL_LIST_ELEMENTS(lp->srlg.srlg, node, nnode, risk))
    vty_out(vty, " gmpls-te link srlg %d%s", *risk, VTY_NEWLINE);
}
      
/*GMPLS if output */
static void 
ospf_gmpls_te_config_write_if (struct vty *vty, struct interface *ifp)
{
  struct mpls_te_link *lp;

  if ((OspfMplsTE.status == enabled)
  &&  (! if_is_loopback (ifp) && if_is_up (ifp) && ospf_oi_count (ifp) > 0)
  &&  ((lp = lookup_linkparams_by_ifp (ifp)) != NULL))
    {
      ospf_gmpls_te_config_write_if_lrid(vty,lp);
      ospf_gmpls_te_config_write_if_capability(vty, lp);
      ospf_gmpls_te_config_write_if_protection(vty, lp);
      ospf_gmpls_te_config_write_if_srlg(vty,lp);
    }
}

static void
ospf_mpls_te_config_write_if (struct vty *vty, struct interface *ifp)
{
  struct mpls_te_link *lp;

  if ((OspfMplsTE.status == enabled)
  &&  (! if_is_loopback (ifp) && if_is_up (ifp) && ospf_oi_count (ifp) > 0)
  &&  ((lp = lookup_linkparams_by_ifp (ifp)) != NULL))
    {
      float fval;
      int i;

      vty_out (vty, " mpls-te link metric %u%s",
               (u_int32_t) ntohl (lp->te_metric.value), VTY_NEWLINE);

      ntohf (&lp->max_bw.value, &fval);
      if (fval >= MPLS_TE_MINIMUM_BANDWIDTH)
        vty_out (vty, " mpls-te link max-bw %g%s", fval, VTY_NEWLINE);

      ntohf (&lp->max_rsv_bw.value, &fval);
      if (fval >= MPLS_TE_MINIMUM_BANDWIDTH)
        vty_out (vty, " mpls-te link max-rsv-bw %g%s", fval, VTY_NEWLINE);

      for (i = 0; i < 8; i++)
        {
          ntohf (&lp->unrsv_bw.value[i], &fval);
          if (fval >= MPLS_TE_MINIMUM_BANDWIDTH)
            vty_out (vty, " mpls-te link unrsv-bw %d %g%s",
                     i, fval, VTY_NEWLINE);
        }

      vty_out (vty, " mpls-te link rsc-clsclr 0x%x%s",
               (u_int32_t) ntohl (lp->rsc_clsclr.value), VTY_NEWLINE);
      
      /* GMPLS IF output */
      ospf_gmpls_te_config_write_if (vty, ifp);

    }
  return;
}

/*------------------------------------------------------------------------*
 * Followings are vty command functions.
 *------------------------------------------------------------------------*/

DEFUN (mpls_te,
       mpls_te_cmd,
       "mpls-te",
       "Configure MPLS-TE parameters\n"
       "Enable the MPLS-TE functionality\n")
{
  struct listnode *node, *nnode;
  struct mpls_te_link *lp;

  if (OspfMplsTE.status == enabled)
    return CMD_SUCCESS;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("MPLS-TE: OFF -> ON");

  OspfMplsTE.status = enabled;

  /*
   * Following code is intended to handle two cases;
   *
   * 1) MPLS-TE was disabled at startup time, but now become enabled.
   * 2) MPLS-TE was once enabled then disabled, and now enabled again.
   */
  for (ALL_LIST_ELEMENTS (OspfMplsTE.iflist, node, nnode, lp))
    initialize_linkparams (lp);

  ospf_mpls_te_foreach_area (ospf_mpls_te_lsa_schedule, REORIGINATE_PER_AREA);

  return CMD_SUCCESS;
}

ALIAS (mpls_te,
       mpls_te_on_cmd,
       "mpls-te on",
       "Configure MPLS-TE parameters\n"
       "Enable the MPLS-TE functionality\n")

DEFUN (no_mpls_te,
       no_mpls_te_cmd,
       "no mpls-te",
       NO_STR
       "Configure MPLS-TE parameters\n"
       "Disable the MPLS-TE functionality\n")
{
  struct listnode *node, *nnode;
  struct mpls_te_link *lp;

  if (OspfMplsTE.status == disabled)
    return CMD_SUCCESS;

  if (IS_DEBUG_OSPF_EVENT)
    zlog_debug ("MPLS-TE: ON -> OFF");

  OspfMplsTE.status = disabled;

  for (ALL_LIST_ELEMENTS (OspfMplsTE.iflist, node, nnode, lp))
    if (lp->area != NULL)
      if (lp->flags & LPFLG_LSA_ENGAGED)
        ospf_mpls_te_lsa_schedule (lp, FLUSH_THIS_LSA);

  return CMD_SUCCESS;
}

DEFUN (mpls_te_router_addr,
       mpls_te_router_addr_cmd,
       "mpls-te router-address A.B.C.D",
       "MPLS-TE specific commands\n"
       "Stable IP address of the advertising router\n"
       "MPLS-TE router address in IPv4 address format\n")
{
  struct te_tlv_router_addr *ra = &OspfMplsTE.router_addr;
  struct in_addr value;

  if (! inet_aton (argv[0], &value))
    {
      vty_out (vty, "Please specify Router-Addr by A.B.C.D%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (ntohs (ra->header.type) == 0
      || ntohl (ra->value.s_addr) != ntohl (value.s_addr))
    {
      struct listnode *node, *nnode;
      struct mpls_te_link *lp;
      int need_to_reoriginate = 0;

      set_mpls_te_router_addr (value);

      if (OspfMplsTE.status == disabled)
        goto out;

      for (ALL_LIST_ELEMENTS (OspfMplsTE.iflist, node, nnode, lp))
        {
          if (lp->area == NULL)
            continue;

          if ((lp->flags & LPFLG_LSA_ENGAGED) == 0)
            {
              need_to_reoriginate = 1;
              break;
            }
        }
      
      for (ALL_LIST_ELEMENTS (OspfMplsTE.iflist, node, nnode, lp))
        {
          if (lp->area == NULL)
            continue;

          if (need_to_reoriginate)
            lp->flags |= LPFLG_LSA_FORCED_REFRESH;
          else
            ospf_mpls_te_lsa_schedule (lp, REFRESH_THIS_LSA);
        }

      if (need_to_reoriginate)
        ospf_mpls_te_foreach_area (
            ospf_mpls_te_lsa_schedule, REORIGINATE_PER_AREA);
    }
out:
  return CMD_SUCCESS;
}

DEFUN (mpls_te_link_metric,
       mpls_te_link_metric_cmd,
       "mpls-te link metric <0-4294967295>",
       "MPLS-TE specific commands\n"
       "Configure MPLS-TE link parameters\n"
       "Link metric for MPLS-TE purpose\n"
       "Metric\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  u_int32_t value;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "mpls_te_link_metric: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  value = strtoul (argv[0], NULL, 10);

  if (ntohs (lp->te_metric.header.type) == 0
  ||  ntohl (lp->te_metric.value) != value)
    {
      set_linkparams_te_metric (lp, value);

      if (OspfMplsTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_ENGAGED)
              ospf_mpls_te_lsa_schedule (lp, REFRESH_THIS_LSA);
            else
              ospf_mpls_te_lsa_schedule (lp, REORIGINATE_PER_AREA);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (mpls_te_link_maxbw,
       mpls_te_link_maxbw_cmd,
       "mpls-te link max-bw BANDWIDTH",
       "MPLS-TE specific commands\n"
       "Configure MPLS-TE link parameters\n"
       "Maximum bandwidth that can be used\n"
       "Bytes/second (IEEE floating point format)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  float f1, f2;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "mpls_te_link_maxbw: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ntohf (&lp->max_bw.value, &f1);
  if (sscanf (argv[0], "%g", &f2) != 1)
    {
      vty_out (vty, "mpls_te_link_maxbw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (ntohs (lp->max_bw.header.type) == 0
  ||  f1 != f2)
    {
      set_linkparams_max_bw (lp, &f2);

      if (OspfMplsTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_ENGAGED)
              ospf_mpls_te_lsa_schedule (lp, REFRESH_THIS_LSA);
            else
              ospf_mpls_te_lsa_schedule (lp, REORIGINATE_PER_AREA);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (mpls_te_link_max_rsv_bw,
       mpls_te_link_max_rsv_bw_cmd,
       "mpls-te link max-rsv-bw BANDWIDTH",
       "MPLS-TE specific commands\n"
       "Configure MPLS-TE link parameters\n"
       "Maximum bandwidth that may be reserved\n"
       "Bytes/second (IEEE floating point format)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  float f1, f2;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "mpls_te_link_max_rsv_bw: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ntohf (&lp->max_rsv_bw.value, &f1);
  if (sscanf (argv[0], "%g", &f2) != 1)
    {
      vty_out (vty, "mpls_te_link_max_rsv_bw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (ntohs (lp->max_rsv_bw.header.type) == 0
  ||  f1 != f2)
    {
      set_linkparams_max_rsv_bw (lp, &f2);

      if (OspfMplsTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_ENGAGED)
              ospf_mpls_te_lsa_schedule (lp, REFRESH_THIS_LSA);
            else
              ospf_mpls_te_lsa_schedule (lp, REORIGINATE_PER_AREA);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (mpls_te_link_unrsv_bw,
       mpls_te_link_unrsv_bw_cmd,
       "mpls-te link unrsv-bw <0-7> BANDWIDTH",
       "MPLS-TE specific commands\n"
       "Configure MPLS-TE link parameters\n"
       "Unreserved bandwidth at each priority level\n"
       "Priority\n"
       "Bytes/second (IEEE floating point format)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  int priority;
  float f1, f2;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "mpls_te_link_unrsv_bw: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* We don't have to consider about range check here. */
  if (sscanf (argv[0], "%d", &priority) != 1)
    {
      vty_out (vty, "mpls_te_link_unrsv_bw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }

  ntohf (&lp->unrsv_bw.value [priority], &f1);
  if (sscanf (argv[1], "%g", &f2) != 1)
    {
      vty_out (vty, "mpls_te_link_unrsv_bw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (ntohs (lp->unrsv_bw.header.type) == 0
  ||  f1 != f2)
    {
      set_linkparams_unrsv_bw (lp, priority, &f2);

      if (OspfMplsTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_ENGAGED)
              ospf_mpls_te_lsa_schedule (lp, REFRESH_THIS_LSA);
            else
              ospf_mpls_te_lsa_schedule (lp, REORIGINATE_PER_AREA);
          }
    }
  return CMD_SUCCESS;
}

/* LSA update function if one link parameter changes */
static void
ospf_mpls_te_lsa_update (struct mpls_te_link *lp)
{
  if (OspfMplsTE.status == enabled)
    if (lp->area != NULL)
    {
      if (lp->flags & LPFLG_LSA_ENGAGED)
        ospf_mpls_te_lsa_schedule (lp, REFRESH_THIS_LSA);
      else
        ospf_mpls_te_lsa_schedule (lp, REORIGINATE_PER_AREA);
    }
}

DEFUN (gmpls_te_link_capability,
       gmpls_te_link_capability_switching_cmd,
       "gmpls-te link capability switching (psc1|psc2|psc3|psc4|l2sc|tdm|lsc|fsc)",
       "GMPLS specific commands\n"
       "Configure GMPLS link parameters\n"
       "Configure GMPLS link capability\n"
       "Interface switching capability\n"
       "Packet-Switch Capable-1\n"
       "Packet-Switch Capable-2\n"
       "Packet-Switch Capable-3\n"
       "Packet-Switch Capable-4\n"
       "Layer-2 Switch Capable\n"
       "Time-Division-Multiplex Capable\n"
       "Lambda-Switch Capable\n"
       "Fiber-Switch Capable\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  u_char cap;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "gmpls_link_capability: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  if (strncmp(argv[0], "psc1", 4) == 0)
    cap = GTE_SWITCHING_TYPE_PSC1;
  else if (strncmp(argv[0], "psc2", 4) == 0)
    cap = GTE_SWITCHING_TYPE_PSC2;
  else if (strncmp(argv[0], "psc3", 4) == 0)
    cap = GTE_SWITCHING_TYPE_PSC3;
  else if (strncmp(argv[0], "psc4", 4) == 0)
    cap = GTE_SWITCHING_TYPE_PSC4;
  else if (strncmp(argv[0], "l2", 2) == 0)
    cap = GTE_SWITCHING_TYPE_L2SC;
  else if (strncmp(argv[0], "t", 1) == 0)
    cap = GTE_SWITCHING_TYPE_TDM;
  else if (strncmp(argv[0], "ls", 2) == 0)
    cap = GTE_SWITCHING_TYPE_LSC;
  else if (strncmp(argv[0], "f", 1) == 0)
    cap = GTE_SWITCHING_TYPE_FSC;
  else return CMD_WARNING;

  if (ntohs (lp->capability.header.type) == 0)
  {
    set_linkparams_capability_init(lp);
    set_linkparams_capability_cap (lp, cap);

    ospf_mpls_te_lsa_update (lp);
  }
  else if (lp->capability.capability != cap)
  {
    set_linkparams_capability_cap (lp, cap);
    ospf_mpls_te_lsa_update (lp);
  }
  return CMD_SUCCESS;
}  

/* GMPLS encoding setting */
DEFUN (gmpls_te_link_capability_encoding,
       gmpls_te_link_capability_encoding_cmd,
       "gmpls-te link capability encoding (packet|ethernet|pdh|sonet-sdh|dwrapper|lambda|fiber|fiberchannel)",
       "GMPLS specific commands\n"
       "Configure GMPLS link parameters\n"
       "Configure GMPLS link capability\n"
       "Interface encoding\n"
       "Packet encoding\n"
       "Ethernet encoding\n"
       "ANSI/ETSI PDH\n"
       "SDH ITU-T G.707 / SONET ANSI T1.105\n"
       "Digital Wrapper\n"
       "Lambda (photonic)\n"
       "Fiber\n"
       "FiberChannel\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  u_char enc;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "gmpls_link_capability_encoding: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  if (strncmp(argv[0], "pa", 2) == 0)
    enc = GTE_ENCODING_TYPE_PACKET;
  else if (strncmp(argv[0], "et", 2) == 0)
    enc = GTE_ENCODING_TYPE_ETHERNET;
  else if (strncmp(argv[0], "pd", 2) == 0)
    enc = GTE_ENCODING_TYPE_PDH;
  else if (strncmp(argv[0], "s", 1) == 0)
    enc = GTE_ENCODING_TYPE_SDH_SONET;
  else if (strncmp(argv[0], "d", 1) == 0)
    enc = GTE_ENCODING_TYPE_DWRAPPER;
  else if (strncmp(argv[0], "l", 1) == 0)
    enc = GTE_ENCODING_TYPE_LAMBDA;
  else if (strncmp(argv[0], "fiberc", 6) == 0)
    enc = GTE_ENCODING_TYPE_FIBERCHANNEL;
  else if (strncmp(argv[0], "f", 1) == 0)
    enc = GTE_ENCODING_TYPE_FIBER;
  else return CMD_WARNING;

  if (ntohs (lp->capability.header.type) == 0)
  {
    set_linkparams_capability_init(lp);
    set_linkparams_capability_encoding(lp,enc);
    
    ospf_mpls_te_lsa_update(lp);
    
  }
  else if (lp->capability.encoding != enc)
  {
    set_linkparams_capability_encoding (lp, enc);
    ospf_mpls_te_lsa_update(lp);  
  }
      
  return CMD_SUCCESS;
}
  
/* GMPLS Maximum LSP bandwidth setting */
DEFUN (gmpls_te_link_capability_maxbw,
       gmpls_te_link_capability_maxbw_cmd,
       "gmpls-te link capability max-lsp-bw <0-7> BANDWIDTH",
       "GMPLS specific commands\n"
       "Configure GMPLS link parameters\n"
       "Configure GMPLS link capability\n"
       "Maximum LSP bandwidth at each priority level\n"
       "Priority\n"
       "Bytes/second (IEEE floating point format)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  float f1,f2;
  int priority;
  
  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "gmpls_link_capability_maxbw: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  
  if (sscanf (argv[0], "%d", &priority) != 1)
  {
    vty_out (vty, "gmpls_te_link_capability_maxbw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

    
  if (sscanf (argv[1], "%g", &f2) != 1)
  {
    vty_out (vty, "gmpls_te_link_capability_maxbw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }



  if (ntohs (lp->capability.header.type) == 0)
  {
    set_linkparams_capability_init(lp);
    set_linkparams_capability_maxbw(lp,priority,f2);
    
    ospf_mpls_te_lsa_update(lp);
    
  }
  else 
  {
    ntohf (&lp->capability.maxbw[priority], &f1);
    
    if (f1 != f2)
    {
      set_linkparams_capability_maxbw(lp, priority, f2);
      ospf_mpls_te_lsa_update(lp);  
    }
  }
      
  return CMD_SUCCESS;
}
/* GMPLS Minimum LSP bandwidth setting */
DEFUN (gmpls_te_link_capability_minbw,
       gmpls_te_link_capability_minbw_cmd,
       "gmpls-te link capability min-lsp-bw BANDWIDTH",
       "GMPLS specific commands\n"
       "Configure GMPLS link parameters\n"
       "Configure GMPLS link capability\n"
       "Minimum LSP bandwidth\n"
       "Bytes/second (IEEE floating point format)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  float f1,f2;
  
  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "gmpls_link_capability_maxbw: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  
  if (sscanf (argv[0], "%g", &f2) != 1)
  {
    vty_out (vty, "gmpls_te_link_capability_maxbw: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }



  if (ntohs (lp->capability.header.type) == 0)
  {
    set_linkparams_capability_init(lp);
    set_linkparams_capability_minbw(lp,GTE_SWITCHING_TYPE_PSC1,f2);
    
    ospf_mpls_te_lsa_update(lp);
    
  }
  else 
  {
    if (lp->capability.capability != (GTE_SWITCHING_TYPE_PSC1 || \
	  GTE_SWITCHING_TYPE_PSC2 || GTE_SWITCHING_TYPE_PSC3 || GTE_SWITCHING_TYPE_PSC4 || \
	  GTE_SWITCHING_TYPE_TDM))
    {
       vty_out (vty, "Wrong switching type. Must be PSC1, PSC2, PSC3, PSC4 or TDM%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
 
    if (lp->capability.capability == GTE_SWITCHING_TYPE_TDM)
    {
      ntohf (&lp->capability.tdm.minbw, &f1);
    } 
    else
    {
      ntohf (&lp->capability.psc.minbw, &f1);
    }
    
    if (f1 != f2)
    {
      set_linkparams_capability_minbw(lp,lp->capability.capability, f2);
      ospf_mpls_te_lsa_update(lp);  
    }
  }
      
  return CMD_SUCCESS;
}


/* GMPLS Interface MTU setting */
DEFUN (gmpls_te_link_capability_mtu,
       gmpls_te_link_capability_mtu_cmd,
       "gmpls-te link capability mtu <40-65535>",
       "GMPLS specific commands\n"
       "Configure GMPLS link parameters\n"
       "Configure GMPLS link capability\n"
       "Interface MTU (applicable only to PSCx)\n"
       "Bytes\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  int mtu;
  
  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "gmpls_link_capability_mtu: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  
  if (sscanf (argv[0], "%d", &mtu) != 1)
  {
    vty_out (vty, "gmpls_te_link_capability_mtu: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }


  if (ntohs (lp->capability.header.type) == 0)
  {
    set_linkparams_capability_init(lp);
    set_linkparams_capability_mtu(lp, mtu);
    
    ospf_mpls_te_lsa_update(lp);
    
  }
  else 
  {
    if (lp->capability.capability != (GTE_SWITCHING_TYPE_PSC1 || GTE_SWITCHING_TYPE_PSC2 || GTE_SWITCHING_TYPE_PSC3 || GTE_SWITCHING_TYPE_PSC4))
    {
       vty_out (vty, "Wrong switching type. Must be PSC1, PSC2, PSC3 or PSC4%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
 
    if (mtu != htons(lp->capability.psc.mtu))
    {
      set_linkparams_capability_mtu(lp,mtu);
      ospf_mpls_te_lsa_update(lp);  
    }
  }
      
  return CMD_SUCCESS;
}

/* GMPLS Indication setting */
DEFUN (gmpls_te_link_capability_indication,
       gmpls_te_link_capability_indication_cmd,
       "gmpls-te link capability indication (standard|arbitrary)",
       "GMPLS specific commands\n"
       "Configure GMPLS link parameters\n"
       "Configure GMPLS link capability\n"
       "Interface indication (applicable only to SONET/SDH)\n"
       "Standard SONET/SDH\n"
       "Arbitrary SONET/SDH\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  u_char ind;
  
  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "gmpls_link_capability_mtu: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  
  if (strncmp(argv[0],"a",1) == 0)
    ind = 1;
  else if (strncmp(argv[0],"s",1) == 0)
    ind = 0;
  else return CMD_WARNING; 
    
  if (ntohs (lp->capability.header.type) == 0)
  {
    set_linkparams_capability_init(lp);
    set_linkparams_capability_cap(lp, GTE_SWITCHING_TYPE_TDM);
    set_linkparams_capability_indication(lp, ind);
    
    ospf_mpls_te_lsa_update(lp);
    
  }
  else 
  {
    if (lp->capability.capability != GTE_SWITCHING_TYPE_TDM)
    {
       vty_out (vty, "Wrong switching type. Must be TDM%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
 
    if (ind != lp->capability.tdm.indication)
    {
      set_linkparams_capability_indication(lp,ind);
      ospf_mpls_te_lsa_update(lp);  
    }
  }
      
  return CMD_SUCCESS;
}

/* GMPLS Protection setting */
DEFUN (gmpls_te_link_protection,
       gmpls_te_link_protection_cmd,
       "gmpls-te link protection (extra-traffic|unprotected|shared|enchanced)",
       "GMPLS specific commands\n"
       "Configure GMPLS link parameters\n"
       "Interface protection level\n"
       "Extra-traffic link\n"
       "Unprotected link\n"
       "Shared protection\n"
       "Enchanced protection (e.g. BLSR/MS-SPRING)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  u_char prot;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "gmpls_link_protection: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  
  if (strncmp(argv[0],"ex",2))
    prot = GTE_PROTECTION_TYPE_EXTRA_TRAFFIC;
  else if (strncmp(argv[0],"u",1))
    prot = GTE_PROTECTION_TYPE_UNPROTECTED;
  else if (strncmp(argv[0],"s",1))
    prot = GTE_PROTECTION_TYPE_SHARED;
  else if (strncmp(argv[0],"e",1))
    prot = GTE_PROTECTION_TYPE_ENCHANCED;
  else if (strncmp(argv[0],"d",1))
    {
      if (strncmp(argv[1],"one-t",5))
        prot = GTE_PROTECTION_TYPE_DEDICATED_ONE_TO_ONE;
      else if (strncmp(argv[1],"one-p",5))
        prot = GTE_PROTECTION_TYPE_DEDICATED_ONE_PLUS_ONE;
    }
  else return CMD_WARNING;

  if (ntohs (lp->capability.header.type) == 0)
  {
    set_linkparams_capability_init(lp);
    set_linkparams_protection(lp,prot);
    ospf_mpls_te_lsa_update(lp);
  }
  else
  {
    set_linkparams_protection(lp,prot);
    ospf_mpls_te_lsa_update(lp);
  }

  return CMD_SUCCESS;
}

/* GMPLS dedicated protection setting */
ALIAS (gmpls_te_link_protection,
       gmpls_te_link_protection_dedicated_cmd,
       "gmpls-te link protection dedicated (one-to-one|one-plus-one)",
       "GMPLS specific commands\n"
       "Configure GMPLS link parameters\n"
       "Interface protection level\n"
       "Dedicated protection\n"
       "1:1 protection\n"
       "1+1 protection\n")

/* GMPLS lrid setting */
DEFUN (gmpls_te_link_lrid,
       gmpls_te_link_lrid_cmd,
       "gmpls-te link (local-id|remote-id) A.B.C.D",
       "GMPLS specific commands\n"
       "Configure GMPLS link parameters\n"
       "Local link ID\n"
       "Remote link ID\n"
       "ID\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  struct in_addr value; 

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "gmpls_link_lrid: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (! inet_aton(argv[1], &value))
  {
    vty_out (vty, "Please specify Router-Addr by A.B.C.D%s", VTY_NEWLINE);
      return CMD_WARNING;
  }

  if (strncmp(argv[0],"l",1))
    set_linkparams_lrid_local(lp,value);
  else if (strncmp(argv[0],"r",1))
    set_linkparams_lrid_remote(lp,value);
  else return CMD_WARNING;

  return CMD_SUCCESS;
}

/* GMPLS srlg setting */
DEFUN (gmpls_te_link_srlg,
       gmpls_te_link_srlg_cmd,
       "gmpls-te link srlg <0-4294967295>",
       "GMPLS specific commands\n"
       "Configure GMPLS link parameters\n"
       "Shared Risk Link Group configuration\n"
       "SRLG number\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  u_int32_t risk;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
  {
    vty_out (vty, "gmpls_link_slrg: Something wrong!%s", VTY_NEWLINE);
    return CMD_WARNING;
  }

  if (sscanf(argv[0],"%u",&risk) != 1)
  {
    vty_out (vty, "gmpls_te_link_capability_mtu: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
    return CMD_WARNING;
  }

  set_linkparams_srlg(lp,risk);
  return CMD_SUCCESS;
}

DEFUN (mpls_te_link_rsc_clsclr,
       mpls_te_link_rsc_clsclr_cmd,
       "mpls-te link rsc-clsclr BITPATTERN",
       "MPLS-TE specific commands\n"
       "Configure MPLS-TE link parameters\n"
       "Administrative group membership\n"
       "32-bit Hexadecimal value (ex. 0xa1)\n")
{
  struct interface *ifp = (struct interface *) vty->index;
  struct mpls_te_link *lp;
  unsigned long value;

  if ((lp = lookup_linkparams_by_ifp (ifp)) == NULL)
    {
      vty_out (vty, "mpls_te_link_rsc_clsclr: Something wrong!%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (sscanf (argv[0], "0x%lx", &value) != 1)
    {
      vty_out (vty, "mpls_te_link_rsc_clsclr: fscanf: %s%s", safe_strerror (errno), VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (ntohs (lp->rsc_clsclr.header.type) == 0
  ||  ntohl (lp->rsc_clsclr.value) != value)
    {
      set_linkparams_rsc_clsclr (lp, value);

      if (OspfMplsTE.status == enabled)
        if (lp->area != NULL)
          {
            if (lp->flags & LPFLG_LSA_ENGAGED)
              ospf_mpls_te_lsa_schedule (lp, REFRESH_THIS_LSA);
            else
              ospf_mpls_te_lsa_schedule (lp, REORIGINATE_PER_AREA);
          }
    }
  return CMD_SUCCESS;
}

DEFUN (show_mpls_te_router,
       show_mpls_te_router_cmd,
       "show mpls-te router",
       SHOW_STR
       "MPLS-TE information\n"
       "Router information\n")
{
  if (OspfMplsTE.status == enabled)
    {
      vty_out (vty, "--- MPLS-TE router parameters ---%s",
               VTY_NEWLINE);

      if (ntohs (OspfMplsTE.router_addr.header.type) != 0)
        show_vty_router_addr (vty, &OspfMplsTE.router_addr.header);
      else if (vty != NULL)
        vty_out (vty, "  N/A%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

static void
show_mpls_te_link_sub (struct vty *vty, struct interface *ifp)
{
  struct mpls_te_link *lp;
  struct te_tlv_header *tlvh;

  if ((OspfMplsTE.status == enabled)
  &&  (! if_is_loopback (ifp) && if_is_up (ifp) && ospf_oi_count (ifp) > 0)
  &&  ((lp = lookup_linkparams_by_ifp (ifp)) != NULL))
    {
      vty_out (vty, "-- MPLS-TE link parameters for %s --%s",
               ifp->name, VTY_NEWLINE);

      show_vty_link_subtlv_link_type (vty, &lp->link_type.header);
      show_vty_link_subtlv_link_id (vty, &lp->link_id.header);

      if ((tlvh = (struct te_tlv_header *) lp->lclif_ipaddr) != NULL)
        show_vty_link_subtlv_lclif_ipaddr (vty, tlvh);
      if ((tlvh = (struct te_tlv_header *) lp->rmtif_ipaddr) != NULL)
        show_vty_link_subtlv_rmtif_ipaddr (vty, tlvh);

      show_vty_link_subtlv_te_metric (vty, &lp->te_metric.header);

      show_vty_link_subtlv_max_bw (vty, &lp->max_bw.header);
      show_vty_link_subtlv_max_rsv_bw (vty, &lp->max_rsv_bw.header);
      show_vty_link_subtlv_unrsv_bw (vty, &lp->unrsv_bw.header);
      show_vty_link_subtlv_rsc_clsclr (vty, &lp->rsc_clsclr.header);
    }
  else
    {
      vty_out (vty, "  %s: MPLS-TE is disabled on this interface%s",
               ifp->name, VTY_NEWLINE);
    }

  return;
}

DEFUN (show_mpls_te_link,
       show_mpls_te_link_cmd,
       "show mpls-te interface [INTERFACE]",
       SHOW_STR
       "MPLS-TE information\n"
       "Interface information\n"
       "Interface name\n")
{
  struct interface *ifp;
  struct listnode *node, *nnode;

  /* Show All Interfaces. */
  if (argc == 0)
    {
      for (ALL_LIST_ELEMENTS (iflist, node, nnode, ifp))
        show_mpls_te_link_sub (vty, ifp);
    }
  /* Interface name is specified. */
  else
    {
      if ((ifp = if_lookup_by_name (argv[0])) == NULL)
        vty_out (vty, "No such interface name%s", VTY_NEWLINE);
      else
        show_mpls_te_link_sub (vty, ifp);
    }

  return CMD_SUCCESS;
}

static void
ospf_mpls_te_register_vty (void)
{
  install_element (VIEW_NODE, &show_mpls_te_router_cmd);
  install_element (VIEW_NODE, &show_mpls_te_link_cmd);
  install_element (ENABLE_NODE, &show_mpls_te_router_cmd);
  install_element (ENABLE_NODE, &show_mpls_te_link_cmd);

  install_element (OSPF_NODE, &mpls_te_cmd);
  install_element (OSPF_NODE, &no_mpls_te_cmd);
  install_element (OSPF_NODE, &mpls_te_on_cmd);
  install_element (OSPF_NODE, &mpls_te_router_addr_cmd);

  install_element (INTERFACE_NODE, &mpls_te_link_metric_cmd);
  install_element (INTERFACE_NODE, &mpls_te_link_maxbw_cmd);
  install_element (INTERFACE_NODE, &mpls_te_link_max_rsv_bw_cmd);
  install_element (INTERFACE_NODE, &mpls_te_link_unrsv_bw_cmd);
  install_element (INTERFACE_NODE, &mpls_te_link_rsc_clsclr_cmd);
  install_element (INTERFACE_NODE, &gmpls_te_link_capability_switching_cmd);
  install_element (INTERFACE_NODE, &gmpls_te_link_capability_encoding_cmd);
  install_element (INTERFACE_NODE, &gmpls_te_link_capability_maxbw_cmd);
  install_element (INTERFACE_NODE, &gmpls_te_link_capability_minbw_cmd);
  install_element (INTERFACE_NODE, &gmpls_te_link_capability_mtu_cmd);
  install_element (INTERFACE_NODE, &gmpls_te_link_capability_indication_cmd);
  install_element (INTERFACE_NODE, &gmpls_te_link_lrid_cmd);
  install_element (INTERFACE_NODE, &gmpls_te_link_protection_dedicated_cmd);
  install_element (INTERFACE_NODE, &gmpls_te_link_protection_cmd);
  install_element (INTERFACE_NODE, &gmpls_te_link_srlg_cmd);

  return;
}

#endif /* HAVE_OSPF_TE */
