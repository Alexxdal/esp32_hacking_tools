/*****************************
  *    Project Name:pcap_file_generator
  *    Author:V.Koroy
  *  Пт. окт. 6 15:32:33 MSK 2017
  *****************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "libpcap_file_generator.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_vfs.h"
#include "esp_vfs_fat.h"
#include "esp_log.h"
 
static const char* TAG = "PCAP_FILE_GENERATOR";


PCAPFILE * lpcap_create(const char * file_path )
{
   struct pcap_file_header pfh;
   memset(&pfh, 0, sizeof(pfh));

   pfh.magic = TCPDUMP_MAGIC;
   pfh.version_major = PCAP_VERSION_MAJOR;
   pfh.version_minor = PCAP_VERSION_MINOR;
   pfh.thiszone = 0;
   pfh.sigfigs = 0;
   pfh.snaplen = 65535;
   pfh.linktype = LINKTYPE_IEEE802_11; 
   
   PCAPFILE *f_pcp = fopen("/fat/hs.txt", "wb");
   if(f_pcp != NULL)
   {
      int res_wr = 0;
      res_wr =  fwrite(&pfh, sizeof(pfh), 1, f_pcp);
      if(res_wr != 0){
         return f_pcp;
      }
      return NULL;
   } 
   return NULL; 
}


void lpcap_close_file( PCAPFILE * f_pcp )
{
    if(f_pcp)
    {
       fflush( f_pcp );
       fclose( f_pcp );
    }
}

int lpcap_write_data( PCAPFILE * f_pcp ,  ethernet_data_t * eth_data, uint32_t current_seconds, uint32_t current_u_seconds)
{
   int res_wr = 0;
   pcaprec_hdr_and_data_t  prec_frame_w = { 0 };
   prec_frame_w.pcp_rec_hdr.ts_sec = current_seconds;
   prec_frame_w.pcp_rec_hdr.ts_usec = current_u_seconds;

   prec_frame_w.pcp_rec_hdr.orig_len =  eth_data->len;
   prec_frame_w.pcp_rec_hdr.incl_len =eth_data->len;
    
   res_wr =  fwrite(&prec_frame_w.pcp_rec_hdr, 1, sizeof(prec_frame_w.pcp_rec_hdr), f_pcp );
    if(res_wr)
    {
           memcpy((void *)prec_frame_w.packet_data , (void *)eth_data->data ,  ( eth_data->len ));
           res_wr &=  fwrite(&prec_frame_w.packet_data, 1, prec_frame_w.pcp_rec_hdr.orig_len, f_pcp ); 
    } 
   return res_wr;
}


void write_pcap(PCAPFILE * f_pcp, const struct timespec * ts, const void * p, const int len)
{
   pcap_pkthdr_t pkh = { 0 };
	pkh.caplen = pkh.len = len;
	pkh.tv_sec = ts->tv_sec;
	pkh.tv_usec = ts->tv_nsec / 1000UL;

   int res_wr = 0;
   res_wr = fwrite(&pkh, sizeof(pkh), 1, f_pcp);
   res_wr = fwrite(p, len, 1, f_pcp);
}

void packet_write_pcap(PCAPFILE * f_pcp, packet_t * p)
{
	write_pcap(f_pcp, &p->p_ts, p->p_data, p->p_len);
}

void packet_append_pcap(packet_t * p)
{
   PCAPFILE *f_pcp = fopen("/fat/hs.txt", "a");
	write_pcap(f_pcp, &p->p_ts, p->p_data, p->p_len);
   lpcap_close_file( f_pcp );
}