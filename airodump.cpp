#include <stdio.h>
#include <pcap.h>
#include <glog/logging.h>
#include <iostream>
#include <string>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include <map>
#include <pthread.h>
#include "IEEE80211.h"

#define MAX_SSID_LEN                        32
#define REFRESH_TIME_INTERVAL               500000  // us
#define PACKET_NUM_EXPIRE_TIME_INTERVAL     5       // s
#define AP_INFO_EXPIRE_TIME_LIMIT           10      // s

struct ap_info
{
    unsigned int        first_time;
    unsigned int        last_time;
    unsigned int        beacon_pkt_num;
    unsigned int        data_pkt_num;
    struct ether_addr   bssid;
    signed char         ssi_signal;
    signed char         ssi_noise;
    uint8_t             channel;
    unsigned int        data_rate;
    u_char              ssid[MAX_SSID_LEN + 1];
};

std::map<unsigned int, struct ap_info> ap_info_map;

namespace neolib
{
    template<class Elem, class Traits>
    inline void hex_dump(const void* aData, std::size_t aLength, std::basic_ostream<Elem, Traits>& aStream, std::size_t aWidth = 16)
    {
        const char* const start = static_cast<const char*>(aData);
        const char* const end = start + aLength;
        const char* line = start;
        while (line != end)
        {
            aStream.width(4);
            aStream.fill('0');
            aStream << std::hex << line - start << " : ";
            std::size_t lineLength = std::min(aWidth, static_cast<std::size_t>(end - line));
            for (std::size_t pass = 1; pass <= 2; ++pass)
            {   
                for (const char* next = line; next != end && next != line + aWidth; ++next)
                {
                    char ch = *next;
                    switch(pass)
                    {
                    case 1:
                        aStream << (ch < 32 ? '.' : ch);
                        break;
                    case 2:
                        if (next != line)
                            aStream << " ";
                        aStream.width(2);
                        aStream.fill('0');
                        aStream << std::hex << std::uppercase << static_cast<int>(static_cast<unsigned char>(ch));
                        break;
                    }
                }
                if (pass == 1 && lineLength != aWidth)
                    aStream << std::string(aWidth - lineLength, ' ');
                aStream << " ";
            }
            aStream << std::endl;
            line = line + lineLength;
        }
    }
}

unsigned int ether_addr_hasher(struct ether_addr addr)
{
    unsigned int hash;
    int i;

    hash = 0;

    for(i=0;i<ETHER_ADDR_LEN;i++)
    {
        hash = (hash << 8) | (addr.octet[i]); 
    }

    return hash;
}
    
void *print_ap_info(void *)
{
    struct ap_info ap_info;
    std::vector<unsigned int> keys;
    int i, loop_cnt;
    loop_cnt = 0;
    while(true)
    {
        system("clear");

        printf("%-20s%-10s%-12s%-10s%-10s%-10s%-10s%-10s%-18s%-20s\n", "BSSID", "#Beacon", "#Beacon/s", "#Data", "#Data/s", "Signal", "Noise", "Channel", "DataRate(Mb/s)", "SSID");
        for(std::pair<unsigned int, struct ap_info> element : ap_info_map)
        {
            ap_info = element.second;

            printf("%-20s%-10d%-12.02f%-10d%-10.02f%-10d%-10d%-10d%-18d%-20s\n", ether_ntoa(&ap_info.bssid), ap_info.beacon_pkt_num, (double)ap_info.beacon_pkt_num/(time(NULL)-ap_info.first_time), ap_info.data_pkt_num, (double)ap_info.data_pkt_num/(time(NULL)-ap_info.first_time), ap_info.ssi_signal, ap_info.ssi_noise, ap_info.channel, ap_info.data_rate, ap_info.ssid);

            if(ap_info.last_time < time(NULL) - AP_INFO_EXPIRE_TIME_LIMIT)
            {
                keys.push_back(element.first);
            }
        }
        fflush(stdout);

        for(i=0;i<(int)keys.size();i++)
        {
            ap_info_map.erase(keys[i]);
        }

        loop_cnt = (loop_cnt + 1) % (PACKET_NUM_EXPIRE_TIME_INTERVAL * 1000000 / REFRESH_TIME_INTERVAL);
        if(loop_cnt == 0)
        {
            for(std::pair<unsigned int, struct ap_info> element : ap_info_map)
            {
                ap_info_map[element.first].first_time       = time(NULL);
                ap_info_map[element.first].beacon_pkt_num   = 0;
                ap_info_map[element.first].data_pkt_num     = 0;
            }        
        }
 
        usleep(REFRESH_TIME_INTERVAL);
    }
    pthread_exit((void *) 0);
    return NULL;
}

int main(int argc, char **argv)
{
    char *                  interface;
    pcap_t *                handle;
    char                    errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program      fp;
    int                     res;
    struct pcap_pkthdr *    header;
    const u_char *          packet;
    struct ap_info          ap_info;
    uint16_t                subtype;
    IEEE80211_mgt_pkt *     mgt_pkt;
    u_char *                tagged_param;
    unsigned int            ssid_len;
    pthread_t               thread;

    google::InitGoogleLogging(argv[0]);

    if(argc != 2)
    {
        LOG(ERROR) << "Usage : " << argv[0] << " <interface>";
        return -1;
    }

    interface = argv[1];

    // pcap handle이 active 상태이면 pcap_set_rfmon 등 세팅 불가능
    // pcap_create -> pcap_set_* -> pcap_activate
    if((handle = pcap_create(interface, errbuf)) == NULL)
    {
        LOG(FATAL) << "pcap_create : failed";
        return -1;
    }
    LOG(INFO) << "pcap_create : succeed";

    if(pcap_set_promisc(handle, 1) != 0)
    {
        LOG(FATAL) << "pcap_set_promisc : failed";
        return -1;
    }
    LOG(INFO) << "pcap_set_promisc : succeed";

    if(pcap_set_rfmon(handle, 1) != 0)
    {
        LOG(FATAL) << "pcap_set_rfmon : failed";
        return -1;
    }
    LOG(INFO) << "pcap_set_rfmon : succeed";

    if(pcap_set_snaplen(handle, BUFSIZ))
    {
        LOG(FATAL) << "pcap_set_snaplen : failed";
        return -1;
    }
    LOG(INFO) << "pcap_set_snaplen : succeed";

    if(pcap_set_timeout(handle, 1))
    {
        LOG(FATAL) << "pcap_set_timeout : failed";
        return -1;
    }
    LOG(INFO) << "pcap_set_timeout : succeed";

    if(pcap_activate(handle) != 0)
    {
        LOG(FATAL) << "pcap_activate : failed";
        return -1;
    }
    LOG(INFO) << "pcap_activate : succeed";

    if(pcap_compile(handle, &fp, "(type mgt subtype probe-resp) or (type mgt subtype beacon) or (type data)", 0, PCAP_NETMASK_UNKNOWN) == -1) // mgt : management, probe-resp : probe response
    {
        LOG(FATAL) << "pcap_compile : failed";
        return -1;
    }
    LOG(INFO) << "pcap_compile : succeed";

    if(pcap_setfilter(handle, &fp) == -1)
    {
        LOG(FATAL) << "pcap_setfilter : failed";
        return -1;
    }
    LOG(INFO) << "pcap_setfilter : succeed";

    pthread_create(&thread, NULL, &print_ap_info, NULL);

    while((res = pcap_next_ex(handle, &header, &packet)) >= 0)
    {
        if(res == 0)
        {
            LOG(INFO) << "pcap_next_ex : timeout";
            continue;
        }
        LOG(INFO) << "pcap_next_ex : succeed";

        //neolib::hex_dump(packet, header->len, std::cout);
        //printf("\n\n");   

        subtype = ntohs(*(uint16_t *)(packet + sizeof(struct radiotap_hdr)));

        // (type mgt subtype probe-resp) or (type mgt subtype beacon)
        if(subtype == IEEE80211_SUBTYPE_PROBERESP || subtype == IEEE80211_SUBTYPE_BEACON)
        {
            mgt_pkt = (IEEE80211_mgt_pkt *) packet;
            tagged_param = (u_char *)packet + sizeof(IEEE80211_mgt_pkt);

            while(true)
            {
                switch(*tagged_param)
                {
                case IEEE80211_MANAGEMENT_TAG_SSID:
                    
                    ssid_len = *(tagged_param + 1);
                    if(ssid_len < 3)
                    {
                        strcpy((char *)ap_info.ssid, "<length : ?>");
                    }
                    else
                    {
                        strncpy((char *)ap_info.ssid, (char *)tagged_param + 2, ssid_len);
                        ap_info.ssid[ssid_len] = '\0';
                    }
                    break;

                case IEEE80211_MANAGEMENT_TAG_CHANNEL:

                    ap_info.channel = tagged_param[2];
                    break;

                case IEEE80211_MANAGEMENT_TAG_SUP_DATA_RATE:
                case IEEE80211_MANAGEMENT_TAG_EXT_DATA_RATE:

                    ap_info.data_rate = (tagged_param[1 + tagged_param[1]] & 0x7F) >> 1;
                    break;
                }

                tagged_param += *(tagged_param + 1) + 2;

                if(tagged_param > packet + header->len)
                {
                    break;
                }
            }
            
            ap_info.last_time   = time(NULL);
            ap_info.bssid       = mgt_pkt->IEEE80211_hdr.bssid;
            ap_info.ssi_signal  = (signed char) mgt_pkt->radiotap_hdr.signal;
            ap_info.ssi_noise   = (signed char) mgt_pkt->radiotap_hdr.noise;

            if(ap_info_map.find(ether_addr_hasher(ap_info.bssid)) == ap_info_map.end())   
            {
                ap_info.first_time = time(NULL);
                if(subtype == IEEE80211_SUBTYPE_BEACON)
                {
                    ap_info.beacon_pkt_num  = 1;
                    ap_info.data_pkt_num    = 0;
                }
                else
                {
                    ap_info.beacon_pkt_num  = 0;
                    ap_info.data_pkt_num    = 0;
                }

                ap_info_map[ether_addr_hasher(ap_info.bssid)] = ap_info;
            }
            else
            {
                ap_info.first_time = ap_info_map[ether_addr_hasher(ap_info.bssid)].first_time;

                if(subtype == IEEE80211_SUBTYPE_BEACON)
                {
                    ap_info.beacon_pkt_num = ap_info_map[ether_addr_hasher(ap_info.bssid)].beacon_pkt_num + 1;
                }
                else
                {
                    ap_info.beacon_pkt_num = ap_info_map[ether_addr_hasher(ap_info.bssid)].beacon_pkt_num;
                }

                ap_info_map[ether_addr_hasher(ap_info.bssid)] = ap_info;
            }

            /*
            printf("%-29s : %s\n", "BSSID", ether_ntoa(&ap_info.bssid));
            printf("%-29s : %d\n", "SSI Signal", (signed char) mgt_pkt->radiotap_hdr.signal);
            printf("%-29s : %d\n", "SSI Noise", (signed char) mgt_pkt->radiotap_hdr.noise);
            printf("%-29s : %d\n", "Channel", (mgt_pkt->radiotap_hdr.frequency - 2407)/5);
            printf("%-29s : %d (Mb/s)\n", "Data rate", mgt_pkt->radiotap_hdr.data_rate / 2);
            printf("%-29s : %s\n", "SSID", ap_info.ssid);
            printf("\n\n");
            */

            LOG(INFO) << "management packet parsing : succeed";
        }
        // (type data)
        else
        {

        }
    }
    
    pthread_cancel(thread);
    pcap_close(handle);

    return 0;

}
