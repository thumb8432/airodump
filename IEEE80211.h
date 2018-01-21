#include <net/ethernet.h>

#define IEEE80211_SUBTYPE_PROBERESP         0x5000
#define IEEE80211_SUBTYPE_BEACON            0x8000
#define IEEE80211_MANAGEMENT_TAG_SSID       0x00

struct radiotap_hdr
{
    uint8_t     revision;
    uint8_t     pad;
    uint16_t    length;
    uint32_t    present_flags;
    uint64_t    timestamp;
    uint8_t     flags;
    uint8_t     data_rate;
    uint16_t    frequency;
    uint16_t    channel_flags;
    uint8_t     signal;
    uint8_t     noise;
    uint8_t     antenna;
}__attribute__((packed));

struct IEEE80211_hdr
{
    uint16_t            frame_ctrl;
    uint16_t            duration;
    struct ether_addr   dst_addr;
    struct ether_addr   src_addr;
    struct ether_addr   bssid;
    uint16_t            frag_seq_num;
}__attribute__((packed));

struct IEEE80211_mgt_fixed_param
{
    uint64_t    timestamp;
    uint16_t    beacon_interval;
    uint16_t    capa_info;
}__attribute__((packed));

struct IEEE80211_mgt_pkt
{
    struct radiotap_hdr                 radiotap_hdr;
    struct IEEE80211_hdr                IEEE80211_hdr;
    struct IEEE80211_mgt_fixed_param    IEEE80211_mgt_fixed_param;
}__attribute__((packed));