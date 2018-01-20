#include <stdio.h>
#include <pcap.h>
#include <glog/logging.h>
#include <iostream>
#include <string>

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

int main(int argc, char **argv)
{
    char *                  interface;
    pcap_t *                handle;
    char                    errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program      fp;
    bpf_u_int32             net;
    int                     res;
    struct pcap_pkthdr *    header;
    const u_char *          packet;

    google::InitGoogleLogging(argv[0]);

    if(argc != 2)
    {
        LOG(FATAL) << "Usage : " << argv[0] << " <interface>";
        return -1;
    }

    interface = argv[1];

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

    while((res = pcap_next_ex(handle, &header, &packet)) >= 0)
    {
        printf("packet length : %d\n", header->len);
        neolib::hex_dump(packet, header->len, std::cout);
        printf("\n\n");
    }
    
    pcap_close(handle);

    return 0;

}