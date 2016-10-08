#ifndef PACKETSPARSER_H
#define PACKETSPARSER_H

#include <QString>
#include <QByteArray>
#include <QFile>



/*
 * Struct to save transport protocols info of ipv4&ipv6
 */
struct TransportProtocolsCount
{
    uint protocol = 0;
    uint TCP = 0; //0x06
    uint UDP = 0; //0x11
    uint GRE = 0; //0x2f
    uint ICMP = 0; //0x01
    uint ESP = 0; //0x32
    uint EIGRP = 0; //0x58
    uint other = 0;

};

/*
 * Class to parse file <2 bytes><packet> into simple packet info
 */
class PacketsParser
{
private:
    //offsets to data that we need

    const uint protocolOffset = 0;
    const uint packetLengthIPV4Offset = 2;
    const uint packetChecksumIPV4Offset = 10;
    const uint payloadLengthIPV6Offset = 4;
    const uint transportProtocolOffsetIpv4 = 9;
    const uint transportProtocolOffsetIpv6 = 6;
    uint mainOffset = 0;
    uint currentOffset = 0;
    uint firstBytes = 0;
    //choose some popular transport level protocols
    void selectTransportProtocolType(char protocol, TransportProtocolsCount &protocolsCount);
    //reset all data
    void resetData();
    QByteArray fileBytes;
    TransportProtocolsCount ipv4PacketsCount;
    TransportProtocolsCount ipv6PacketsCount;
    uint otherPacketsCount = 0;
    uint totalPackets = 0;
    //calculate checksum of ipv4 header
    uint16_t ipv4Checksum(uint offset);
    
public:
    PacketsParser();
    PacketsParser(QString fileName, uint firstBytes);
    void loadFile(QString fileName, uint firstBytes);
    void packetParse();
// getter functions
    uint getTotalPackets();
    uint getIPv4TotalPackets();
    uint getIPv4TCPPackets();
    uint getIPv4UDPPackets();
    uint getIPv4GREPackets();
    uint getIPv4ICMPPackets();
    uint getIPv4ESPPackets();
    uint getIPv4EIGRPPackets();
    uint getIPv4OtherPackets();
    uint getIPv6TotalPackets();
    uint getIPv6TCPPackets();
    uint getIPv6UDPPackets();
    uint getIPv6GREPackets();
    uint getIPv6ICMPPackets();
    uint getIPv6ESPPackets();
    uint getIPv6EIGRPPackets();
    uint getIPv6OtherPackets();
    uint getOtherTotalPackets();
};

#endif // PACKETSPARSER_H
