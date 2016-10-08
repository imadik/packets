#include "packetsparser.h"


const uint IPV4 = 0x0800;
const uint IPV6 = 0x86dd;
const uint Loopback = 0x9000;
const uint ARP = 0x0806;
const char ICMP = 0x01;
const char TCP = 0x06;
const char UDP = 0x11;
const char GRE = 0x2f;
const char ESP = 0x32;
const char EIGRP = 0x58;
const char IPv4HeaderSize = 20;
const char IPv6HeaderSize = 40;


/*
 * Default constructor
 */
PacketsParser::PacketsParser()
{

}

/*
 * Constructor that opens file
 */
PacketsParser::PacketsParser(QString fileName, uint firstBytes)
{
    loadFile(fileName, firstBytes);
}

/*
 * Load file if it wasnt loaded in init
 */
void PacketsParser::loadFile(QString fileName, uint firstBytes)
{
    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly)) return;
    resetData();
    fileBytes.clear();
    fileBytes = file.readAll();
    PacketsParser::firstBytes = firstBytes;
}

/*
 * Simple packet parser
 * it is trying to find some ipv4 and ipv6 basic signs, and signs of the some other protocols
 * it is trying to find packet TYPE in <6 bytes mac of destination><6 bytes mac of source><2 bytes mac of TYPE><data>
 */
void PacketsParser::packetParse()
{
    if (fileBytes.size() < IPv4HeaderSize) //smallest ipv4 packet:20 bytes
        return;
    while (currentOffset <= (fileBytes.size() - IPv4HeaderSize))
    {
        totalPackets++;
        bool otherPacketsFlag = true; //flag that we use to find other packets
        uint packetLen = (fileBytes[currentOffset] & 0xff) + ((fileBytes[currentOffset + 1] & 0xff) << 8);
        for (mainOffset = 2; (mainOffset <= (firstBytes + 2)) && (mainOffset < (packetLen + 2)); mainOffset++)
        {
            uint protocol = ((fileBytes[currentOffset + protocolOffset + mainOffset] & 0xf0) >> 4); // only for ipv4 and ipv6

            char transportProtocol = 0;
            //trying to find only basic protocols signs, not full parse. Beacause the task dont say anything else.
            if ((protocol == 4) && ((packetLen - mainOffset - 2) >= IPv4HeaderSize))
            {
                // calculating header checksum, and it is good check for ipv4 packet
                uint checksumStored = (fileBytes[currentOffset + mainOffset + packetChecksumIPV4Offset] & 0xff) \
                        + ((fileBytes[currentOffset + mainOffset + packetChecksumIPV4Offset + 1] & 0xff) << 8);
                uint checksumCalculated = ipv4Checksum(currentOffset + mainOffset);
                if (checksumStored == checksumCalculated)
                {
                    transportProtocol = fileBytes[currentOffset + transportProtocolOffsetIpv4 + mainOffset] & 0xff;
                    selectTransportProtocolType(transportProtocol, ipv4PacketsCount);
                    otherPacketsFlag = false;
                    break; // stop if find packet
                }
                else
                {
                    otherPacketsFlag = true;
                }

            }else
            if ((protocol == 6) && ((packetLen - mainOffset - 2) >= IPv6HeaderSize))// we can check packet length, ipv6 header must be not less than 40 bytes
            {
                //ipv6 havent got checksum in header
                uint payloadLength = (fileBytes[currentOffset + payloadLengthIPV6Offset + mainOffset + 1] & 0xff) \
                        + ((fileBytes[currentOffset + payloadLengthIPV6Offset + mainOffset] & 0xff) << 8);
                if (packetLen == (payloadLength + (mainOffset - 2) + IPv6HeaderSize)) // check size of packet again, better check with payload length
                {
                    transportProtocol = fileBytes[currentOffset + transportProtocolOffsetIpv6 + mainOffset];
                    selectTransportProtocolType(transportProtocol, ipv6PacketsCount);
                    otherPacketsFlag = false;
                    break; // stop if find packet
                }else
                {
                    otherPacketsFlag = true;
                }

            }else
            {
                otherPacketsFlag = true;
            }
        }
        if (otherPacketsFlag)
            otherPacketsCount++;
        currentOffset += packetLen + 2; // packet size + 2 bytes of len

    }
}

/*
 * choousing transport protocol type
 */
void PacketsParser::selectTransportProtocolType(char protocol, TransportProtocolsCount &protocolsCount)
{
    protocolsCount.protocol++;
    switch (protocol) {
    case TCP:
        {
            protocolsCount.TCP++;
            break;
        }
    case UDP:
        {
            protocolsCount.UDP++;
            break;
        }
    case GRE:
        {
            protocolsCount.GRE++;
            break;
        }
    case ICMP:
        {
            protocolsCount.ICMP++;
            break;
        }
    case ESP:
        {
            protocolsCount.ESP++;
            break;
        }
    case EIGRP:
        {
            protocolsCount.EIGRP++;
            break;
        }
    default:
        {
            protocolsCount.other++;
            break;
        }
    }
}

void PacketsParser::resetData()
{
    totalPackets = 0;
    ipv4PacketsCount.protocol = 0;
    ipv4PacketsCount.TCP = 0;
    ipv4PacketsCount.UDP = 0;
    ipv4PacketsCount.GRE = 0;
    ipv4PacketsCount.ICMP = 0;
    ipv4PacketsCount.ESP = 0;
    ipv4PacketsCount.EIGRP = 0;
    ipv4PacketsCount.other = 0;
    ipv6PacketsCount.protocol = 0;
    ipv6PacketsCount.TCP = 0;
    ipv6PacketsCount.UDP = 0;
    ipv6PacketsCount.GRE = 0;
    ipv6PacketsCount.ICMP = 0;
    ipv6PacketsCount.ESP = 0;
    ipv6PacketsCount.EIGRP = 0;
    ipv6PacketsCount.other = 0;
    otherPacketsCount = 0;
}

/*
 * Function to calculate ipv4 header checksum
 */
uint16_t PacketsParser::ipv4Checksum(uint offset)
{

    uint headerLength = (fileBytes[offset] & 0x0f);
    // Initialise the accumulator.
    uint acc = 0;

    // Handle complete 16-bit blocks.
    for (uint i = 0; (i + 1 < (headerLength * 4)) && (i + 1 < fileBytes.size()); i += 2) {
        if (i == 10)
            continue;
        uint word = (fileBytes[offset + i] & 0xff) + ((fileBytes[offset + i + 1] & 0xff) << 8);
        acc += word;

    }
    uint accPre = (acc & 0xffff0000) >> 16;
    acc = (acc & 0xffff) + accPre;
    uint16_t ret = acc;
    return (~ret);
}

/*
 * Getter functions to get the data
 */
uint PacketsParser::getTotalPackets()
{
    return totalPackets;
}

uint PacketsParser::getIPv4TotalPackets()
{
    return ipv4PacketsCount.protocol;
}

uint PacketsParser::getIPv4TCPPackets()
{
    return ipv4PacketsCount.TCP;
}

uint PacketsParser::getIPv4UDPPackets()
{
    return ipv4PacketsCount.UDP;
}

uint PacketsParser::getIPv4GREPackets()
{
    return ipv4PacketsCount.GRE;
}

uint PacketsParser::getIPv4ICMPPackets()
{
    return ipv4PacketsCount.ICMP;
}

uint PacketsParser::getIPv4ESPPackets()
{
    return ipv4PacketsCount.ESP;
}

uint PacketsParser::getIPv4EIGRPPackets()
{
    return ipv4PacketsCount.EIGRP;
}

uint PacketsParser::getIPv4OtherPackets()
{
    return ipv4PacketsCount.other;
}

uint PacketsParser::getIPv6TotalPackets()
{
    return ipv6PacketsCount.protocol;
}

uint PacketsParser::getIPv6TCPPackets()
{
    return ipv6PacketsCount.TCP;
}

uint PacketsParser::getIPv6UDPPackets()
{
    return ipv6PacketsCount.UDP;
}

uint PacketsParser::getIPv6GREPackets()
{
    return ipv6PacketsCount.GRE;
}

uint PacketsParser::getIPv6ICMPPackets()
{
    return ipv6PacketsCount.ICMP;
}

uint PacketsParser::getIPv6ESPPackets()
{
    return ipv6PacketsCount.ESP;
}

uint PacketsParser::getIPv6EIGRPPackets()
{
    return ipv6PacketsCount.EIGRP;
}

uint PacketsParser::getIPv6OtherPackets()
{
    return ipv6PacketsCount.other;
}

uint PacketsParser::getOtherTotalPackets()
{
    return otherPacketsCount;
}
