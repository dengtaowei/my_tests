#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <netdb.h>

#define SSDP_PORT 1900
#define HTTP_PORT 8000
#define SSDP_GROUP "239.255.255.250"
#define BUFFER_SIZE 1024
#define DEVICE_UUID "12345678-0000-0000-0000-000000000000"
#define DEVICE_TYPE "upnp:rootdevice"

int running = 1;

// 设备描述XML
const char *device_description = 
    "<?xml version=\"1.0\"?>"
    "<root xmlns=\"urn:schemas-upnp-org:device-1-0\">"
    "  <specVersion>"
    "    <major>1</major>"
    "    <minor>0</minor>"
    "  </specVersion>"
    "  <device>"
    "    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>"
    "    <UDN>uuid:%s</UDN>"
    "    <friendlyName>DLNA Virtual Renderer</friendlyName>"
    "    <manufacturer>DLNA Developer</manufacturer>"
    "    <manufacturerURL>http://www.example.com</manufacturerURL>"
    "    <modelDescription>DLNA Virtual Renderer for Testing</modelDescription>"
    "    <modelName>DVR-Sim</modelName>"
    "    <modelNumber>1.0</modelNumber>"
    "    <modelURL>http://www.example.com</modelURL>"
    "    <serialNumber>12345678</serialNumber>"
    "    <serviceList>"
    "      <service>"
    "        <serviceType>urn:schemas-upnp-org:service:AVTransport:1</serviceType>"
    "        <serviceId>urn:upnp-org:serviceId:AVTransport</serviceId>"
    "        <controlURL>AVTransport/action</controlURL>"
    "        <eventSubURL>AVTransport/event</eventSubURL>"
    "        <SCPDURL>dlna/AVTransport.xml</SCPDURL>"
    "      </service>"
    "      <service>"
    "        <serviceType>urn:schemas-upnp-org:service:RenderingControl:1</serviceType>"
    "        <serviceId>urn:upnp-org:serviceId:RenderingControl</serviceId>"
    "        <controlURL>RenderingControl/action</controlURL>"
    "        <eventSubURL>RenderingControl/event</eventSubURL>"
    "        <SCPDURL>dlna/RenderingControl.xml</SCPDURL>"
    "      </service>"
    "      <service>"
    "        <serviceType>urn:schemas-upnp-org:service:ConnectionManager:1</serviceType>"
    "        <serviceId>urn:upnp-org:serviceId:ConnectionManager</serviceId>"
    "        <controlURL>ConnectionManager/action</controlURL>"
    "        <eventSubURL>ConnectionManager/event</eventSubURL>"
    "        <SCPDURL>dlna/ConnectionManager.xml</SCPDURL>"
    "      </service>"
    "    </serviceList>"
    "    <presentationURL>http://%s:%d/</presentationURL>"
    "  </device>"
    "</root>";



const char* get_local_ip() {

    return "192.168.1.23";

    static char ip[16] = "127.0.0.1";
    struct ifaddrs *ifaddr, *ifa;
    int family, s;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return ip;
    }

    // 遍历接口列表寻找IPv4地址
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        // 只考虑IPv4和非回环地址
        if (family == AF_INET && strcmp(ifa->ifa_name, "lo") != 0) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                          ip, sizeof(ip), NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                continue;
            }
            break;
        }
    }

    freeifaddrs(ifaddr);
    return ip;
}

const char* get_current_time() {
    static char time_buf[64];
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    strftime(time_buf, sizeof(time_buf), "%a, %d %b %Y %H:%M:%S GMT", tm);
    return time_buf;
}

// AVTransport服务描述
const char *avtransport_scpd = 
"    <?xml version=\"1.0\" encoding=\"UTF-8\"?>"
"<scpd"
"        xmlns=\"urn:schemas-upnp-org:service-1-0\">"
"    <specVersion>"
"        <major>1</major>"
"        <minor>0</minor>"
"    </specVersion>"
"    <actionList>"
"        <action>"
"            <name>GetCurrentTransportActions</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>Actions</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>CurrentTransportActions</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>GetDeviceCapabilities</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>PlayMedia</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>PossiblePlaybackStorageMedia</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>RecMedia</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>PossibleRecordStorageMedia</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>RecQualityModes</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>PossibleRecordQualityModes</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>GetMediaInfo</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>NrTracks</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>NumberOfTracks</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>MediaDuration</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>CurrentMediaDuration</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>CurrentURI</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>AVTransportURI</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>CurrentURIMetaData</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>AVTransportURIMetaData</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>NextURI</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>NextAVTransportURI</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>NextURIMetaData</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>NextAVTransportURIMetaData</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>PlayMedium</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>PlaybackStorageMedium</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>RecordMedium</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>RecordStorageMedium</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>WriteStatus</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>RecordMediumWriteStatus</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>GetPositionInfo</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>Track</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>CurrentTrack</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>TrackDuration</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>CurrentTrackDuration</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>TrackMetaData</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>CurrentTrackMetaData</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>TrackURI</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>CurrentTrackURI</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>RelTime</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>RelativeTimePosition</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>AbsTime</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>AbsoluteTimePosition</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>RelCount</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>RelativeCounterPosition</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>AbsCount</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>AbsoluteCounterPosition</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>GetTransportInfo</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>CurrentTransportState</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>TransportState</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>CurrentTransportStatus</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>TransportStatus</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>CurrentSpeed</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>TransportPlaySpeed</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>GetTransportSettings</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>PlayMode</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>CurrentPlayMode</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>RecQualityMode</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>CurrentRecordQualityMode</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>Next</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>Pause</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>Play</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>Speed</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>TransportPlaySpeed</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>Previous</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>Seek</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>Unit</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_SeekMode</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>Target</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_SeekTarget</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>SetAVTransportURI</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>CurrentURI</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>AVTransportURI</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>CurrentURIMetaData</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>AVTransportURIMetaData</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>SetPlayMode</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>NewPlayMode</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>CurrentPlayMode</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>Stop</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"    </actionList>"
"    <serviceStateTable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>CurrentPlayMode</name>"
"            <dataType>string</dataType>"
"            <defaultValue>NORMAL</defaultValue>"
"            <allowedValueList>"
"                <allowedValue>NORMAL</allowedValue>"
"                <allowedValue>REPEAT_ONE</allowedValue>"
"                <allowedValue>REPEAT_ALL</allowedValue>"
"                <allowedValue>SHUFFLE</allowedValue>"
"                <allowedValue>SHUFFLE_NOREPEAT</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>RecordStorageMedium</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>NOT_IMPLEMENTED</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"yes\">"
"            <name>LastChange</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>RelativeTimePosition</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>CurrentTrackTitle</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>DisplayCurrentSubtitle</name>"
"            <dataType>boolean</dataType>"
"            <defaultValue>1</defaultValue>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>CurrentTrackURI</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>CurrentTrackDuration</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>CurrentRecordQualityMode</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>NOT_IMPLEMENTED</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>CurrentMediaDuration</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>AbsoluteCounterPosition</name>"
"            <dataType>i4</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>RelativeCounterPosition</name>"
"            <dataType>i4</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>A_ARG_TYPE_InstanceID</name>"
"            <dataType>ui4</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>AVTransportURI</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>TransportState</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>STOPPED</allowedValue>"
"                <allowedValue>PAUSED_PLAYBACK</allowedValue>"
"                <allowedValue>PLAYING</allowedValue>"
"                <allowedValue>TRANSITIONING</allowedValue>"
"                <allowedValue>NO_MEDIA_PRESENT</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>CurrentTrackMetaData</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>NextAVTransportURI</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>PossibleRecordQualityModes</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>NOT_IMPLEMENTED</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>CurrentTrack</name>"
"            <dataType>ui4</dataType>"
"            <allowedValueRange>"
"                <minimum>0</minimum>"
"                <maximum>65535</maximum>"
"                <step>1</step>"
"            </allowedValueRange>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>AbsoluteTimePosition</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>NextAVTransportURIMetaData</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>PlaybackStorageMedium</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>NONE</allowedValue>"
"                <allowedValue>UNKNOWN</allowedValue>"
"                <allowedValue>CD-DA</allowedValue>"
"                <allowedValue>HDD</allowedValue>"
"                <allowedValue>NETWORK</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>CurrentTransportActions</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>RecordMediumWriteStatus</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>NOT_IMPLEMENTED</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>PossiblePlaybackStorageMedia</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>NONE</allowedValue>"
"                <allowedValue>UNKNOWN</allowedValue>"
"                <allowedValue>CD-DA</allowedValue>"
"                <allowedValue>HDD</allowedValue>"
"                <allowedValue>NETWORK</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>AVTransportURIMetaData</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>NumberOfTracks</name>"
"            <dataType>ui4</dataType>"
"            <allowedValueRange>"
"                <minimum>0</minimum>"
"                <maximum>65535</maximum>"
"            </allowedValueRange>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>A_ARG_TYPE_SeekMode</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>REL_TIME</allowedValue>"
"                <allowedValue>TRACK_NR</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>A_ARG_TYPE_SeekTarget</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>PossibleRecordStorageMedia</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>NOT_IMPLEMENTED</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>TransportStatus</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>OK</allowedValue>"
"                <allowedValue>ERROR_OCCURRED</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>TransportPlaySpeed</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>0.5</allowedValue>"
"                <allowedValue>0.75</allowedValue>"
"                <allowedValue>1</allowedValue>"
"                <allowedValue>1.25</allowedValue>"
"                <allowedValue>1.5</allowedValue>"
"                <allowedValue>2</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"    </serviceStateTable>"
"</scpd>";


const char *rendercontrol_scpd = 
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
"<scpd"
"    xmlns=\"urn:schemas-upnp-org:service-1-0\">"
"    <specVersion>"
"        <major>1</major>"
"        <minor>0</minor>"
"    </specVersion>"
"    <actionList>"
"        <action>"
"            <name>GetMute</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>Channel</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_Channel</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>CurrentMute</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>Mute</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>GetVolume</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>Channel</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_Channel</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>CurrentVolume</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>Volume</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>GetVolumeDB</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>Channel</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_Channel</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>CurrentVolume</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>VolumeDB</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>GetVolumeDBRange</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>Channel</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_Channel</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>MinValue</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>VolumeDB</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>MaxValue</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>VolumeDB</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>ListPresets</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>CurrentPresetNameList</name>"
"                    <direction>out</direction>"
"                    <relatedStateVariable>PresetNameList</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>SelectPreset</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>PresetName</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_PresetName</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>SetMute</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>Channel</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_Channel</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>DesiredMute</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>Mute</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"        <action>"
"            <name>SetVolume</name>"
"            <argumentList>"
"                <argument>"
"                    <name>InstanceID</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_InstanceID</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>Channel</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>A_ARG_TYPE_Channel</relatedStateVariable>"
"                </argument>"
"                <argument>"
"                    <name>DesiredVolume</name>"
"                    <direction>in</direction>"
"                    <relatedStateVariable>Volume</relatedStateVariable>"
"                </argument>"
"            </argumentList>"
"        </action>"
"    </actionList>"
"    <serviceStateTable>"
"        <stateVariable sendEvents=\"yes\">"
"            <name>LastChange</name>"
"            <dataType>string</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>A_ARG_TYPE_Channel</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>Master</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>A_ARG_TYPE_InstanceID</name>"
"            <dataType>ui4</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>Volume</name>"
"            <dataType>ui2</dataType>"
"            <allowedValueRange>"
"                <minimum>0</minimum>"
"                <maximum>100</maximum>"
"                <step>1</step>"
"            </allowedValueRange>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>Mute</name>"
"            <dataType>boolean</dataType>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>PresetNameList</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>FactoryDefaults</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>A_ARG_TYPE_PresetName</name>"
"            <dataType>string</dataType>"
"            <allowedValueList>"
"                <allowedValue>FactoryDefaults</allowedValue>"
"            </allowedValueList>"
"        </stateVariable>"
"        <stateVariable sendEvents=\"no\">"
"            <name>VolumeDB</name>"
"            <dataType>i2</dataType>"
"            <allowedValueRange>"
"                <minimum>-32767</minimum>"
"                <maximum>32767</maximum>"
"            </allowedValueRange>"
"        </stateVariable>"
"    </serviceStateTable>"
"</scpd>";

// 发送设备描述
void send_device_description(int client_sock) {
    char desc[BUFFER_SIZE * 2];
    snprintf(desc, sizeof(desc), device_description, DEVICE_UUID, get_local_ip(), HTTP_PORT);
    
    char response[BUFFER_SIZE * 3];
    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/xml\r\n"
        "SERVER: Linux/6.8.0-84-generic UPnP/1.0 DLNA_TV_Simulator/1.0\r\n"
        "Date: %s\r\n"
        "Allow: GET, HEAD, POST, SUBSCRIBE, UNSUBSCRIBE"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s", get_current_time(), strlen(desc), desc);
    
    send(client_sock, response, strlen(response), 0);
}

// 发送服务描述
void send_service_description(int client_sock, const char *service) {
    const char *scpd = NULL;
    if (strcmp(service, "AVTransport") == 0) {
        scpd = avtransport_scpd;
    } else {
        send_404_response(client_sock);
        return;
    }
    
    char response[BUFFER_SIZE * 3];
    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/xml\r\n"
        "Server: Linux/6.8.0-84-generic UPnP/1.0 DLNA_TV_Simulator/1.0"
        "Date: %s"
        "Allow: GET, HEAD, POST, SUBSCRIBE, UNSUBSCRIBE"
        "Accept-Ranges: bytes"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", get_current_time(), strlen(scpd), scpd);
    
    send(client_sock, response, strlen(response), 0);
}

void send_render_description(int client_sock, const char *service) {
    const char *scpd = NULL;
    if (strcmp(service, "RenderingControl") == 0) {
        scpd = rendercontrol_scpd;
    } else {
        send_404_response(client_sock);
        return;
    }
    
    char response[BUFFER_SIZE * 3];
    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/xml\r\n"
        "Server: Linux/6.8.0-84-generic UPnP/1.0 DLNA_TV_Simulator/1.0"
        "Date: %s"
        "Allow: GET, HEAD, POST, SUBSCRIBE, UNSUBSCRIBE"
        "Accept-Ranges: bytes"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", get_current_time(), strlen(scpd), scpd);
    
    send(client_sock, response, strlen(response), 0);
}

// 处理AVTransport控制请求
void handle_avtransport_request(int client_sock, const char *request) {
    // 这里简化处理，实际应解析SOAP请求
    char response[BUFFER_SIZE];
    const char *soap_response = 
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body>"
        "<u:SetAVTransportURIResponse xmlns:u=\"urn:schemas-upnp-org:service:AVTransport:1\">"
        "</u:SetAVTransportURIResponse>"
        "</s:Body>"
        "</s:Envelope>";
    
    snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/xml; charset=\"utf-8\"\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "EXT:\r\n"
        "\r\n"
        "%s", strlen(soap_response), soap_response);
    
    send(client_sock, response, strlen(response), 0);
}

// 发送404响应
void send_404_response(int client_sock) {
    const char *response = 
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 9\r\n"
        "Connection: close\r\n"
        "\r\n"
        "Not Found";
    send(client_sock, response, strlen(response), 0);
}


// 处理SSDP通知和搜索请求
void handle_ssdp_request(int sockfd, const char *buffer, struct sockaddr_in *client_addr) {
    if (strstr(buffer, "M-SEARCH") != NULL) {
        // 检查搜索目标是否匹配
        if (strstr(buffer, "ssdp:discover") || strstr(buffer, "urn:schemas-upnp-org:device:MediaRenderer:1")) {
            char response[BUFFER_SIZE];
            snprintf(response, BUFFER_SIZE,
                "HTTP/1.1 200 OK\r\n"
                "USN: uuid:%s::%s\r\n"
                "LOCATION: http://%s:%d/description.xml\r\n"
                "ST: %s\r\n"
                "EXT:\r\n"
                "SERVER: Linux/6.8.0-84-generic UPnP/1.0 DLNA_TV_Simulator/1.0\r\n"
                "CACHE-CONTROL: max-age=66\r\n"
                "DATE: %s\r\n"
                "\r\n",
                DEVICE_UUID, DEVICE_TYPE, 
                get_local_ip(), HTTP_PORT, 
                DEVICE_TYPE, 
                get_current_time());
            
            sendto(sockfd, response, strlen(response), 0, 
                  (struct sockaddr *)client_addr, sizeof(*client_addr));
            
            printf("Responded to M-SEARCH from %s\n", inet_ntoa(client_addr->sin_addr));
        }
    }
}

// 发送SSDP通知
void send_ssdp_notify(int sockfd) {
    char notify_msg[BUFFER_SIZE];
    snprintf(notify_msg, BUFFER_SIZE,
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "NTS: ssdp:alive\r\n"
        "USN: uuid:%s::%s\r\n"
        "LOCATION: http://%s:%d/description.xml\r\n"
        "EXT:\r\n"
        "SERVER: Linux/6.8.0-84-generic UPnP/1.0 DLNA_TV_Simulator/1.0\r\n"
        "CACHE-CONTROL: max-age=66\r\n"
        "NT: %s\r\n"
        "\r\n", 
        DEVICE_UUID, DEVICE_TYPE, get_local_ip(), HTTP_PORT, DEVICE_TYPE);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SSDP_PORT);
    inet_pton(AF_INET, SSDP_GROUP, &addr.sin_addr);
    
    sendto(sockfd, notify_msg, strlen(notify_msg), 0, 
          (struct sockaddr *)&addr, sizeof(addr));
    
    time_t now;
    time(&now);
    printf("[%.24s] Sent SSDP NOTIFY\n", ctime(&now));
}

// 简单的HTTP服务器线程函数
void *http_server_thread(void *arg) {
    int http_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (http_sock < 0) {
        perror("HTTP socket creation failed");
        return NULL;
    }

    int reuse = 1;
    if (setsockopt(http_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        close(http_sock);
        return NULL;
    }
    
    struct sockaddr_in http_addr;
    memset(&http_addr, 0, sizeof(http_addr));
    http_addr.sin_family = AF_INET;
    http_addr.sin_addr.s_addr = INADDR_ANY;
    http_addr.sin_port = htons(HTTP_PORT);
    
    if (bind(http_sock, (struct sockaddr *)&http_addr, sizeof(http_addr)) < 0) {
        perror("HTTP bind failed");
        close(http_sock);
        return NULL;
    }
    
    if (listen(http_sock, 5) < 0) {
        perror("HTTP listen failed");
        close(http_sock);
        return NULL;
    }
    
    printf("HTTP server started on port %d\n", HTTP_PORT);
    
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(http_sock, (struct sockaddr *)&client_addr, &client_len);
        
        if (client_sock < 0) {
            if (running) perror("HTTP accept failed");
            continue;
        }
        
        char request[BUFFER_SIZE];
        ssize_t len = recv(client_sock, request, BUFFER_SIZE - 1, 0);
        if (len > 0) {
            request[len] = '\0';
            
            // 处理设备描述请求
            if (strstr(request, "GET /description.xml")) {
                send_device_description(client_sock);
            }
            // 处理服务描述请求
            else if (strstr(request, "GET /AVTransport.xml") || 
                strstr(request, "GET /dlna/AVTransport.xml")) {
                send_service_description(client_sock, "AVTransport");
            }
            // 处理Render描述请求
            else if (strstr(request, "GET /RenderingControl.xml") || 
                strstr(request, "GET /dlna/RenderingControl.xml")) {
                send_render_description(client_sock, "RenderingControl");
            }
            // 处理控制请求
            else if (strstr(request, "POST /upnp/control/AVTransport") || 
                    strstr(request, "POST /AVTransport/action") != NULL) {
                handle_avtransport_request(client_sock, request);
            }
            else {
                send_404_response(client_sock);
            }
        }
        close(client_sock);
    }
    
    close(http_sock);
    return NULL;
}

int main() {
    // 设置SSDP套接字
    int ssdp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ssdp_sock < 0) {
        perror("SSDP socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // 允许地址重用
    int reuse = 1;
    if (setsockopt(ssdp_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt (SO_REUSEADDR) failed");
        close(ssdp_sock);
        exit(EXIT_FAILURE);
    }

    // 设置接收超时
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    if (setsockopt(ssdp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt (SO_RCVTIMEO) failed");
        close(ssdp_sock);
        exit(EXIT_FAILURE);
    }
    
    // 绑定到SSDP端口
    struct sockaddr_in ssdp_addr;
    memset(&ssdp_addr, 0, sizeof(ssdp_addr));
    ssdp_addr.sin_family = AF_INET;
    ssdp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    ssdp_addr.sin_port = htons(SSDP_PORT);
    
    if (bind(ssdp_sock, (struct sockaddr *)&ssdp_addr, sizeof(ssdp_addr)) < 0) {
        perror("SSDP bind failed");
        close(ssdp_sock);
        exit(EXIT_FAILURE);
    }
    
    // 加入多播组
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(SSDP_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    
    if (setsockopt(ssdp_sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt (IP_ADD_MEMBERSHIP) failed");
        close(ssdp_sock);
        exit(EXIT_FAILURE);
    }
    
    // 启动HTTP服务器线程
    pthread_t http_thread;
    if (pthread_create(&http_thread, NULL, http_server_thread, NULL) != 0) {
        perror("Failed to create HTTP server thread");
        close(ssdp_sock);
        exit(EXIT_FAILURE);
    }
    
    printf("DLNA TV Simulator started\n");
    printf("Device UUID: %s\n", DEVICE_UUID);
    printf("Device type: %s\n", DEVICE_TYPE);
    
    // 初始通知
    send_ssdp_notify(ssdp_sock);
    
    // 主循环处理SSDP请求
    while (running) {
        char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        ssize_t len = recvfrom(ssdp_sock, buffer, BUFFER_SIZE - 1, 0, 
                              (struct sockaddr *)&client_addr, &client_len);
        if (len > 0) {
            buffer[len] = '\0';
            handle_ssdp_request(ssdp_sock, buffer, &client_addr);
        } else if (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            perror("recvfrom failed");
            break;
        }
        
        // 每隔30秒发送一次通知
        static time_t last_notify = 0;
        time_t now = time(NULL);
        if (difftime(now, last_notify) >= 3) {
            send_ssdp_notify(ssdp_sock);
            last_notify = now;
        }
    }
    
    // 清理
    running = 0;
    pthread_join(http_thread, NULL);
    close(ssdp_sock);
    
    printf("DLNA TV Simulator stopped\n");
    return 0;
}