#pragma once

#define PUBLIC __attribute__ ((visibility("default")))

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Make a call.
/// @discussion Connect to service on host using protocol.
/// @param protname Protocol {udp[46], tcp[46], unixgram, unix}.
/// If the IPv{4,6} suffix is not given then the system will choose the protocol version.
/// @param hostname Hostname or dotted IP address.
/// @param servname Service name (see /etc/services) or port number.
/// @return int Positive file descriptor on success, negative errno otherwise.
int net_dial(char const *protname, char const *hostname, char const *servname) PUBLIC;

/// @brief Listen for connections.
/// @discussion Bind and listen (if appropriate) to service on host using protocol.
/// @param protname Protocol {udp[46], tcp[46], unixgram, unix}.
/// If the IPv{4,6} suffix is not given then the system will choose the protocol version.
/// @param hostname Hostname or dotted IP address.
/// @param servname Service name (see /etc/services) or port number.
/// @return int Positive file descriptor on success, negative errno otherwise.
int net_listen(char const *protname, char const *hostname, char const *servname) PUBLIC;

#ifdef __cplusplus
}
#endif
