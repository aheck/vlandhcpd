CMAKE_MINIMUM_REQUIRED (VERSION 2.8)
PROJECT (vlandhcpd)

SET(CMAKE_C_FLAGS "-ggdb -Wall -lpcap")

FIND_PACKAGE(PkgConfig)
PKG_CHECK_MODULES(GLIB2 glib-2.0)

INCLUDE_DIRECTORIES(${GLIB2_INCLUDE_DIRS})
LINK_DIRECTORIES(${GLIB2_LIBRARY_DIRS})
ADD_EXECUTABLE(vlandhcpd main.c arp.c dhcp.c pktbuf.c)
TARGET_LINK_LIBRARIES(vlandhcpd ${GLIB2_LIBRARIES})
