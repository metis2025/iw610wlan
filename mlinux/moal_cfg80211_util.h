/** @file moal_cfg80211_util.h
 *
 * @brief This file contains the CFG80211 vendor specific defines.
 *
 *
 * Copyright 2015-2021, 2024 NXP
 *
 * NXP CONFIDENTIAL
 * The source code contained or described herein and all documents related to
 * the source code (Materials) are owned by NXP, its
 * suppliers and/or its licensors. Title to the Materials remains with NXP,
 * its suppliers and/or its licensors. The Materials contain
 * trade secrets and proprietary and confidential information of NXP, its
 * suppliers and/or its licensors. The Materials are protected by worldwide
 * copyright and trade secret laws and treaty provisions. No part of the
 * Materials may be used, copied, reproduced, modified, published, uploaded,
 * posted, transmitted, distributed, or disclosed in any way without NXP's prior
 * express written permission.
 *
 * No license under any patent, copyright, trade secret or other intellectual
 * property right is granted to or conferred upon you by disclosure or delivery
 * of the Materials, either expressly, by implication, inducement, estoppel or
 * otherwise. Any license under such intellectual property rights must be
 * express and approved by NXP in writing.
 *
 *  Alternatively, this software may be distributed under the terms of GPL v2.
 *  SPDX-License-Identifier:    GPL-2.0
 *
 */

#ifndef _MOAL_CFGVENDOR_H_
#define _MOAL_CFGVENDOR_H_

#include "moal_main.h"

#define TLV_TYPE_APINFO (PROPRIETARY_TLV_BASE_ID + 249)
#define TLV_TYPE_KEYINFO (PROPRIETARY_TLV_BASE_ID + 250)
#define TLV_TYPE_ASSOC_REQ_IE (PROPRIETARY_TLV_BASE_ID + 292)

/** Key Info structure */
typedef struct _key_info_tlv {
	/** Header */
	MrvlIEtypesHeader_t header;
	/** kck, kek, key_replay*/
	mlan_ds_misc_gtk_rekey_data key;
} key_info;

/** APinfo TLV structure */
typedef struct _apinfo_tlv {
	/** Header */
	MrvlIEtypesHeader_t header;
	/** Assoc response buffer */
	t_u8 rsp_ie[1];
} apinfo;

#if KERNEL_VERSION(3, 14, 0) <= CFG80211_VERSION_CODE

#define ATTRIBUTE_U32_LEN (nla_total_size(NLA_HDRLEN + 4))
#define VENDOR_ID_OVERHEAD ATTRIBUTE_U32_LEN
#define VENDOR_SUBCMD_OVERHEAD ATTRIBUTE_U32_LEN
#define VENDOR_DATA_OVERHEAD (nla_total_size(NLA_HDRLEN))

#define VENDOR_REPLY_OVERHEAD                                                  \
	(VENDOR_ID_OVERHEAD + VENDOR_SUBCMD_OVERHEAD + VENDOR_DATA_OVERHEAD)

/* Features Enums*/
#define WLAN_FEATURE_INFRA 0x0001 // Basic infrastructure mode support
#define WLAN_FEATURE_INFRA_5G 0x0002 // 5 GHz Band support
#define WLAN_FEATURE_HOTSPOT 0x0004 // GAS/ANQP support
#define WLAN_FEATURE_P2P 0x0008 // Wifi-Direct/P2P
#define WLAN_FEATURE_SOFT_AP 0x0010 // Soft AP support
#define WLAN_FEATURE_GSCAN 0x0020 // Google-Scan APIsi support
#define WLAN_FEATURE_NAN 0x0040 // Neighbor Awareness Networking (NAN)
#define WLAN_FEATURE_D2D_RTT 0x0080 // Device-to-device RTT support
#define WLAN_FEATURE_D2AP_RTT 0x0100 // Device-to-AP RTT support
#define WLAN_FEATURE_BATCH_SCAN 0x0200 // Batched Scan (legacy) support
#define WLAN_FEATURE_PNO 0x0400 // Preferred network offload support
#define WLAN_FEATURE_ADDITIONAL_STA 0x0800 // Two STAs support
#define WLAN_FEATURE_TDLS 0x1000 // Tunnel directed link setup (TDLS)
#define WLAN_FEATURE_TDLS_OFFCHANNEL 0x2000 // TDLS off channel support
#define WLAN_FEATURE_EPR 0x4000 // Enhanced power reporting support
#define WLAN_FEATURE_AP_STA 0x8000 // AP STA Concurrency support
#define WLAN_FEATURE_LINK_LAYER_STATS                                          \
	0x10000 // Link layer stats collection support
#define WLAN_FEATURE_LOGGER 0x20000 // WiFi Logger support
#define WLAN_FEATURE_HAL_EPNO 0x40000 // WiFi enhanced PNO support
#define WLAN_FEATURE_RSSI_MONITOR 0x80000 // RSSI Monitor support
#define WLAN_FEATURE_MKEEP_ALIVE 0x100000 // WiFi mkeep_alive support
#define WLAN_FEATURE_CONFIG_NDO 0x200000 // ND offload configure support
#define WLAN_FEATURE_TX_TRANSMIT_POWER                                         \
	0x400000 // Capture Tx transmit power levels
#define WLAN_FEATURE_CONTROL_ROAMING 0x800000 // Enable/Disable firmware roaming
#define WLAN_FEATURE_IE_WHITELIST 0x1000000 // Probe IE white listing support
#define WLAN_FEATURE_SCAN_RAND                                                 \
	0x2000000 // MAC & Probe Sequence Number randomization Support
// Add more features here

#define MAX_CHANNEL_NUM 200

/** Wifi Band */
typedef enum {
	WIFI_BAND_UNSPECIFIED,
	/** 2.4 GHz */
	WIFI_BAND_BG = 1,
	/** 5 GHz without DFS */
	WIFI_BAND_A = 2,
	/** 5 GHz DFS only */
	WIFI_BAND_A_DFS = 4,
	/** 5 GHz with DFS */
	WIFI_BAND_A_WITH_DFS = 6,
	/** 2.4 GHz + 5 GHz; no DFS */
	WIFI_BAND_ABG = 3,
	/** 2.4 GHz + 5 GHz with DFS */
	WIFI_BAND_ABG_WITH_DFS = 7,

	/** Keep it last */
	WIFI_BAND_LAST,
	WIFI_BAND_MAX = WIFI_BAND_LAST - 1,
} wifi_band;

typedef enum wifi_attr {
	ATTR_FEATURE_SET_INVALID = 0,
	ATTR_SCAN_MAC_OUI_SET = 1,
	ATTR_FEATURE_SET = 2,
	ATTR_NODFS_VALUE = 3,
	ATTR_COUNTRY_CODE = 4,
	ATTR_CHANNELS_BAND = 5,
	ATTR_NUM_CHANNELS = 6,
	ATTR_CHANNEL_LIST = 7,
	ATTR_GET_CONCURRENCY_MATRIX_SET_SIZE_MAX = 8,
	ATTR_GET_CONCURRENCY_MATRIX_SET_SIZE = 9,
	ATTR_GET_CONCURRENCY_MATRIX_SET = 10,
	ATTR_SCAN_BAND_SET = 11,
	ATTR_WIFI_AFTER_LAST,
	ATTR_WIFI_MAX = ATTR_WIFI_AFTER_LAST - 1
} wifi_attr_t;
enum mrvl_wlan_vendor_attr_wifi_logger {
	MRVL_WLAN_VENDOR_ATTR_NAME = 10,
};

enum ATTR_FW_RELOAD {
	ATTR_FW_RELOAD_INVALID = 0,
	ATTR_FW_RELOAD_MODE = 1,
	ATTR_FW_RELOAD_AFTER_LAST,
	ATTR_FW_RELOAD_MAX = ATTR_FW_RELOAD_AFTER_LAST - 1,
};

void woal_cfg80211_driver_hang_event(moal_private *priv, t_u8 reload_mode);

/**vendor event*/
enum vendor_event {
	event_hang = 0,
	event_fw_dump_done = 1,
	event_fw_reset_success = 2,
	event_fw_reset_failure = 3,
	event_fw_reset_start = 4,
	event_rssi_monitor = 0x1501,
	event_set_key_mgmt_offload = 0x10001,
	event_fw_roam_success = 0x10002,
	event_dfs_radar_detected = 0x10004,
	event_dfs_cac_started = 0x10005,
	event_dfs_cac_finished = 0x10006,
	event_dfs_cac_aborted = 0x10007,
	event_dfs_nop_finished = 0x10008,
	event_max,
};

/** struct dfs_event */
typedef struct _dfs_event {
	/** Frequency */
	int freq;
	/** HT enable */
	int ht_enabled;
	/** Channel Offset */
	int chan_offset;
	/** Channel width */
	enum nl80211_chan_width chan_width;
	/** Center Frequency 1 */
	int cf1;
	/** Center Frequency 2 */
	int cf2;
} dfs_event;

void woal_cfg80211_dfs_vendor_event(moal_private *priv, int event,
				    struct cfg80211_chan_def *chandef);

enum ATTR_RSSI_MONITOR {
	ATTR_RSSI_MONITOR_INVALID,
	ATTR_RSSI_MONITOR_CONTROL,
	ATTR_RSSI_MONITOR_MIN_RSSI,
	ATTR_RSSI_MONITOR_MAX_RSSI,
	ATTR_RSSI_MONITOR_CUR_BSSID,
	ATTR_RSSI_MONITOR_CUR_RSSI,
	ATTR_RSSI_MONITOR_AFTER_LAST,
	ATTR_RSSI_MONITOR_MAX = ATTR_RSSI_MONITOR_AFTER_LAST - 1,
};
void woal_cfg80211_rssi_monitor_event(moal_private *priv, t_s16 rssi);

/**vendor sub command*/
enum vendor_sub_command {
	sub_cmd_set_drvdbg = 0,
	sub_cmd_set_roaming_offload_key = 0x0002,
	sub_cmd_dfs_capability = 0x0005,
	sub_cmd_set_scan_mac_oui = 0x0007,
	sub_cmd_set_scan_band = 0x0008,
	sub_cmd_nd_offload = 0x0100,
	SUBCMD_SET_GET_SCANCFG = 0x0200,
	SUBCMD_SET_GET_ADDBAPARAMS = 0x0201,
	SUBCMD_SET_GET_CLR_HOSTCMD = 0x0202,
	sub_cmd_get_valid_channels = 0x1009,
	sub_cmd_get_wifi_supp_feature_set = 0x100a,
	sub_cmd_set_country_code = 0x100d,
	sub_cmd_get_fw_version = 0x1404,
	sub_cmd_get_drv_version = 0x1406,
	sub_cmd_rssi_monitor = 0x1500,
	subcmd_cfr_request = 0x1900,
	subcmd_cfr_cancel,
	subcmd_get_csi_dump_path,
	subcmd_get_csi_config,
	subcmd_get_csi_capa,
	sub_cmd_max,
};

void woal_register_cfg80211_vendor_command(struct wiphy *wiphy);
int woal_cfg80211_vendor_event(moal_private *priv, int event, t_u8 *data,
			       int len);

enum mrvl_wlan_vendor_attr {
	MRVL_WLAN_VENDOR_ATTR_INVALID = 0,
	/* Used by MRVL_NL80211_VENDOR_SUBCMD_DFS_CAPABILITY */
	MRVL_WLAN_VENDOR_ATTR_DFS = 1,
	MRVL_WLAN_VENDOR_ATTR_AFTER_LAST,

	MRVL_WLAN_VENDOR_ATTR_MAX = MRVL_WLAN_VENDOR_ATTR_AFTER_LAST - 1,
};

typedef enum {
	ATTR_ND_OFFLOAD_INVALID = 0,
	ATTR_ND_OFFLOAD_CONTROL,
	ATTR_ND_OFFLOAD_AFTER_LAST,
	ATTR_ND_OFFLOAD_MAX = ATTR_ND_OFFLOAD_AFTER_LAST - 1,
} ND_OFFLOAD_ATTR;

int woal_roam_ap_info(moal_private *priv, t_u8 *data, int len);

/*Attribute for wpa_supplicant*/
enum mrvl_wlan_vendor_attr_roam_auth {
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_INVALID = 0,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_BSSID,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_REQ_IE,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_RESP_IE,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_AUTHORIZED,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_KEY_REPLAY_CTR,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_PTK_KCK,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_PTK_KEK,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_SUBNET_STATUS,
	/* keep last */
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_AFTER_LAST,
	MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_MAX =
		MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_AFTER_LAST - 1
};

enum attr_csi {
	ATTR_CSI_INVALID = 0,
	ATTR_CSI_CONFIG,
	ATTR_PEER_MAC_ADDR,
	ATTR_CSI_DUMP_PATH,
	ATTR_CSI_CAPA,
	ATTR_CSI_DUMP_FORMAT,
	ATTR_CSI_AFTER_LAST,
	ATTR_CSI_MAX = ATTR_CSI_AFTER_LAST - 1,
};

/** CSI capability structure */
typedef struct {
	/**Bit mask indicates what BW is supported */
	t_u8 bw_support;
	/** Bit mask indicates what capturing method is supported */
	t_u8 method_support;
	/** Max number of capture peers supported */
	t_u8 max_peer;
} wifi_csi_capabilities;

mlan_status woal_cfg80211_event_csi_dump(moal_private *priv, t_u8 *data,
					 int len);
#endif
#endif /* _MOAL_CFGVENDOR_H_ */
