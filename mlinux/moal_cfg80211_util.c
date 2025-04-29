/** @file moal_cfg80211_util.c
 *
 * @brief This file contains the functions for CFG80211 vendor.
 *
 *
 * Copyright 2015-2022, 2024 NXP
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

#include "moal_cfg80211_util.h"
#include "moal_cfg80211.h"

/********************************************************
 *				Local Variables
 ********************************************************/

/********************************************************
 *				Global Variables
 ********************************************************/

/********************************************************
 *				Local Functions
 ********************************************************/

/********************************************************
 *				Global Functions
 ********************************************************/

#if KERNEL_VERSION(3, 14, 0) <= CFG80211_VERSION_CODE
/**nxp vendor command and event*/
#define MRVL_VENDOR_ID 0x005043
/** vendor events */
static const struct nl80211_vendor_cmd_info vendor_events[] = {
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_hang,
	}, /*event_id 0*/
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_fw_dump_done,
	}, /*event_id 1*/
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_fw_reset_success,
	}, /*event_id 2*/
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_fw_reset_failure,
	}, /*event_id 3*/
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_fw_reset_start,
	}, /*event_id 4*/
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_rssi_monitor,
	}, /*event_id 0x1501*/
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_set_key_mgmt_offload,
	}, /*event_id 0x10001*/
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_fw_roam_success,
	}, /*event_id 0x10002*/
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_dfs_radar_detected,
	}, /*event_id 0x10004*/
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_dfs_cac_started,
	}, /*event_id 0x10005*/
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_dfs_cac_finished,
	}, /*event_id 0x10006*/
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_dfs_cac_aborted,
	}, /*event_id 0x10007*/
	{
		.vendor_id = MRVL_VENDOR_ID,
		.subcmd = event_dfs_nop_finished,
	}, /*event_id 0x10008*/
	/**add vendor event here*/
};

/**nxp vendor policies*/
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE

static const struct nla_policy woal_attr_policy[ATTR_WIFI_MAX + 1] = {
	[ATTR_CHANNELS_BAND] = {.type = NLA_U32},
	[ATTR_SCAN_MAC_OUI_SET] = {.type = NLA_STRING, .len = 3},
	[ATTR_NODFS_VALUE] = {.type = NLA_U32},
	[ATTR_GET_CONCURRENCY_MATRIX_SET_SIZE_MAX] = {.type = NLA_U32},
	[ATTR_SCAN_BAND_SET] = {.type = NLA_U8},
};
// clang-format off
static const struct nla_policy
        woal_nd_offload_policy[ATTR_ND_OFFLOAD_MAX + 1] = {
		[ATTR_ND_OFFLOAD_CONTROL] = {.type = NLA_U8},
};
// clang-format on

static const struct nla_policy
	woal_rssi_monitor_policy[ATTR_RSSI_MONITOR_MAX + 1] = {
		[ATTR_RSSI_MONITOR_CONTROL] = {.type = NLA_U32},
		[ATTR_RSSI_MONITOR_MIN_RSSI] = {.type = NLA_S8},
		[ATTR_RSSI_MONITOR_MAX_RSSI] = {.type = NLA_S8},
};

// clang-format off
// clang-format on

#endif

/**
 * @brief get the event id of the events array
 *
 * @param event     vendor event
 *
 * @return    index of events array
 */
static int woal_get_event_id(int event)
{
	int i = 0;

	for (i = 0; i < (int)ARRAY_SIZE(vendor_events); i++) {
		if ((int)vendor_events[i].subcmd == event)
			return i;
	}

	return event_max;
}

/**
 * @brief send vendor event to kernel
 *
 * @param priv       A pointer to moal_private
 * @param event    vendor event
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  1: fail
 */
int woal_cfg80211_vendor_event(moal_private *priv, int event, t_u8 *data,
			       int len)
{
	struct wiphy *wiphy = NULL;
	struct sk_buff *skb = NULL;
	int event_id = 0;
	t_u8 *pos = NULL;
	int ret = 0;

	ENTER();

	if (!priv || !priv->wdev || !priv->wdev->wiphy) {
		LEAVE();
		return ret;
	}
	wiphy = priv->wdev->wiphy;
	PRINTM(MEVENT, "vendor event :0x%x\n", event);
	event_id = woal_get_event_id(event);
	if (event_max == event_id) {
		PRINTM(MERROR, "Not find this event %d\n", event_id);
		ret = 1;
		LEAVE();
		return ret;
	}

	/**allocate skb*/
#if KERNEL_VERSION(4, 1, 0) <= CFG80211_VERSION_CODE
	skb = cfg80211_vendor_event_alloc(wiphy, priv->wdev, len, event_id,
					  GFP_ATOMIC);
#else
	skb = cfg80211_vendor_event_alloc(wiphy, len, event_id, GFP_ATOMIC);
#endif

	if (!skb) {
		PRINTM(MERROR, "allocate memory fail for vendor event\n");
		ret = 1;
		LEAVE();
		return ret;
	}
	pos = skb_put(skb, len);
	moal_memcpy_ext(priv->phandle, pos, data, len, len);
	/**send event*/
	cfg80211_vendor_event(skb, GFP_ATOMIC);

	LEAVE();
	return ret;
}

#if KERNEL_VERSION(3, 14, 0) <= CFG80211_VERSION_CODE
/**
 * @brief send fw dump complete event to vendorhal
 *
 * @param priv       A pointer to moal_private
 *
 * @return      N/A
 */
void woal_cfg80211_vendor_event_fw_dump(moal_private *priv)
{
	PRINTM(MEVENT, "wlan: Notify FW dump complete event\n");
	woal_cfg80211_vendor_event(priv, event_fw_dump_done, CUS_EVT_FW_DUMP,
				   strlen(CUS_EVT_FW_DUMP));
}
#endif

/**
 * @brief send dfs vendor event to kernel
 *
 * @param priv       A pointer to moal_private
 * @param event      dfs vendor event
 * @param chandef    a pointer to struct cfg80211_chan_def
 *
 * @return      N/A
 */
void woal_cfg80211_dfs_vendor_event(moal_private *priv, int event,
				    struct cfg80211_chan_def *chandef)
{
	dfs_event evt;

	ENTER();
	if (!chandef) {
		LEAVE();
		return;
	}
	memset(&evt, 0, sizeof(dfs_event));
	evt.freq = chandef->chan->center_freq;
	evt.chan_width = chandef->width;
	evt.cf1 = chandef->center_freq1;
	evt.cf2 = chandef->center_freq2;
	switch (chandef->width) {
	case NL80211_CHAN_WIDTH_20_NOHT:
		evt.ht_enabled = 0;
		break;
	case NL80211_CHAN_WIDTH_20:
		evt.ht_enabled = 1;
		break;
	case NL80211_CHAN_WIDTH_40:
		evt.ht_enabled = 1;
		if (chandef->center_freq1 < chandef->chan->center_freq)
			evt.chan_offset = -1;
		else
			evt.chan_offset = 1;
		break;
	case NL80211_CHAN_WIDTH_80:
	case NL80211_CHAN_WIDTH_80P80:
	case NL80211_CHAN_WIDTH_160:
		evt.ht_enabled = 1;
		break;
	default:
		break;
	}
	woal_cfg80211_vendor_event(priv, event, (t_u8 *)&evt,
				   sizeof(dfs_event));
	LEAVE();
}

/**
 * @brief vendor command to set drvdbg
 *
 * @param wiphy       A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  1: fail
 */
static int woal_cfg80211_subcmd_set_drvdbg(struct wiphy *wiphy,
					   struct wireless_dev *wdev,
					   const void *data, int data_len)
{
#ifdef DEBUG_LEVEL1
	struct net_device *dev = wdev->netdev;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	struct sk_buff *skb = NULL;
	t_u8 *pos = NULL;
#endif
	int ret = 1;

	ENTER();
#ifdef DEBUG_LEVEL1
	/**handle this sub command*/
	DBG_HEXDUMP(MCMD_D, "Vendor drvdbg", (t_u8 *)data, data_len);

	if (data_len) {
		/* Get the driver debug bit masks from user */
		drvdbg = *((t_u32 *)data);
		PRINTM(MIOCTL, "new drvdbg %x\n", drvdbg);
		/* Set the driver debug bit masks into mlan */
		if (woal_set_drvdbg(priv, drvdbg)) {
			PRINTM(MERROR, "Set drvdbg failed!\n");
			ret = 1;
		}
	}
	/** Allocate skb for cmd reply*/
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, sizeof(drvdbg));
	if (!skb) {
		PRINTM(MERROR, "allocate memory fail for vendor cmd\n");
		ret = 1;
		LEAVE();
		return ret;
	}
	pos = skb_put(skb, sizeof(drvdbg));
	moal_memcpy_ext(priv->phandle, pos, &drvdbg, sizeof(drvdbg),
			sizeof(drvdbg));
	ret = cfg80211_vendor_cmd_reply(skb);
#endif
	LEAVE();
	return ret;
}

/**
 * @brief process one channel in bucket
 *
 * @param priv       A pointer to moal_private struct
 *
 * @param channel     a pointer to channel
 *
 * @return      0: success  other: fail
 */
static mlan_status woal_band_to_valid_channels(moal_private *priv,
					       wifi_band w_band, int channel[],
					       t_u32 *nchannel)
{
	int band = 0;
	struct ieee80211_supported_band *sband;
	struct ieee80211_channel *ch;
	int i = 0;
	t_u8 cnt = 0;
	int *ch_ptr = channel;

	for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
		if (!priv->wdev->wiphy->bands[band])
			continue;
		if ((band == IEEE80211_BAND_2GHZ) && !(w_band & WIFI_BAND_BG))
			continue;
		if ((band == IEEE80211_BAND_5GHZ) &&
		    !((w_band & WIFI_BAND_A) || (w_band & WIFI_BAND_A_DFS)))
			continue;
		sband = priv->wdev->wiphy->bands[band];
		for (i = 0; (i < sband->n_channels); i++) {
			ch = &sband->channels[i];
			if (ch->flags & IEEE80211_CHAN_DISABLED) {
				PRINTM(MERROR, "Skip DISABLED channel %d\n",
				       ch->center_freq);
				continue;
			}
			if (band == IEEE80211_BAND_5GHZ) {
				if (((ch->flags & IEEE80211_CHAN_RADAR) &&
				     !(w_band & WIFI_BAND_A_DFS)) ||
				    (!(ch->flags & IEEE80211_CHAN_RADAR) &&
				     !(w_band & WIFI_BAND_A)))
					continue;
			}
			if (cnt >= *nchannel) {
				PRINTM(MERROR,
				       "cnt=%d is exceed %d, cur ch=%d %dMHz\n",
				       cnt, *nchannel, ch->hw_value,
				       ch->center_freq);
				break;
			}
			*ch_ptr = ch->center_freq;
			ch_ptr++;
			cnt++;
		}
	}

	PRINTM(MCMND, "w_band=%d cnt=%d\n", w_band, cnt);
	*nchannel = cnt;
	return MLAN_STATUS_SUCCESS;
}

/**
 * @brief GSCAN subcmd - enable full scan results
 *
 * @param wiphy       A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 *
 * @param data     a pointer to data
 * @param  data_len     data length
 *
 * @return      0: success  other: fail
 */
static int woal_cfg80211_subcmd_get_valid_channels(struct wiphy *wiphy,
						   struct wireless_dev *wdev,
						   const void *data, int len)
{
	struct net_device *dev = wdev->netdev;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	struct nlattr *tb[ATTR_WIFI_MAX + 1];
	t_u32 band = 0;
	int ch_out[MAX_CHANNEL_NUM];
	t_u32 nchannel = 0;
	t_u32 mem_needed = 0;
	struct sk_buff *skb = NULL;
	int err = 0;

	ENTER();
	PRINTM(MCMND, "Enter %s()\n", __func__);

	err = nla_parse(tb, ATTR_WIFI_MAX, data, len, NULL
#if KERNEL_VERSION(4, 12, 0) <= CFG80211_VERSION_CODE
			,
			NULL
#endif
	);
	if (err) {
		PRINTM(MERROR, "%s: nla_parse fail\n", __func__);
		err = -EFAULT;
		goto done;
	}

	if (!tb[ATTR_CHANNELS_BAND]) {
		PRINTM(MERROR, "%s: null attr: tb[ATTR_GET_CH]=%p\n", __func__,
		       tb[ATTR_CHANNELS_BAND]);
		err = -EINVAL;
		goto done;
	}
	band = nla_get_u32(tb[ATTR_CHANNELS_BAND]);
	if (band > WIFI_BAND_MAX) {
		PRINTM(MERROR, "%s: invalid band=%d\n", __func__, band);
		err = -EINVAL;
		goto done;
	}

	memset(ch_out, 0x00, sizeof(ch_out));
	nchannel = MAX_CHANNEL_NUM;
	if (woal_band_to_valid_channels(priv, band, ch_out, &nchannel) !=
	    MLAN_STATUS_SUCCESS) {
		PRINTM(MERROR,
		       "get_channel_list: woal_band_to_valid_channels fail\n");
		return -EFAULT;
	}

	mem_needed = nla_total_size(nchannel * sizeof(ch_out[0])) +
		     nla_total_size(sizeof(nchannel)) + VENDOR_REPLY_OVERHEAD;
	/* Alloc the SKB for vendor_event */
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, mem_needed);
	if (unlikely(!skb)) {
		PRINTM(MERROR, "skb alloc failed");
		err = -ENOMEM;
		goto done;
	}

	if (nla_put_u32(skb, ATTR_NUM_CHANNELS, nchannel) ||
	    nla_put(skb, ATTR_CHANNEL_LIST, nchannel * sizeof(ch_out[0]),
		    ch_out)) {
		PRINTM(MERROR, "nla_put failed!\n");
		kfree_skb(skb);
		err = -ENOMEM;
		goto done;
	}
	err = cfg80211_vendor_cmd_reply(skb);
	if (err) {
		PRINTM(MERROR, "Vendor Command reply failed ret:%d\n", err);
		goto done;
	}

done:
	LEAVE();
	return err;
}

/**
 * @brief vendor command to get driver version
 *
 * @param wiphy       A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  1: fail
 */
static int woal_cfg80211_subcmd_get_drv_version(struct wiphy *wiphy,
						struct wireless_dev *wdev,
						const void *data, int data_len)
{
	struct net_device *dev = wdev->netdev;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	struct sk_buff *skb = NULL;
	t_u32 reply_len = 0;
	int ret = 0;
	t_u32 drv_len = 0;
	char drv_version[MLAN_MAX_VER_STR_LEN] = {0};
	char *pos;

	ENTER();
	moal_memcpy_ext(priv->phandle, drv_version,
			&priv->phandle->driver_version, MLAN_MAX_VER_STR_LEN,
			MLAN_MAX_VER_STR_LEN);
	drv_len = strlen(drv_version);
	pos = strstr(drv_version, "%s");
	/* remove 3 char "-%s" in driver_version string */
	if (pos != NULL)
		moal_memcpy_ext(priv->phandle, pos, pos + 3, strlen(pos) - 3,
				strlen(pos));

	reply_len = strlen(drv_version) + 1;
	drv_len -= 3;
	drv_version[drv_len] = '\0';

	/** Allocate skb for cmd reply*/
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, reply_len);
	if (!skb) {
		PRINTM(MERROR, "allocate memory fail for vendor cmd\n");
		ret = -ENOMEM;
		goto done;
	}

	nla_put(skb, MRVL_WLAN_VENDOR_ATTR_NAME, reply_len,
		(t_u8 *)drv_version);
	ret = cfg80211_vendor_cmd_reply(skb);
	if (ret)
		PRINTM(MERROR, "Vendor command reply failed ret = %d\n", ret);
done:
	LEAVE();
	return ret;
}

/**
 * @brief vendor command to get firmware version
 *
 * @param wiphy       A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  1: fail
 */
static int woal_cfg80211_subcmd_get_fw_version(struct wiphy *wiphy,
					       struct wireless_dev *wdev,
					       const void *data, int data_len)
{
	struct net_device *dev = wdev->netdev;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	struct sk_buff *skb = NULL;
	t_u32 reply_len = 0;
	char end_c = '\0';
	int ret = 0;
	char fw_ver[32] = {0};
	t_u8 hotfix_ver = 0;
	union {
		t_u32 l;
		t_u8 c[4];
	} ver;

	ENTER();

	hotfix_ver = priv->phandle->fw_hotfix_version;
	ver.l = priv->phandle->fw_release_number;
	if (hotfix_ver) {
		snprintf(fw_ver, sizeof(fw_ver), "%u.%u.%u.p%u.%u%c", ver.c[2],
			 ver.c[1], ver.c[0], ver.c[3], hotfix_ver, end_c);
	} else {
		snprintf(fw_ver, sizeof(fw_ver), "%u.%u.%u.p%u%c", ver.c[2],
			 ver.c[1], ver.c[0], ver.c[3], end_c);
	}
	reply_len = strlen(fw_ver) + 1;

	/** Allocate skb for cmd reply*/
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, reply_len);
	if (!skb) {
		PRINTM(MERROR, "allocate memory fail for vendor cmd\n");
		ret = -ENOMEM;
		goto done;
	}

	nla_put(skb, MRVL_WLAN_VENDOR_ATTR_NAME, reply_len, (t_u8 *)fw_ver);
	ret = cfg80211_vendor_cmd_reply(skb);
	if (ret)
		PRINTM(MERROR, "Vendor command reply failed ret = %d\n", ret);
done:
	LEAVE();
	return ret;
}

/**
 * @brief vendor command to get supported feature set
 *
 * @param wiphy       A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  1: fail
 */
static int woal_cfg80211_subcmd_get_supp_feature_set(struct wiphy *wiphy,
						     struct wireless_dev *wdev,
						     const void *data,
						     int data_len)
{
	struct sk_buff *skb = NULL;

	struct net_device *dev = wdev->netdev;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	mlan_fw_info fw_info;

	t_u32 reply_len = 0;
	int ret = 0;
	t_u32 supp_feature_set = 0;

	ENTER();
	supp_feature_set = WLAN_FEATURE_INFRA
#if defined(UAP_SUPPORT) && defined(STA_SUPPORT)
			   | WLAN_FEATURE_AP_STA
#endif
			   | WLAN_FEATURE_RSSI_MONITOR |
			   WLAN_FEATURE_CONFIG_NDO | WLAN_FEATURE_SCAN_RAND |
			   WLAN_FEATURE_TDLS;

	memset(&fw_info, 0, sizeof(mlan_fw_info));
	if (MLAN_STATUS_SUCCESS !=
	    woal_request_get_fw_info(priv, MOAL_IOCTL_WAIT, &fw_info)) {
		PRINTM(MERROR, "Fail to get fw info\n");
		ret = -EFAULT;
		goto done;
	}
	if (fw_info.fw_bands & BAND_A)
		supp_feature_set |= WLAN_FEATURE_INFRA_5G;

	priv->phandle->wifi_hal_flag = MTRUE;

	reply_len = sizeof(supp_feature_set);
	/** Allocate skb for cmd reply*/
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, reply_len);
	if (!skb) {
		PRINTM(MERROR, "allocate memory fail for vendor cmd\n");
		ret = -ENOMEM;
		goto done;
	}
	if (nla_put_u32(skb, ATTR_FEATURE_SET, supp_feature_set)) {
		PRINTM(MERROR, "nla_put failed!\n");
		kfree_skb(skb);
		ret = -ENOMEM;
		goto done;
	}
	ret = cfg80211_vendor_cmd_reply(skb);
	if (ret)
		PRINTM(MERROR, "Vendor command reply failed ret = %d\n", ret);
done:
	LEAVE();
	return ret;
}

/**
 * @brief vendor command to set country code
 *
 * @param wiphy       A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  1: fail
 */
static int woal_cfg80211_subcmd_set_country_code(struct wiphy *wiphy,
						 struct wireless_dev *wdev,
						 const void *data, int data_len)
{
	struct sk_buff *skb = NULL;
	t_u32 reply_len = 0;
	int ret = 0, rem, type;
	const struct nlattr *iter;
	char country[COUNTRY_CODE_LEN] = {0};

	ENTER();

	nla_for_each_attr (iter, data, data_len, rem) {
		type = nla_type(iter);
		switch (type) {
		case ATTR_COUNTRY_CODE:
			strncpy(country, nla_data(iter),
				MIN((int)sizeof(country) - 1, nla_len(iter)));
			break;
		default:
			PRINTM(MERROR, "Unknown type: %d\n", type);
			return ret;
		}
	}

	if (!moal_extflg_isset((moal_handle *)woal_get_wiphy_priv(wiphy),
			       EXT_DISABLE_REGD_BY_DRIVER))
		regulatory_hint(wiphy, country);

	/** Allocate skb for cmd reply*/
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, reply_len);
	if (!skb) {
		PRINTM(MERROR, "allocate memory fail for vendor cmd\n");
		ret = -ENOMEM;
		goto done;
	}

	ret = cfg80211_vendor_cmd_reply(skb);
	if (ret)
		PRINTM(MERROR, "Vendor command reply failed ret = %d\n", ret);
done:
	LEAVE();
	return ret;
}

/**
 * @brief Prints the scancfg params from the mlan_ds_scan struct
 *
 * @param scan	A pointer to mlan_ds_scan struct
 *
 * @return      void
 */
static void woal_print_scancfg_params(mlan_ds_scan *scan)
{
	if (!scan)
		return;
	PRINTM(MCMND,
	       "scancfg params: scan_type = 0x%x, scan_mode = 0x%x, scan_probe = 0x%x \n",
	       scan->param.scan_cfg.scan_type, scan->param.scan_cfg.scan_mode,
	       scan->param.scan_cfg.scan_probe);

	PRINTM(MCMND, "scancfg params: passive_to_active_scan = 0x%x \n",
	       scan->param.scan_cfg.passive_to_active_scan);

	PRINTM(MCMND,
	       "scancfg params: specific_scan_time = 0x%x, active_scan_time = 0x%x, passive_scan_time = 0x%x \n",
	       scan->param.scan_cfg.scan_time.specific_scan_time,
	       scan->param.scan_cfg.scan_time.active_scan_time,
	       scan->param.scan_cfg.scan_time.passive_scan_time);

	PRINTM(MCMND, "scancfg params: ext_scan = 0x%x\n",
	       scan->param.scan_cfg.ext_scan);
	PRINTM(MCMND, "scancfg params: scan_chan_gap = 0x%x\n",
	       scan->param.scan_cfg.scan_chan_gap);
}

/**
 * @brief Parse the vendor cmd input data based on attribute len
 * 	  and copy each attrubute into a output buffer/integer array
 *
 * @param data			A pointer to input data buffer
 * @param data_len		Input data buffer total len
 * @param user_buff		A pointer to output data buffer after the
 * parsing
 * @param buff_len		Maximum no. of data attributes to be parsed
 * @param user_data_len		No. of data attributes that are parsed
 *
 * @return      0: success  -1: fail
 */
static int woal_parse_vendor_cmd_attributes(t_u8 *data, t_u32 data_len,
					    t_u32 *user_buff, t_u32 buff_len,
					    t_u16 *user_data_len)
{
	t_u16 i = 0, j = 0, len = 0;

	len = strlen(data);
	for (i = 0, j = 0; (i < data_len) && (j < buff_len); ++j) {
		t_u32 value = 0, value1 = 0;
		t_u8 attr_len = 0;
		attr_len = (t_u8) * (data + i);
		++i;
		if (attr_len > 0) {
			t_u8 k = 0;
			for (k = 0; k < attr_len; ++k) {
				value1 = (t_u8) * (data + i + k);
				value = (value << 8) + value1;
			}
			i = i + k;
		} else {
			PRINTM(MERROR, "\nIn parse_args: Invalid attr_len \n");
			*user_data_len = 0;
			return -1;
		}
		user_buff[j] = value;
	}
	*user_data_len = j;
	return 0;
}

/**
 * @brief Vendor cmd to trigger the scancfg params.
 *	Set/Get the scancfg params to/from driver
 *
 * @param wiphy    A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  -1: fail
 */
static int woal_cfg80211_subcmd_set_get_scancfg(struct wiphy *wiphy,
						struct wireless_dev *wdev,
						const void *data, int len)
{
	struct net_device *dev = wdev->netdev;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	mlan_ds_scan *scan = NULL;
	mlan_ioctl_req *req = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;
	struct sk_buff *skb = NULL;
	t_s32 user_data[9];
	t_s32 ret = 0;
	t_u16 user_data_len = 0;
	t_u16 ret_length = 1;
	t_u8 get_data = 0, get_val = 0;
	t_u8 *data_buff = (t_u8 *)data;
	t_u8 *pos = NULL;
	ENTER();

	if (len < 1) {
		PRINTM(MERROR, "vendor cmd: scancfg - Invalid data length!\n");
		ret = -EINVAL;
		goto done;
	}
	if (len == 1) {
		PRINTM(MMSG, "vendor cmd: Get scancfg params!\n");
		get_val = (t_u8) * (data_buff);

		/* Get scancfg works if an input argument passed is 00 */
		if (get_val) {
			PRINTM(MERROR,
			       "vendor cmd: Get scancfg failed due to Invalid argument!\n");
			ret = -EINVAL;
			goto done;
		}
		get_data = 1;
	} else if (len > 1) {
		PRINTM(MMSG, "Vendor cmd: Set scancfg params!\n");
		memset((char *)user_data, 0, sizeof(user_data));

		/* vendor cmd : the user_data_len is set only for set cmd */
		if (woal_parse_vendor_cmd_attributes(data_buff, len, user_data,
						     ARRAY_SIZE(user_data),
						     &user_data_len)) {
			PRINTM(MMSG,
			       "vendor cmd: Couldn't parse the scancfg params!\n");
			ret = -EINVAL;
			goto done;
		}
	}

	/* Allocate an IOCTL request buffer */
	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_scan));
	if (req == NULL) {
		PRINTM(MERROR,
		       "vendor cmd: Could not allocate mlan ioctl request, scancfg!\n");
		ret = -ENOMEM;
		goto done;
	}

	/* Fill request buffer */
	scan = (mlan_ds_scan *)req->pbuf;
	scan->sub_command = MLAN_OID_SCAN_CONFIG;
	req->req_id = MLAN_IOCTL_SCAN;

	/* Validate each scancfg parameters */
	if (user_data_len) {
		DBG_HEXDUMP(MCMD_D, "scancfg input dump: ", (t_u8 *)user_data,
			    (user_data_len * sizeof(t_u32)));
		moal_memcpy_ext(priv->phandle, &scan->param.scan_cfg, user_data,
				sizeof(user_data),
				sizeof(scan->param.scan_cfg));
		if (scan->param.scan_cfg.scan_type > MLAN_SCAN_TYPE_PASSIVE) {
			PRINTM(MERROR,
			       "vendor cmd:Invalid argument for scan type\n");
			ret = -EINVAL;
			goto done;
		}
		if (scan->param.scan_cfg.scan_mode > MLAN_SCAN_MODE_ANY) {
			PRINTM(MERROR,
			       "vendor cmd:Invalid argument for scan mode\n");
			ret = -EINVAL;
			goto done;
		}
		if (scan->param.scan_cfg.scan_probe > MAX_PROBES) {
			PRINTM(MERROR,
			       "vendor cmd:Invalid argument for scan probes\n");
			ret = -EINVAL;
			goto done;
		}
		if ((scan->param.scan_cfg.scan_time.specific_scan_time >
		     MRVDRV_MAX_ACTIVE_SCAN_CHAN_TIME) ||
		    (scan->param.scan_cfg.scan_time.active_scan_time >
		     MRVDRV_MAX_ACTIVE_SCAN_CHAN_TIME) ||
		    (scan->param.scan_cfg.scan_time.passive_scan_time >
		     MRVDRV_MAX_PASSIVE_SCAN_CHAN_TIME)) {
			PRINTM(MERROR, "Invalid argument for scan time\n");
			ret = -EINVAL;
			goto done;
		}
		if (scan->param.scan_cfg.passive_to_active_scan >
		    MLAN_PASS_TO_ACT_SCAN_DIS) {
			PRINTM(MERROR,
			       "Invalid argument for Passive to Active Scan\n");
			ret = -EINVAL;
			goto done;
		}
		if (scan->param.scan_cfg.ext_scan > MLAN_EXT_SCAN_ENH) {
			PRINTM(MERROR, "Invalid argument for extended scan\n");
			ret = -EINVAL;
			goto done;
		}
		if (scan->param.scan_cfg.scan_chan_gap >
		    MRVDRV_MAX_SCAN_CHAN_GAP_TIME) {
			PRINTM(MERROR,
			       "Invalid argument for scan channel gap\n");
			ret = -EINVAL;
			goto done;
		}

		req->action = MLAN_ACT_SET;
		if (scan->param.scan_cfg.scan_time.specific_scan_time)
			priv->phandle->user_scan_cfg = MTRUE;
		PRINTM(MINFO, "vendor cmd: SET ioctl request for scanfg\n");
		woal_print_scancfg_params(scan);
	} else {
		PRINTM(MINFO, "vendor cmd: GET ioctl request for scanfg\n");
		req->action = MLAN_ACT_GET;
	}

	/* Send IOCTL request to MLAN */
	status = woal_request_ioctl(priv, req, MOAL_IOCTL_WAIT);
	if (status == MLAN_STATUS_SUCCESS) {
		PRINTM(MMSG, "Set/Get scancfg ioctl successfull\n");
		if (!user_data_len) {
			moal_memcpy_ext(priv->phandle, user_data,
					&scan->param.scan_cfg,
					sizeof(scan->param.scan_cfg),
					sizeof(user_data));
			DBG_HEXDUMP(MCMD_D, "scancfg dump: ", (t_u8 *)user_data,
				    sizeof(user_data));
			ret_length = sizeof(mlan_scan_cfg);
		}
	} else {
		PRINTM(MERROR, "Set/Get scancfg ioctl failed!\n");
		ret = -EFAULT;
		goto done;
	}

	/* Allocate skb for cmd reply*/
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, ret_length);
	if (!skb) {
		PRINTM(MERROR,
		       "vendor cmd: allocate memory fail for vendor cmd\n");
		ret = -ENOMEM;
		goto done;
	}
	/* Get scancfg if an input argument passed is 00 */
	if (!user_data_len && get_data == 1) {
		PRINTM(MINFO, "vendor cmd: copying the response into buffer\n");
		scan = (mlan_ds_scan *)req->pbuf;
		pos = skb_put(skb, sizeof(mlan_scan_cfg));
		moal_memcpy_ext(priv->phandle, pos, &scan->param.scan_cfg,
				sizeof(mlan_scan_cfg), sizeof(mlan_scan_cfg));
		woal_print_scancfg_params(scan);
	}

	ret = cfg80211_vendor_cmd_reply(skb);
	if (unlikely(ret))
		PRINTM(MERROR, "vendor cmd: reply failed with ret:%d \n", ret);

done:
	if (status != MLAN_STATUS_PENDING && req)
		kfree(req);

	LEAVE();
	return ret;
}

/*
 * @brief A common function copies an user data(from integer array) into
 * different types of structures. Declare a layout based on each member size of
 * a strucure within the caller().
 *
 * @param phandle		A pointer to moal handler
 * @param dest_struct		Final destination strucuture
 * @param src_data		A pointer to input user data/integer array
 * @param src_data_len		Input user data length
 * @param dest_struct_len	Destination data structure length
 * @param layout		A pointer to integer array/layout describing struct
 * member
 * *
 * @return      0: success  -1: fail
 * */
static void
woal_memcpy_user_intarray_to_struct(moal_handle *phandle, void *dest_struct,
				    t_u32 *src_data, t_u32 src_data_len,
				    t_u32 dest_struct_len, t_u32 *layout)
{
	t_u8 *dest = (t_u8 *)dest_struct;
	t_u16 i = 0;

	if (!dest_struct || !src_data) {
		PRINTM(MERROR, "dest/src pointer is null\n");
	}

	for (i = 0; (layout[i] > 0 && i < src_data_len); ++i) {
		moal_memcpy_ext(phandle, dest, src_data, layout[i], layout[i]);
		dest += layout[i];
		if (layout[i] > sizeof(t_u32)) {
			src_data += layout[i] / sizeof(t_u32);
			src_data += (layout[i] % sizeof(t_u32)) ? 1 : 0;
		} else
			src_data += 1;
	}
}

/*
 * @brief A common function directly copies different type of structures into
 * user data buffer(integere array). Declare a layout based on each member size
 * of a strucure within the caller function.
 *
 * @param phandle		A pointer to moal handler
 * @param dest_data		A pointer to destination data buffer/integer
 * array
 * @param src_struct		A pointer to source structure
 * @param src_struct_len	Source data structure length
 * @param dest_data_len		Destination user data length
 * @param layout		A pointer to integer array/layout describing struct
 * member
 * *
 * @return      0: success  -1: fail
 * */
static void
woal_memcpy_struct_to_user_intarray(moal_handle *phandle, t_u32 *dest_data,
				    void *src_struct, t_u32 src_struct_len,
				    t_u32 dest_data_len, t_u32 *layout)
{
	t_u8 *src = (t_u8 *)src_struct;
	t_u16 i = 0;

	if (!dest_data || !src_struct) {
		PRINTM(MERROR, "dest/src pointer is null\n");
	}

	for (i = 0; (layout[i] > 0 && i < dest_data_len); ++i) {
		moal_memcpy_ext(phandle, dest_data, src, layout[i], layout[i]);
		src += layout[i];
		if (layout[i] > sizeof(t_u32)) {
			dest_data += layout[i] / sizeof(t_u32);
			dest_data += (layout[i] % sizeof(t_u32)) ? 1 : 0;
		} else
			dest_data += 1;
	}
}

/**
 * @brief Prints the addba params from the woal_print_addba_param
 *
 * @param scan	A pointer to woal_print_addba_param struct
 *
 * @return      void
 */
static void woal_print_addba_params(mlan_ds_11n_addba_param *addba)
{
	if (!addba) {
		PRINTM(MERROR, "addba param is null\n");
		return;
	}

	PRINTM(MCMND,
	       "ADDBA: timeout:%d txwinsize:%d rxwinsize:%d txamsdu=%d, rxamsdu=%d\n",
	       addba->timeout, addba->txwinsize, addba->rxwinsize,
	       addba->txamsdu, addba->rxamsdu);
	return;
}

/**
 * @brief API to trigger the addba params.
 *	It sets or gets the addba params
 *
 * @param wiphy    A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  -1: fail
 */
static int woal_cfg80211_subcmd_set_get_addbaparams(struct wiphy *wiphy,
						    struct wireless_dev *wdev,
						    const void *data, int len)
{
	struct net_device *dev = wdev->netdev;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	mlan_ds_11n_cfg *cfg_addba = NULL;
	mlan_ioctl_req *req = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;
	struct sk_buff *skb = NULL;
	t_u32 user_data[5];
	/* Define layout as per required structure */
	t_u32 layout[5] = {sizeof(t_u32), sizeof(t_u32), sizeof(t_u32),
			   sizeof(char), sizeof(char)};
	t_s32 ret = 0;
	t_u16 user_data_len = 0;
	t_u16 ret_length = 1;
	t_u8 get_data = 0, get_val = 0;
	t_u8 *data_buff = (t_u8 *)data;
	t_u8 *pos = NULL;
	ENTER();

	if (len < 1) {
		PRINTM(MERROR,
		       "vendor cmd: addbaparams - Invalid data length!\n");
		ret = -EINVAL;
		goto done;
	}
	if (len == 1) {
		PRINTM(MMSG, "vendor cmd: Get addbaparams!\n");
		get_val = (t_u8) * (data_buff);

		/* Get addbaparams works if an input argument passed is 00 */
		if (get_val) {
			PRINTM(MERROR,
			       "vendor cmd: Get addbaparams failed due to Invalid argument!\n");
			ret = -EINVAL;
			goto done;
		}
		get_data = 1;
		memset((char *)user_data, 0, sizeof(user_data));
	} else if (len > 1) {
		PRINTM(MMSG, "Vendor cmd: Set addbaparams !\n");
		memset((char *)user_data, 0, sizeof(user_data));

		/* vendor cmd : the user_data_len is set only for set cmd */
		if (woal_parse_vendor_cmd_attributes(data_buff, len, user_data,
						     ARRAY_SIZE(user_data),
						     &user_data_len)) {
			PRINTM(MERROR,
			       "vendor cmd: Couldn't parse the addbaparams!\n");
			ret = -EINVAL;
			goto done;
		}
	}

	/* Allocate an IOCTL request buffer */
	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_11n_cfg));
	if (req == NULL) {
		PRINTM(MERROR,
		       "vendor cmd: Could not allocate mlan ioctl request, addbaparams!\n");
		ret = -ENOMEM;
		goto done;
	}

	/* Fill request buffer */
	cfg_addba = (mlan_ds_11n_cfg *)req->pbuf;
	cfg_addba->sub_command = MLAN_OID_11N_CFG_ADDBA_PARAM;
	req->req_id = MLAN_IOCTL_11N_CFG;

	/* Validate each addbaparams parameters */
	if (user_data_len) {
		DBG_HEXDUMP(MCMD_D,
			    "addbaparams input dump: ", (t_u8 *)user_data,
			    (user_data_len * sizeof(t_u32)));
		/* To copy an user data in an integer array format into strcture
		 */
		woal_memcpy_user_intarray_to_struct(
			priv->phandle, (void *)&cfg_addba->param.addba_param,
			user_data, ARRAY_SIZE(user_data),
			sizeof(cfg_addba->param.addba_param), layout);

		woal_print_addba_params(&cfg_addba->param.addba_param);
		if (cfg_addba->param.addba_param.timeout >
		    MLAN_DEFAULT_BLOCK_ACK_TIMEOUT) {
			PRINTM(MERROR, "Incorrect addba timeout value.\n");
			ret = -EINVAL;
			goto done;
		}
		if (cfg_addba->param.addba_param.txwinsize >
		    MLAN_AMPDU_MAX_TXWINSIZE) {
			PRINTM(MERROR, "Incorrect Tx window size.\n");
			ret = -EINVAL;
			goto done;
		}
		if (cfg_addba->param.addba_param.rxwinsize >
		    MLAN_AMPDU_MAX_RXWINSIZE) {
			PRINTM(MERROR, "Incorrect Rx window size.\n");
			ret = -EINVAL;
			goto done;
		}
		if (cfg_addba->param.addba_param.txamsdu > 1 ||
		    cfg_addba->param.addba_param.rxamsdu > 1) {
			PRINTM(MERROR, "Incorrect Tx/Rx amsdu.\n");
			ret = -EINVAL;
			goto done;
		}
		req->action = MLAN_ACT_SET;
		PRINTM(MINFO,
		       "vendor cmd: SET ioctl request for addbaparams\n");
	} else {
		PRINTM(MINFO,
		       "vendor cmd: GET ioctl request for addbaparams\n");
		req->action = MLAN_ACT_GET;
	}

	/* Send IOCTL request to MLAN */
	status = woal_request_ioctl(priv, req, MOAL_IOCTL_WAIT);
	if (status == MLAN_STATUS_SUCCESS) {
		PRINTM(MMSG, "Set/Get addbaparams ioctl successfull\n");
		if (!user_data_len) {
			/* To copy an strcture members into user data/integer
			 * array separately */
			woal_memcpy_struct_to_user_intarray(
				priv->phandle, user_data,
				(void *)&cfg_addba->param.addba_param,
				sizeof(cfg_addba->param.addba_param),
				ARRAY_SIZE(user_data), layout);
			woal_print_addba_params(&cfg_addba->param.addba_param);
			ret_length = sizeof(user_data);
		}
	} else {
		PRINTM(MERROR, "Set/Get addbaparams ioctl failed!\n");
		ret = -EFAULT;
		goto done;
	}

	/* Allocate skb for cmd reply*/
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, ret_length);
	if (!skb) {
		PRINTM(MERROR,
		       "vendor cmd: allocate memory fail for vendor cmd\n");
		ret = -ENOMEM;
		goto done;
	}

	/* Get addbaparams if an input data argument is 00 */
	if (!user_data_len && get_data == 1) {
		PRINTM(MINFO, "vendor cmd: copying the response into buffer\n");
		DBG_HEXDUMP(MCMD_D, "addbaparams dump: ", (t_u8 *)user_data,
			    sizeof(user_data));
		cfg_addba = (mlan_ds_11n_cfg *)req->pbuf;
		pos = skb_put(skb, sizeof(user_data));
		moal_memcpy_ext(priv->phandle, pos, user_data,
				sizeof(user_data), sizeof(user_data));
	}

	ret = cfg80211_vendor_cmd_reply(skb);
	if (unlikely(ret))
		PRINTM(MERROR, "vendor cmd: reply failed with ret:%d \n", ret);

done:
	if (status != MLAN_STATUS_PENDING && req)
		kfree(req);
	LEAVE();
	return ret;
}

/**
 * @brief API to trigger the vendor cmd related to
 * hostcmd/sys_cfg_80211d_country_ie. It sets/get/clear the function/operation
 * that is specific the hostcmd.
 *
 * @param wiphy    A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  -1: fail
 */
static int woal_cfg80211_subcmd_hostcmd(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data, int len)
{
	struct net_device *dev = wdev->netdev;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	mlan_ds_misc_cfg *misc_cfg = NULL;
	mlan_ioctl_req *req = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;
	struct sk_buff *skb = NULL;
	HostCmd_DS_GEN cmd_info;
	t_s32 ret = 0;
	t_u16 ret_length = 1;
	t_u16 action = 0;
	t_u8 get_data = 0;
	t_u8 *data_buff = (t_u8 *)data;
	t_u8 *pos = NULL;
	ENTER();

	if (len < (sizeof(HostCmd_DS_GEN) + sizeof(action))) {
		PRINTM(MERROR, "vendor cmd: Invalid hostcmd!\n");
		ret = -EINVAL;
		goto done;
	}

	moal_memcpy_ext(priv->phandle, &cmd_info, data_buff,
			sizeof(HostCmd_DS_GEN), sizeof(HostCmd_DS_GEN));
	action = (u16) * (data_buff + sizeof(cmd_info));

	PRINTM(MMSG, "vendor cmd: hostcmd len=%d, action=%d\n", len, action);
	if (action == 0)
		get_data = 1;

	/* Allocate an IOCTL request buffer */
	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_misc_cfg));
	if (req == NULL) {
		PRINTM(MERROR,
		       "vendor cmd: Could not allocate mlan ioctl memory, hostcmd!\n");
		ret = -ENOMEM;
		goto done;
	}

	/* Fill request buffer */
	misc_cfg = (mlan_ds_misc_cfg *)req->pbuf;
	misc_cfg->sub_command = MLAN_OID_MISC_HOST_CMD;
	req->req_id = MLAN_IOCTL_MISC_CFG;
	req->action = action;
	misc_cfg->param.hostcmd.len = woal_le16_to_cpu(cmd_info.size);

	/* Copy the entire command data into hostcmd cmd buffer */
	moal_memcpy_ext(priv->phandle, misc_cfg->param.hostcmd.cmd, data_buff,
			misc_cfg->param.hostcmd.len, MRVDRV_SIZE_OF_CMD_BUFFER);

	DBG_HEXDUMP(MCMD_D, "vendor cmd: hostcmd cmd dump",
		    (t_u8 *)misc_cfg->param.hostcmd.cmd,
		    misc_cfg->param.hostcmd.len);

	/* Send IOCTL request to MLAN */
	status = woal_request_ioctl(priv, req, MOAL_IOCTL_WAIT);
	if (status == MLAN_STATUS_SUCCESS) {
		PRINTM(MMSG, "Set/Clear/Get hostcmd ioctl successfull\n");
		if (get_data) {
			ret_length = misc_cfg->param.hostcmd.len;
			PRINTM(MMSG, "vendor cmd: hostcmd GET, len=%d\n",
			       ret_length);
		}
	} else {
		PRINTM(MERROR, "Set/Clear/Get hostcmd ioctl failed!\n");
		ret = -EFAULT;
		goto done;
	}

	/* Allocate skb for cmd reply*/
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, ret_length);
	if (!skb) {
		PRINTM(MERROR, "vendor cmd: memory allocation failed \n");
		ret = -ENOMEM;
		goto done;
	}

	if (get_data && ret_length > 1) {
		PRINTM(MINFO, "vendor cmd: copying the response into buffer\n");
		DBG_HEXDUMP(MCMD_D, "vendor cmd: hostcmd dump",
			    (t_u8 *)misc_cfg->param.hostcmd.cmd, ret_length);
		pos = skb_put(skb, ret_length);
		moal_memcpy_ext(priv->phandle, pos, misc_cfg->param.hostcmd.cmd,
				misc_cfg->param.hostcmd.len,
				misc_cfg->param.hostcmd.len);
	}

	ret = cfg80211_vendor_cmd_reply(skb);
	if (unlikely(ret))
		PRINTM(MERROR, "vendor cmd: reply failed with ret:%d \n", ret);
done:
	if (status != MLAN_STATUS_PENDING && req)
		kfree(req);
	LEAVE();
	return ret;
}

#ifdef STA_CFG80211
#define RSSI_MONOTOR_START 1
#define RSSI_MONOTOR_STOP 0

/**
 * @brief vendor command to control rssi monitor
 *
 * @param wiphy    A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  -1: fail
 */
static int woal_cfg80211_subcmd_rssi_monitor(struct wiphy *wiphy,
					     struct wireless_dev *wdev,
					     const void *data, int len)
{
	struct nlattr *tb[ATTR_RSSI_MONITOR_MAX + 1];
	moal_private *priv = (moal_private *)woal_get_netdev_priv(wdev->netdev);
	u32 rssi_monitor_control = 0x0;
	s8 rssi_min = 0, rssi_max = 0;
	int err = 0;
	t_u8 *pos = NULL;
	struct sk_buff *skb = NULL;
	int ret = 0;

	ENTER();

	if (!priv->media_connected) {
		ret = -EINVAL;
		goto done;
	}

	ret = nla_parse(tb, ATTR_RSSI_MONITOR_MAX, data, len, NULL
#if KERNEL_VERSION(4, 12, 0) <= CFG80211_VERSION_CODE
			,
			NULL
#endif
	);
	if (ret)
		goto done;

	if (!tb[ATTR_RSSI_MONITOR_CONTROL]) {
		ret = -EINVAL;
		goto done;
	}
	rssi_monitor_control = nla_get_u32(tb[ATTR_RSSI_MONITOR_CONTROL]);

	if (rssi_monitor_control == RSSI_MONOTOR_START) {
		if ((!tb[ATTR_RSSI_MONITOR_MIN_RSSI]) ||
		    (!tb[ATTR_RSSI_MONITOR_MAX_RSSI])) {
			ret = -EINVAL;
			goto done;
		}

		rssi_min = nla_get_s8(tb[ATTR_RSSI_MONITOR_MIN_RSSI]);
		rssi_max = nla_get_s8(tb[ATTR_RSSI_MONITOR_MAX_RSSI]);

		PRINTM(MEVENT,
		       "start rssi monitor rssi_min = %d, rssi_max= %d\n",
		       rssi_min, rssi_max);

		/* set rssi low/high threshold */
		priv->cqm_rssi_high_thold = rssi_max;
		priv->cqm_rssi_thold = rssi_min;
		priv->cqm_rssi_hyst = 4;
		if (MLAN_STATUS_SUCCESS !=
		    woal_set_rssi_threshold(priv, 0, MOAL_IOCTL_WAIT)) {
			PRINTM(MERROR, "set rssi threhold fail\n");
			ret = -EFAULT;
			goto done;
		}
	} else if (rssi_monitor_control == RSSI_MONOTOR_STOP) {
		/* stop rssi monitor */
		PRINTM(MEVENT, "stop rssi monitor\n");
		/* set both rssi_thold/hyst to 0, will trigger subscribe event
		 * clear
		 */
		priv->cqm_rssi_high_thold = 0;
		priv->cqm_rssi_thold = 0;
		priv->cqm_rssi_hyst = 0;
		if (MLAN_STATUS_SUCCESS !=
		    woal_set_rssi_threshold(priv, 0, MOAL_IOCTL_WAIT)) {
			PRINTM(MERROR, "set rssi threhold fail\n");
			ret = -EFAULT;
			goto done;
		}
	} else {
		PRINTM(MERROR, "invalid rssi_monitor control request\n");
		ret = -EINVAL;
		goto done;
	}

	/* Alloc the SKB for cmd reply */
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, len);
	if (unlikely(!skb)) {
		PRINTM(MERROR, "skb alloc failed\n");
		ret = -EINVAL;
		goto done;
	}
	pos = skb_put(skb, len);
	moal_memcpy_ext(priv->phandle, pos, data, len, len);
	err = cfg80211_vendor_cmd_reply(skb);
	if (unlikely(err)) {
		PRINTM(MERROR, "Vendor Command reply failed ret:%d\n", err);
		ret = err;
	}
done:
	LEAVE();
	return ret;
}

/**
 * @brief send rssi event to kernel
 *
 * @param priv       A pointer to moal_private
 * @param rssi       current rssi value
 *
 * @return      N/A
 */
void woal_cfg80211_rssi_monitor_event(moal_private *priv, t_s16 rssi)
{
	struct sk_buff *skb = NULL;
	t_s8 rssi_value = 0;

	ENTER();

	skb = dev_alloc_skb(NLA_HDRLEN * 2 + ETH_ALEN + sizeof(t_s8));
	if (!skb)
		goto done;
	/* convert t_s16 to t_s8*/
	rssi_value = -abs(rssi);
	if (nla_put(skb, ATTR_RSSI_MONITOR_CUR_BSSID, ETH_ALEN,
		    priv->conn_bssid) ||
	    nla_put_s8(skb, ATTR_RSSI_MONITOR_CUR_RSSI, rssi_value)) {
		PRINTM(MERROR, "nla_put failed!\n");
		dev_kfree_skb(skb);
		goto done;
	}
	woal_cfg80211_vendor_event(priv, event_rssi_monitor, (t_u8 *)skb->data,
				   skb->len);
	dev_kfree_skb(skb);
done:
	LEAVE();
}

/**
 * @brief send driver hang vendor event to kernel
 *
 * @param priv          A pointer to moal_private
 * @param reload_mode   reload mode
 *
 * @return      N/A
 */
void woal_cfg80211_driver_hang_event(moal_private *priv, t_u8 reload_mode)
{
	struct sk_buff *skb = NULL;

	ENTER();

	skb = dev_alloc_skb(NLA_HDRLEN + sizeof(t_u8));
	if (!skb) {
		PRINTM(MERROR,
		       "woal_cfg80211_driver_hang_event: Failed to allocate skb");
		goto done;
	}

	if (nla_put_u8(skb, ATTR_FW_RELOAD_MODE, reload_mode)) {
		PRINTM(MERROR,
		       "woal_cfg80211_driver_hang_event: nla_put failed!\n");
		dev_kfree_skb(skb);
		goto done;
	}

	PRINTM(MMSG,
	       "woal_cfg80211_driver_hang_event: Send event_hang with reload mode: %d",
	       reload_mode);
	woal_cfg80211_vendor_event(priv, event_hang, (t_u8 *)skb->data,
				   skb->len);

	dev_kfree_skb(skb);
done:
	LEAVE();
}

#endif // STA_CFG80211

/**
 * @brief vendor command to key_mgmt_set_key
 *
 * @param wiphy    A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  fail otherwise
 */
static int
woal_cfg80211_subcmd_set_roaming_offload_key(struct wiphy *wiphy,
					     struct wireless_dev *wdev,
					     const void *data, int data_len)
{
	moal_private *priv;
	struct net_device *dev;
	struct sk_buff *skb = NULL;
	t_u8 *pos = (t_u8 *)data;
	int ret = MLAN_STATUS_SUCCESS;

	ENTER();

	if (data)
		DBG_HEXDUMP(MCMD_D, "Vendor pmk", (t_u8 *)data, data_len);

	if (!wdev || !wdev->netdev) {
		LEAVE();
		return -EFAULT;
	}

	dev = wdev->netdev;
	priv = (moal_private *)woal_get_netdev_priv(dev);
	if (!priv || !pos) {
		LEAVE();
		return -EFAULT;
	}

	if (data_len > MLAN_MAX_KEY_LENGTH) {
		moal_memcpy_ext(priv->phandle, &priv->pmk.pmk_r0, pos,
				MLAN_MAX_KEY_LENGTH, MLAN_MAX_KEY_LENGTH);
		pos += MLAN_MAX_KEY_LENGTH;
		moal_memcpy_ext(priv->phandle, &priv->pmk.pmk_r0_name, pos,
				data_len - MLAN_MAX_KEY_LENGTH,
				MLAN_MAX_PMKR0_NAME_LENGTH);
	} else {
		moal_memcpy_ext(priv->phandle, &priv->pmk.pmk, data, data_len,
				MLAN_MAX_KEY_LENGTH);
	}
	priv->pmk_saved = MTRUE;

	/** Allocate skb for cmd reply*/
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, data_len);
	if (!skb) {
		PRINTM(MERROR, "allocate memory fail for vendor cmd\n");
		LEAVE();
		return -EFAULT;
	}
	pos = skb_put(skb, data_len);
	moal_memcpy_ext(priv->phandle, pos, data, data_len, data_len);
	ret = cfg80211_vendor_cmd_reply(skb);

	LEAVE();
	return ret;
}

/**
 * @brief vendor command to supplicant to update AP info
 *
 * @param priv     A pointer to moal_private
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  1: fail
 */
int woal_roam_ap_info(moal_private *priv, t_u8 *data, int len)
{
	struct wiphy *wiphy = priv->wdev->wiphy;
	struct sk_buff *skb = NULL;
	int ret = MLAN_STATUS_SUCCESS;
	key_info *pkey = NULL;
	apinfo *pinfo = NULL;
	apinfo *req_tlv = NULL;
	MrvlIEtypesHeader_t *tlv = NULL;
	t_u16 tlv_type = 0, tlv_len = 0, tlv_buf_left = 0;
	int event_id = 0;
	t_u8 authorized = 1;

	ENTER();

	event_id = woal_get_event_id(event_fw_roam_success);
	if (event_max == event_id) {
		PRINTM(MERROR, "Not find this event %d\n", event_id);
		ret = 1;
		LEAVE();
		return ret;
	}
	/**allocate skb*/
#if KERNEL_VERSION(4, 1, 0) <= CFG80211_VERSION_CODE
	skb = cfg80211_vendor_event_alloc(wiphy, priv->wdev, len + 50,
#else
	skb = cfg80211_vendor_event_alloc(wiphy, len + 50,
#endif
					  event_id, GFP_ATOMIC);

	if (!skb) {
		PRINTM(MERROR, "allocate memory fail for vendor event\n");
		ret = 1;
		LEAVE();
		return ret;
	}

	nla_put(skb, MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_BSSID,
		MLAN_MAC_ADDR_LENGTH, (t_u8 *)data);
	nla_put(skb, MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_AUTHORIZED,
		sizeof(authorized), &authorized);
	tlv = (MrvlIEtypesHeader_t *)(data + MLAN_MAC_ADDR_LENGTH);
	tlv_buf_left = len - MLAN_MAC_ADDR_LENGTH;
	while (tlv_buf_left >= sizeof(MrvlIEtypesHeader_t)) {
		tlv_type = woal_le16_to_cpu(tlv->type);
		tlv_len = woal_le16_to_cpu(tlv->len);

		if (tlv_buf_left < (tlv_len + sizeof(MrvlIEtypesHeader_t))) {
			PRINTM(MERROR,
			       "Error processing firmware roam success TLVs, bytes left < TLV length\n");
			break;
		}

		switch (tlv_type) {
		case TLV_TYPE_APINFO:
			pinfo = (apinfo *)tlv;
			nla_put(skb, MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_RESP_IE,
				pinfo->header.len, pinfo->rsp_ie);
			break;
		case TLV_TYPE_ASSOC_REQ_IE:
			req_tlv = (apinfo *)tlv;
			nla_put(skb, MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_REQ_IE,
				req_tlv->header.len, req_tlv->rsp_ie);
			break;
		case TLV_TYPE_KEYINFO:
			pkey = (key_info *)tlv;
			nla_put(skb,
				MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_KEY_REPLAY_CTR,
				MLAN_REPLAY_CTR_LEN, pkey->key.replay_ctr);
			nla_put(skb, MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_PTK_KCK,
				MLAN_KCK_LEN, pkey->key.kck);
			nla_put(skb, MRVL_WLAN_VENDOR_ATTR_ROAM_AUTH_PTK_KEK,
				MLAN_KEK_LEN, pkey->key.kek);
			break;
		default:
			break;
		}
		tlv_buf_left -= tlv_len + sizeof(MrvlIEtypesHeader_t);
		tlv = (MrvlIEtypesHeader_t *)((t_u8 *)tlv + tlv_len +
					      sizeof(MrvlIEtypesHeader_t));
	}

	/**send event*/
	cfg80211_vendor_event(skb, GFP_ATOMIC);

	LEAVE();
	return ret;
}

/**
 * @brief vendor command to enable/disable 11k
 *
 * @param wiphy         A pointer to wiphy struct
 * @param wdev          A pointer to wireless_dev struct
 * @param data           a pointer to data
 * @param data_len     data length
 *
 * @return      0: success  <0: fail
 */
static int woal_cfg80211_subcmd_11k_cfg(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data, int data_len)
{
	struct net_device *dev = NULL;
	moal_private *priv = NULL;
	mlan_ioctl_req *req = NULL;
	mlan_ds_11k_cfg *pcfg_11k = NULL;
	struct nlattr *tb_vendor[ATTR_ND_OFFLOAD_MAX + 1];
	int ret = 0;
	int status = MLAN_STATUS_SUCCESS;

	ENTER();
	if (!wdev || !wdev->netdev) {
		LEAVE();
		return -EFAULT;
	}

	dev = wdev->netdev;
	priv = (moal_private *)woal_get_netdev_priv(dev);

	nla_parse(tb_vendor, ATTR_ND_OFFLOAD_MAX, (struct nlattr *)data,
		  data_len, NULL
#if KERNEL_VERSION(4, 12, 0) <= CFG80211_VERSION_CODE
		  ,
		  NULL
#endif
	);
	if (!tb_vendor[ATTR_ND_OFFLOAD_CONTROL]) {
		PRINTM(MINFO, "%s: ATTR_ND_OFFLOAD not found\n", __func__);
		ret = -EFAULT;
		goto done;
	}
	/* Allocate an IOCTL request buffer */
	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_11k_cfg));
	if (req == NULL) {
		PRINTM(MERROR, "Could not allocate mlan ioctl request!\n");
		ret = -EFAULT;
		goto done;
	}
	/* Fill request buffer */
	pcfg_11k = (mlan_ds_11k_cfg *)req->pbuf;
	pcfg_11k->sub_command = MLAN_OID_11K_CFG_ENABLE;
	req->req_id = MLAN_IOCTL_11K_CFG;
	req->action = MLAN_ACT_SET;
	if (nla_get_u32(tb_vendor[ATTR_ND_OFFLOAD_CONTROL]))
		pcfg_11k->param.enable_11k = MTRUE;
	else
		pcfg_11k->param.enable_11k = MFALSE;
	PRINTM(MCMND, "11k enable = %d\n", pcfg_11k->param.enable_11k);
	status = woal_request_ioctl(priv, req, MOAL_IOCTL_WAIT);
	if (status != MLAN_STATUS_SUCCESS) {
		ret = -EFAULT;
		goto done;
	}
done:
	if (status != MLAN_STATUS_PENDING)
		kfree(req);

	LEAVE();
	return ret;
}

/**
 * @brief vendor command to set scan mac oui
 *
 * @param wiphy         A pointer to wiphy struct
 * @param wdev          A pointer to wireless_dev struct
 * @param data           a pointer to data
 * @param data_len     data length
 *
 * @return      0: success  <0: fail
 */
static int woal_cfg80211_subcmd_set_scan_mac_oui(struct wiphy *wiphy,
						 struct wireless_dev *wdev,
						 const void *data, int data_len)
{
	struct net_device *dev = NULL;
	moal_private *priv = NULL;
	struct nlattr *tb_vendor[ATTR_WIFI_MAX + 1];
	t_u8 mac_oui[3] = {0};
	int ret = MLAN_STATUS_SUCCESS;

	ENTER();

	if (!wdev || !wdev->netdev) {
		LEAVE();
		return -EFAULT;
	}
	dev = wdev->netdev;
	priv = (moal_private *)woal_get_netdev_priv(dev);

	nla_parse(tb_vendor, ATTR_WIFI_MAX, (struct nlattr *)data, data_len,
		  NULL
#if KERNEL_VERSION(4, 12, 0) <= CFG80211_VERSION_CODE
		  ,
		  NULL
#endif
	);
	if (!tb_vendor[ATTR_SCAN_MAC_OUI_SET]) {
		PRINTM(MINFO, "%s: ATTR_SCAN_MAC_OUI_SET not found\n",
		       __func__);
		ret = -EFAULT;
		goto done;
	}
	moal_memcpy_ext(priv->phandle, mac_oui,
			nla_data(tb_vendor[ATTR_SCAN_MAC_OUI_SET]), 3, 3);
	moal_memcpy_ext(priv->phandle, priv->random_mac, priv->current_addr,
			ETH_ALEN, MLAN_MAC_ADDR_LENGTH);
	moal_memcpy_ext(priv->phandle, priv->random_mac, mac_oui, 3,
			MLAN_MAC_ADDR_LENGTH);
	PRINTM(MCMND, "random_mac is " FULL_MACSTR "\n",
	       FULL_MAC2STR(priv->random_mac));
done:
	LEAVE();
	return ret;
}
/**
 * @brief vendor command to
 *
 * @param wiphy         A pointer to wiphy struct
 * @param wdev          A pointer to wireless_dev struct
 * @param data           a pointer to data
 * @param data_len     data length
 *
 * @return      0: success  <0: fail
 */
static int woal_cfg80211_subcmd_set_scan_band(struct wiphy *wiphy,
					      struct wireless_dev *wdev,
					      const void *data, int data_len)
{
	struct net_device *dev = NULL;
	moal_private *priv = NULL;
	struct nlattr *tb_vendor[ATTR_WIFI_MAX + 1];
	int ret = MLAN_STATUS_SUCCESS;

	ENTER();

	if (!wdev || !wdev->netdev) {
		LEAVE();
		return -EFAULT;
	}
	dev = wdev->netdev;
	priv = (moal_private *)woal_get_netdev_priv(dev);

	nla_parse(tb_vendor, ATTR_WIFI_MAX, (struct nlattr *)data, data_len,
		  NULL
#if KERNEL_VERSION(4, 12, 0) <= CFG80211_VERSION_CODE
		  ,
		  NULL
#endif
	);
	if (!tb_vendor[ATTR_SCAN_BAND_SET]) {
		PRINTM(MERROR, "%s: ATTR_SCAN_BAND_SET not found\n", __func__);
		ret = -EFAULT;
		goto done;
	}
	priv->scan_setband_mask =
		*(u8 *)nla_data(tb_vendor[ATTR_SCAN_BAND_SET]);
	PRINTM(MMSG,
	       "woal_cfg80211_subcmd_set_scan_band: scan_setband_mask :%d",
	       priv->scan_setband_mask);

done:
	LEAVE();
	return ret;
}

/**
 * @brief vendor command to set enable/disable dfs offload
 *
 * @param wiphy       A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      0: success  1: fail
 */
static int woal_cfg80211_subcmd_set_dfs_offload(struct wiphy *wiphy,
						struct wireless_dev *wdev,
						const void *data, int data_len)
{
	struct sk_buff *skb = NULL;
	moal_handle *handle = (moal_handle *)woal_get_wiphy_priv(wiphy);
	int dfs_offload;
	int ret = 1;

	ENTER();
	dfs_offload = moal_extflg_isset(handle, EXT_DFS_OFFLOAD);

	/** Allocate skb for cmd reply*/
	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy, sizeof(dfs_offload));
	if (!skb) {
		PRINTM(MERROR, "allocate memory fail for vendor cmd\n");
		ret = 1;
		LEAVE();
		return ret;
	}
	nla_put(skb, MRVL_WLAN_VENDOR_ATTR_DFS, sizeof(t_u32), &dfs_offload);
	ret = cfg80211_vendor_cmd_reply(skb);

	LEAVE();
	return ret;
}

#define CSI_DUMP_FILE_MAX 1200000

/**
 * @brief vendor command to set CSI params
 *
 * @param wiphy    A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param len     data length
 * @param csi_enable    enable/disable CSI
 *
 * @return      0: success  -1: fail
 */
static int woal_cfg80211_subcmd_set_csi(struct wiphy *wiphy,
					struct wireless_dev *wdev,
					const void *data, int len,
					int csi_enable)
{
	struct net_device *dev = NULL;
	moal_private *priv = NULL;
	mlan_ioctl_req *req = NULL;
	mlan_ds_misc_cfg *cfg = NULL;
	struct nlattr *tb_vendor[ATTR_CSI_MAX + 1];
	int ret = 0;
	int status = MLAN_STATUS_SUCCESS;

	ENTER();

	if (!wdev || !wdev->netdev) {
		LEAVE();
		return -EFAULT;
	}
	dev = wdev->netdev;
	priv = (moal_private *)woal_get_netdev_priv(dev);

	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_misc_cfg));
	if (req == NULL) {
		PRINTM(MERROR, "Could not allocate mlan ioctl request!\n");
		ret = -EFAULT;
		goto done;
	}
	req->req_id = MLAN_IOCTL_MISC_CFG;
	cfg = (mlan_ds_misc_cfg *)req->pbuf;
	cfg->sub_command = MLAN_OID_MISC_CSI;

	priv->csi_enable = csi_enable;
	if (csi_enable == 1) {
		nla_parse(tb_vendor, ATTR_CSI_MAX, (struct nlattr *)data, len,
			  NULL
#if KERNEL_VERSION(4, 12, 0) <= CFG80211_VERSION_CODE
			  ,
			  NULL
#endif
		);
		if (!tb_vendor[ATTR_CSI_CONFIG]) {
			ret = -EFAULT;
			goto done;
		}
		moal_memcpy_ext(priv->phandle, &cfg->param.csi_params,
				(mlan_ds_csi_params *)nla_data(
					tb_vendor[ATTR_CSI_CONFIG]),
				sizeof(mlan_ds_csi_params),
				sizeof(mlan_ds_csi_params));
		moal_memcpy_ext(priv->phandle, &priv->csi_config,
				&cfg->param.csi_params,
				sizeof(mlan_ds_csi_params),
				sizeof(mlan_ds_csi_params));
		if (tb_vendor[ATTR_CSI_DUMP_FORMAT])
			priv->csi_dump_format =
				nla_get_u8(tb_vendor[ATTR_CSI_DUMP_FORMAT]);
	} else if (csi_enable == 0) {
		nla_parse(tb_vendor, ATTR_CSI_MAX, (struct nlattr *)data, len,
			  NULL
#if KERNEL_VERSION(4, 12, 0) <= CFG80211_VERSION_CODE
			  ,
			  NULL
#endif
		);
		if (!tb_vendor[ATTR_PEER_MAC_ADDR]) {
			ret = -EFAULT;
			goto done;
		}
		memset(&cfg->param.csi_params, 0, sizeof(mlan_ds_csi_params));
		moal_memcpy_ext(priv->phandle,
				cfg->param.csi_params.csi_filter[0].mac_addr,
				(t_u8 *)nla_data(tb_vendor[ATTR_PEER_MAC_ADDR]),
				MLAN_MAC_ADDR_LENGTH, MLAN_MAC_ADDR_LENGTH);
	}

	status = woal_request_ioctl(priv, req, MOAL_IOCTL_WAIT);
	if (status != MLAN_STATUS_SUCCESS) {
		ret = -EFAULT;
		goto done;
	}

done:
	if (status != MLAN_STATUS_PENDING)
		kfree(req);
	LEAVE();
	return ret;
}

/**
 * @brief vendor command to enable CSI
 *
 * @param wiphy    A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param len     data length
 *
 * @return      0: success  -1: fail
 */
static int woal_cfg80211_subcmd_csi_enable(struct wiphy *wiphy,
					   struct wireless_dev *wdev,
					   const void *data, int len)
{
	int ret = 0;

	ENTER();

	ret = woal_cfg80211_subcmd_set_csi(wiphy, wdev, data, len, 1);

	LEAVE();
	return ret;
}

/**
 * @brief vendor command to disable CSI
 *
 * @param wiphy    A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param len     data length
 *
 * @return      0: success  -1: fail
 */
static int woal_cfg80211_subcmd_csi_disable(struct wiphy *wiphy,
					    struct wireless_dev *wdev,
					    const void *data, int len)
{
	int ret = 0;

	ENTER();

	ret = woal_cfg80211_subcmd_set_csi(wiphy, wdev, data, len, 0);

	LEAVE();
	return ret;
}

/**
 * @brief vendor command to get CSI dump path
 *
 * @param wiphy    A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param len     data length
 *
 * @return      0: success  -1: fail
 */
static int woal_cfg80211_subcmd_get_csi_dump_path(struct wiphy *wiphy,
						  struct wireless_dev *wdev,
						  const void *data, int len)
{
	int ret = 0;
	struct net_device *dev = NULL;
	moal_private *priv = NULL;
	struct sk_buff *skb = NULL;

	ENTER();

	if (!wdev || !wdev->netdev) {
		LEAVE();
		return -EFAULT;
	}
	dev = wdev->netdev;
	priv = (moal_private *)woal_get_netdev_priv(dev);

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
						  sizeof(priv->csi_dump_path));
	if (unlikely(!skb)) {
		PRINTM(MERROR, "skb alloc failed\n");
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}

	/* Push the data to the skb */
	nla_put(skb, ATTR_CSI_DUMP_PATH, sizeof(priv->csi_dump_path),
		(t_u8 *)priv->csi_dump_path);

	ret = cfg80211_vendor_cmd_reply(skb);
	if (unlikely(ret)) {
		PRINTM(MERROR, "Vendor Command reply failed ret:%d\n", ret);
		goto done;
	}

done:
	LEAVE();
	return ret;
}

/**
 * @brief vendor command to get CSI config
 *
 * @param wiphy    A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param len     data length
 *
 * @return      0: success  -1: fail
 */
static int woal_cfg80211_subcmd_get_csi_config(struct wiphy *wiphy,
					       struct wireless_dev *wdev,
					       const void *data, int len)
{
	int ret = 0;
	struct net_device *dev = NULL;
	moal_private *priv = NULL;
	struct sk_buff *skb = NULL;

	ENTER();

	if (!wdev || !wdev->netdev) {
		LEAVE();
		return -EFAULT;
	}
	dev = wdev->netdev;
	priv = (moal_private *)woal_get_netdev_priv(dev);

	skb = cfg80211_vendor_cmd_alloc_reply_skb(wiphy,
						  sizeof(priv->csi_config));
	if (unlikely(!skb)) {
		PRINTM(MERROR, "skb alloc failed\n");
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}
	/* Push the data to the skb */
	nla_put(skb, ATTR_CSI_CONFIG, sizeof(mlan_ds_csi_params),
		(t_u8 *)&priv->csi_config);

	ret = cfg80211_vendor_cmd_reply(skb);
	if (unlikely(ret)) {
		PRINTM(MERROR, "Vendor Command reply failed ret:%d\n", ret);
		goto done;
	}

done:
	LEAVE();
	return ret;
}

/**
 * @brief vendor command to get CSI capability
 *
 * @param wiphy    A pointer to wiphy struct
 * @param wdev     A pointer to wireless_dev struct
 * @param data     a pointer to data
 * @param len     data length
 *
 * @return      0: success  -1: fail
 */
static int woal_cfg80211_subcmd_get_csi_capa(struct wiphy *wiphy,
					     struct wireless_dev *wdev,
					     const void *data, int len)
{
	ENTER();
	LEAVE();
	return 0;
}

/**
 * @brief Save CSI dump to file
 *
 * @param dir_name    Directory name
 * @param file_name    File name
 * @param buf    Pointer to dump buffer
 * @param buf_len    Length of buf
 * @param name    Full path name of CSI dump
 *
 * @return      0: success  -1: fail
 */
static mlan_status woal_save_csi_dump_to_file(char *dir_name, char *file_name,
					      t_u8 *buf, int buf_len,
					      t_u8 format, char *name)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
#ifndef DUMP_TO_PROC
	struct file *pfile = NULL;
	loff_t pos;
	char dw_string[10];
	int i = 0;
	t_u32 *tmp = NULL;
#endif
	ENTER();

	if (!dir_name || !file_name || !buf) {
		PRINTM(MERROR, "Can't save dump info to file\n");
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}
#ifndef DUMP_TO_PROC
	snprintf(name, MAX_BUF_LEN, "%s/%s", dir_name, file_name);
	pfile = filp_open(name, O_CREAT | O_RDWR | O_APPEND, 0644);

	if (IS_ERR(pfile)) {
		PRINTM(MMSG,
		       "Create file %s error, try to save dump file in /var\n",
		       name);
		snprintf(name, MAX_BUF_LEN, "%s/%s", "/var", file_name);
		pfile = filp_open(name, O_CREAT | O_RDWR | O_APPEND, 0644);
	}
	if (IS_ERR(pfile)) {
		PRINTM(MERROR, "Create Dump file for %s error\n", name);
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}

	PRINTM(MMSG, "Dump data %s saved in %s\n", file_name, name);

	pos = 0;
	/* Save CSI dump directly to file */
	if (format == 1) {
#if KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE
		vfs_write(pfile, (const char __user *)buf, buf_len, &pos);
#else
		kernel_write(pfile, buf, buf_len, &pos);
#endif
	} else {
		tmp = (t_u32 *)buf;
		for (i = 0; i < buf_len / 4; i++) {
			if ((i + 1) % 8 == 0)
				snprintf(dw_string, sizeof(dw_string), "%08x\n",
					 *tmp);
			else
				snprintf(dw_string, sizeof(dw_string), "%08x ",
					 *tmp);
#if KERNEL_VERSION(4, 14, 0) > LINUX_VERSION_CODE
			vfs_write(pfile, (const char __user *)dw_string, 9,
				  &pos);
#else
			kernel_write(pfile, dw_string, 9, &pos);
#endif
			tmp++;
		}
	}
	filp_close(pfile, NULL);

	PRINTM(MMSG, "Dump data saved in %s successfully\n", name);
#endif
done:
	LEAVE();
	return ret;
}

/**
 * @brief vendor event to upload csi dump
 *
 * @param priv     A pointer to moal_private
 * @param data     a pointer to data
 * @param  len     data length
 *
 * @return      mlan_status
 */
mlan_status woal_cfg80211_event_csi_dump(moal_private *priv, t_u8 *data,
					 int len)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	char path_name[20];
	char file_name[20];

	ENTER();

	DBG_HEXDUMP(MCMD_D, "CSI dump data", data, len);
	snprintf(path_name, sizeof(path_name), "/data");
	if (priv->csi_dump_format == 1)
		snprintf(file_name, sizeof(file_name), "csi_dump.bin");
	else
		snprintf(file_name, sizeof(file_name), "csi_dump.txt");
	priv->csi_dump_len += len;
	if (priv->csi_dump_len > CSI_DUMP_FILE_MAX) {
		PRINTM(MERROR,
		       "Reached file maximum size. Not saving CSI records.\n");
		goto done;
	}
	/* Save CSI dump to file */
	ret = woal_save_csi_dump_to_file(path_name, file_name, data, len,
					 priv->csi_dump_format,
					 priv->csi_dump_path);
	if (ret != MLAN_STATUS_SUCCESS) {
		PRINTM(MERROR, "Failed to save CSI dump to file\n");
		goto done;
	}

done:
	LEAVE();
	return ret;
}

// clang-format off
static const struct wiphy_vendor_command vendor_commands[] = {
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = sub_cmd_set_drvdbg,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_set_drvdbg,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = sub_cmd_get_valid_channels,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_get_valid_channels,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = woal_attr_policy,
		.maxattr = ATTR_WIFI_MAX,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = sub_cmd_set_scan_mac_oui,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_set_scan_mac_oui,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = woal_attr_policy,
		.maxattr = ATTR_WIFI_MAX,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = sub_cmd_set_scan_band,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_set_scan_band,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = woal_attr_policy,
		.maxattr = ATTR_WIFI_MAX,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = SUBCMD_SET_GET_SCANCFG,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_set_get_scancfg,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = SUBCMD_SET_GET_ADDBAPARAMS,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_set_get_addbaparams,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = SUBCMD_SET_GET_CLR_HOSTCMD,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_hostcmd,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
#ifdef STA_CFG80211
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = sub_cmd_rssi_monitor,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_rssi_monitor,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = woal_rssi_monitor_policy,
		.maxattr = ATTR_RSSI_MONITOR_MAX,
#endif
	},
#endif
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = sub_cmd_set_roaming_offload_key,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_set_roaming_offload_key,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = sub_cmd_dfs_capability,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_set_dfs_offload,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},


	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = sub_cmd_nd_offload
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_11k_cfg,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = woal_nd_offload_policy,
		.maxattr = ATTR_ND_OFFLOAD_MAX,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = sub_cmd_get_drv_version,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_get_drv_version,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = sub_cmd_get_fw_version,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_get_fw_version,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = sub_cmd_get_wifi_supp_feature_set,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_get_supp_feature_set,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = sub_cmd_set_country_code,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_set_country_code,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = subcmd_cfr_request,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_csi_enable,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = subcmd_cfr_cancel,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_csi_disable,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = subcmd_get_csi_dump_path,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_get_csi_dump_path,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = subcmd_get_csi_config,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_get_csi_config,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
	{
		.info = {
				.vendor_id = MRVL_VENDOR_ID,
				.subcmd = subcmd_get_csi_capa,
			},
		.flags = WIPHY_VENDOR_CMD_NEED_WDEV |
			 WIPHY_VENDOR_CMD_NEED_NETDEV,
		.doit = woal_cfg80211_subcmd_get_csi_capa,
#if KERNEL_VERSION(5, 3, 0) <= CFG80211_VERSION_CODE
		.policy = VENDOR_CMD_RAW_DATA,
#endif
	},
};
// clang-format on

/**
 * @brief register vendor commands and events
 *
 * @param wiphy       A pointer to wiphy struct
 *
 * @return
 */
void woal_register_cfg80211_vendor_command(struct wiphy *wiphy)
{
	ENTER();
	wiphy->vendor_commands = vendor_commands;
	wiphy->n_vendor_commands = ARRAY_SIZE(vendor_commands);
	wiphy->vendor_events = vendor_events;
	wiphy->n_vendor_events = ARRAY_SIZE(vendor_events);
	LEAVE();
}
#endif
