/** @file  mlanhostcmd.h
 *
 * @brief This file contains command structures for mlanutl application
 *
 *
 * Copyright 2008-2021, 2024 NXP
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
 */
/************************************************************************
Change log:
     11/26/2008: initial version
************************************************************************/
#ifndef _MLANHOSTCMD_H_
#define _MLANHOSTCMD_H_

/** Find number of elements */
#define NELEMENTS(x) (sizeof(x) / sizeof(x[0]))

/** Size of command buffer */
#define MRVDRV_SIZE_OF_CMD_BUFFER (3 * 1024)

/** Host Command ID : Memory access */
#define HostCmd_CMD_MEM_ACCESS 0x0086

/** Pre-Authenticate - 11r only */
#define HostCmd_CMD_802_11_AUTHENTICATE 0x0011

/** Read/Write Mac register */
#define HostCmd_CMD_MAC_REG_ACCESS 0x0019
/** Read/Write BBP register */
#define HostCmd_CMD_BBP_REG_ACCESS 0x001a
/** Read/Write RF register */
#define HostCmd_CMD_RF_REG_ACCESS 0x001b
/** Get TX Power data */
#define HostCmd_CMD_802_11_RF_TX_POWER 0x001e
/** Host Command ID : CAU register access */
#define HostCmd_CMD_CAU_REG_ACCESS 0x00ed

/** Host Command ID : 802.11 BG scan configuration */
#define HostCmd_CMD_802_11_BG_SCAN_CONFIG 0x006b
/** Host Command ID : Configuration data */
#define HostCmd_CMD_CFG_DATA 0x008f
/** Host Command ID : 802.11 TPC adapt req */
#define HostCmd_CMD_802_11_TPC_ADAPT_REQ 0x0060
/** Host Command ID : 802.11 crypto */
#define HostCmd_CMD_802_11_CRYPTO 0x0078
/** Host Command ID : 802.11 auto Tx */
#define HostCmd_CMD_802_11_AUTO_TX 0x0082

/** Host Command ID : 802.11 subscribe event */
#define HostCmd_CMD_802_11_SUBSCRIBE_EVENT 0x0075

#ifdef OPCHAN
/** Host Command ID : Operating channel config */
#define HostCmd_CMD_OPCHAN_CONFIG 0x00f8
/** Host Command ID : Opchan channel group config */
#define HostCmd_CMD_OPCHAN_CHANGROUP_CONFIG 0x00f9
#endif

/** Host Command ID : Channel TRPC config */
#define HostCmd_CMD_CHAN_TRPC_CONFIG 0x00fb

/** TLV  type ID definition */
#define PROPRIETARY_TLV_BASE_ID 0x0100
/** TLV type : Beacon RSSI low */
#define TLV_TYPE_RSSI_LOW (PROPRIETARY_TLV_BASE_ID + 0x04) /* 0x0104 */
/** TLV type : Beacon SNR low */
#define TLV_TYPE_SNR_LOW (PROPRIETARY_TLV_BASE_ID + 0x05) /* 0x0105 */
/** TLV type : Fail count */
#define TLV_TYPE_FAILCOUNT (PROPRIETARY_TLV_BASE_ID + 0x06) /* 0x0106 */
/** TLV type : BCN miss */
#define TLV_TYPE_BCNMISS (PROPRIETARY_TLV_BASE_ID + 0x07) /* 0x0107 */
/** TLV type : Beacon RSSI high */
#define TLV_TYPE_RSSI_HIGH (PROPRIETARY_TLV_BASE_ID + 0x16) /* 0x0116 */
/** TLV type : Beacon SNR high */
#define TLV_TYPE_SNR_HIGH (PROPRIETARY_TLV_BASE_ID + 0x17) /* 0x0117 */
/** TLV type : Auto Tx */
#define TLV_TYPE_AUTO_TX (PROPRIETARY_TLV_BASE_ID + 0x18) /* 0x0118 */
/** TLV type :Link Quality */
#define TLV_TYPE_LINK_QUALITY (PROPRIETARY_TLV_BASE_ID + 0x24) /* 0x0124 */
/** TLV type : Data RSSI low */
#define TLV_TYPE_RSSI_LOW_DATA (PROPRIETARY_TLV_BASE_ID + 0x26) /* 0x0126 */
/** TLV type : Data SNR low */
#define TLV_TYPE_SNR_LOW_DATA (PROPRIETARY_TLV_BASE_ID + 0x27) /* 0x0127 */
/** TLV type : Data RSSI high */
#define TLV_TYPE_RSSI_HIGH_DATA (PROPRIETARY_TLV_BASE_ID + 0x28) /* 0x0128 */
/** TLV type : Data SNR high */
#define TLV_TYPE_SNR_HIGH_DATA (PROPRIETARY_TLV_BASE_ID + 0x29) /* 0x0129 */
/** TLV type: Pre-Beacon Lost */
#define TLV_TYPE_PRE_BEACON_LOST (PROPRIETARY_TLV_BASE_ID + 0x49) /* 0x0149 */

#ifdef OPCHAN
/** TLV type : Operating channel control description */
#define TLV_TYPE_OPCHAN_CONTROL_DESC                                           \
	(PROPRIETARY_TLV_BASE_ID + 0x79) /* 0x0179 */
/** TLV type : Operating channel group control */
#define TLV_TYPE_OPCHAN_CHANGRP_CTRL                                           \
	(PROPRIETARY_TLV_BASE_ID + 0x7a) /* 0x017a */
#endif

/** TLV type : Channel TRPC */
#define TLV_TYPE_CHAN_TRPC (PROPRIETARY_TLV_BASE_ID + 0x89) /* 0x0189 */

/** mlan_ioctl_11h_tpc_resp */
typedef struct {
	t_u8 status_code; /**< Firmware command result status code */
	t_u8 tx_power; /**< Reported TX Power from the TPC Report */
	t_s8 link_margin; /**< Reported Link margin from the TPC Report */
	t_s8 rssi; /**< RSSI of the received TPC Report frame */
} __ATTRIB_PACK__ mlan_ioctl_11h_tpc_resp;

/* Define general hostcmd data structure */

/** Convert String to integer */
t_u32 a2hex_or_atoi(char *value);
char *mlan_config_get_line(FILE *fp, char *str, t_s32 size, int *lineno);

int prepare_host_cmd_buffer(FILE *fp, char *cmd_name, t_u8 *buf);
int prepare_hostcmd_regrdwr(t_u32 type, t_u32 offset, t_u32 *value, t_u8 *buf);

#endif /* _MLANHOSTCMD_H_ */
