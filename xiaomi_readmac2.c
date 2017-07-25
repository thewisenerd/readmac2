/*
 * Copyright (C) 2017 thewisenerd <thewisenerd@protonmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "xiaomi_readmac2"
#define LOG_NDEBUG 0

#include <cutils/log.h>

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#define SUCCESS (0)
#define FAILED (-1)
#define MAC_ADDR_SIZE 6
#define WLAN_MAC_BIN "/persist/mac.wlan.bin"
#define BD_MAC_BIN "/persist/mac.bd.bin"

#include "qmi-framework/inc/qmi_client.h"
#include "qmi-framework/inc/qmi_idl_lib_internal.h"

#define LIB_QMI_CCI "libqmi_cci.so"
static void *libqmi_cci_handle = NULL;
qmi_client_error_type (*qmi_client_notifier_init_shim) (
	qmi_idl_service_object_type           service_obj,
	qmi_client_os_params                  *os_params,
	qmi_client_type                       *user_handle
) = NULL;
qmi_client_error_type (*qmi_client_get_service_list_shim)
(
	qmi_idl_service_object_type           service_obj,
	qmi_service_info                      *service_info_array,
	unsigned int                          *num_entries,
	unsigned int                          *num_services
);
qmi_client_error_type (*qmi_client_init_shim)
(
	qmi_service_info                          *service_info,
	qmi_idl_service_object_type               service_obj,
	qmi_client_ind_cb                         ind_cb,
	void                                      *ind_cb_data,
	qmi_client_os_params                      *os_params,
	qmi_client_type                           *user_handle
) = NULL;
qmi_client_error_type (*qmi_client_release_shim)
(
	qmi_client_type     user_handle
) = NULL;
qmi_client_error_type (*qmi_client_send_msg_async_shim)
(
	qmi_client_type                 user_handle,
	unsigned int                    msg_id,
	void                            *req_c_struct,
	unsigned int                    req_c_struct_len,
	void                            *resp_c_struct,
	unsigned int                    resp_c_struct_len,
	qmi_client_recv_msg_async_cb    resp_cb,
	void                            *resp_cb_data,
	qmi_txn_handle                  *txn_handle
) = NULL;
qmi_client_error_type (*qmi_client_send_msg_sync_shim)
(
	qmi_client_type    user_handle,
	unsigned int       msg_id,
	void               *req_c_struct,
	unsigned int       req_c_struct_len,
	void               *resp_c_struct,
	unsigned int       resp_c_struct_len,
	unsigned int       timeout_msecs
) = NULL;

#define LIB_QMINVAPI "libqminvapi.so"
static void *libqminvapi_handle = NULL;
qmi_idl_service_object_type (*xiaomi_qmi_nv_get_service_object_internal_v01_shim) (
	int a1,
	int a2,
	int a3
) = NULL;

typedef struct {
	uint32_t index;
	uint32_t offset;
} qminvapi_req_t;

typedef struct  {
	char buf[136];
} qminvapi_resp_t;

const uint8_t xiaomi_oui_list[][3] =
{
	{ 0x9C, 0x99, 0xA0 },
	{ 0x18, 0x59, 0x36 },
	{ 0x98, 0xFA, 0xE3 },
	{ 0x64, 0x09, 0x80 },
	{ 0x8C, 0xBE, 0xBE },
	{ 0xF8, 0xA4, 0x5F },
	{ 0xC4, 0x0B, 0xCB },
	{ 0xEC, 0xD0, 0x9F },
	{ 0xE4, 0x46, 0xDA },
	{ 0xF4, 0xF5, 0xDB },
	{ 0x28, 0xE3, 0x1F },
	{ 0x0C, 0x1D, 0xAF },
	{ 0x14, 0xF6, 0x5A },
	{ 0x74, 0x23, 0x44 },
	{ 0xF0, 0xB4, 0x29 },
	{ 0xD4, 0x97, 0x0B },
	{ 0x64, 0xCC, 0x2E },
	{ 0xB0, 0xE2, 0x35 },
	{ 0x38, 0xA4, 0xED },
	{ 0xF4, 0x8B, 0x32 },
	{ 0x3C, 0xBD, 0x3E },
	{ 0x4C, 0x49, 0xE3 },
	{ 0x00, 0x9E, 0xC8 },
	{ 0xAC, 0xF7, 0xF3 },
	{ 0x10, 0x2A, 0xB3 },
	{ 0x58, 0x44, 0x98 },
	{ 0xA0, 0x86, 0xC6 },
	{ 0x7C, 0x1D, 0xD9 },
	{ 0x28, 0x6C, 0x07 },
	{ 0xAC, 0xC1, 0xEE },
	{ 0x78, 0x02, 0xF8 },
	{ 0x50, 0x8F, 0x4C },
	{ 0x68, 0xDF, 0xDD },
	{ 0xC4, 0x6A, 0xB7 },
	{ 0xFC, 0x64, 0xBA },
	{ 0x20, 0x82, 0xC0 },
	{ 0x34, 0x80, 0xB3 },
	{ 0x74, 0x51, 0xBA },
	{ 0x64, 0xB4, 0x73 },
	{ 0x34, 0xCE, 0x00 },
	{ 0x00, 0xEC, 0x0A },
	{ 0x78, 0x11, 0xDC },
	{ 0x50, 0x64, 0x2B },
};
const size_t xiaomi_oui_list_size = sizeof(xiaomi_oui_list) / 3;

static int setup_dlsym(void)
{
	const char *error = NULL;

	/* dlopen teh files */
	libqmi_cci_handle = dlopen(LIB_QMI_CCI, RTLD_NOW);
	if (!libqmi_cci_handle) {
		error = dlerror();
		fprintf(stderr, "Failed to open %s: %s", LIB_QMI_CCI, error);
		ALOGE("Failed to open %s: %s", LIB_QMI_CCI, error);
		goto dlopen_err;
	}

	dlerror();

	libqminvapi_handle = dlopen(LIB_QMINVAPI, RTLD_NOW);
	if (!libqminvapi_handle) {
		error = dlerror();
		fprintf(stderr, "Failed to open %s: %s", LIB_QMINVAPI, error);
		ALOGE("Failed to open %s: %s", LIB_QMINVAPI, error);
		goto dlopen_err;
	}

	dlerror();

	/* start dlsym'in */
	xiaomi_qmi_nv_get_service_object_internal_v01_shim = dlsym(libqminvapi_handle, "xiaomi_qmi_nv_get_service_object_internal_v01");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "Failed to resolve function: %s: %s",
				"xiaomi_qmi_nv_get_service_object_internal_v01", error);
		ALOGE("Failed to resolve function: %s: %s",
				"xiaomi_qmi_nv_get_service_object_internal_v01", error);
		goto dlsym_err;
	}

	qmi_client_notifier_init_shim = dlsym(libqmi_cci_handle, "qmi_client_notifier_init");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "Failed to resolve function: %s: %s",
				"qmi_client_notifier_init", error);
		ALOGE("Failed to resolve function: %s: %s",
				"qmi_client_notifier_init", error);
		goto dlsym_err;
	}

	qmi_client_get_service_list_shim = dlsym(libqmi_cci_handle, "qmi_client_get_service_list");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "Failed to resolve function: %s: %s",
				"qmi_client_get_service_list", error);
		ALOGE("Failed to resolve function: %s: %s",
				"qmi_client_get_service_list", error);
		goto dlsym_err;
	}

	qmi_client_init_shim = dlsym(libqmi_cci_handle, "qmi_client_init");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "Failed to resolve function: %s: %s",
				"qmi_client_init", error);
		ALOGE("Failed to resolve function: %s: %s",
				"qmi_client_init", error);
		goto dlsym_err;
	}

	qmi_client_release_shim = dlsym(libqmi_cci_handle, "qmi_client_release");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "Failed to resolve function: %s: %s",
				"qmi_client_release", error);
		ALOGE("Failed to resolve function: %s: %s",
				"qmi_client_release", error);
		goto dlsym_err;
	}

	qmi_client_send_msg_async_shim = dlsym(libqmi_cci_handle, "qmi_client_send_msg_async");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "Failed to resolve function: %s: %s",
				"qmi_client_send_msg_async", error);
		ALOGE("Failed to resolve function: %s: %s",
				"qmi_client_send_msg_async", error);
		goto dlsym_err;
	}

	qmi_client_send_msg_sync_shim = dlsym(libqmi_cci_handle, "qmi_client_send_msg_sync");
	if ((error = dlerror()) != NULL) {
		fprintf(stderr, "Failed to resolve function: %s: %s",
				"qmi_client_send_msg_sync", error);
		ALOGE("Failed to resolve function: %s: %s",
				"qmi_client_send_msg_sync", error);
		goto dlsym_err;
	}

	return SUCCESS;

dlsym_err:
dlopen_err:
	if (libqmi_cci_handle)
		dlclose(libqmi_cci_handle);
	if (libqminvapi_handle)
		dlclose(libqminvapi_handle);

	return FAILED;
}

static void dump_struct(void *p, size_t s) {
	unsigned char* charPtr=(unsigned char*)p;
	size_t i;
	for(i=0;i<s;i++)
		fprintf(stderr, "%02x",charPtr[i]);
	fprintf(stderr, "\r\n");
}

static int check_wlan_mac_bin_file(void) {
	char content[6+1];
	FILE* fp;
	size_t i;

	fp = fopen(WLAN_MAC_BIN, "r");
	if (fp == NULL)
		return 1;

	memset(content, 0, sizeof(content));
	fread(content, 1, sizeof(content) - 1, fp);
	fclose(fp);

	for (i = 0; i < xiaomi_oui_list_size; i++) {
		if(content[0] == xiaomi_oui_list[i][0] && content[1] == xiaomi_oui_list[i][1] && content[2] == xiaomi_oui_list[i][2])
			return 0;
	}

	fprintf(stderr, "invalid mac addr in %s\n", WLAN_MAC_BIN);
	return 1;
}

static int write_wlan_mac_bin_file(uint8_t addr[MAC_ADDR_SIZE])
{
	FILE* fp;

	fp = fopen(WLAN_MAC_BIN, "w");
	if (fp == NULL)
		return 0;

	fwrite((void *)addr, MAC_ADDR_SIZE, 1, fp);
	fclose(fp);

	return 1;
}

static int check_bd_mac_bin_file(void) {
	char content[6+1];
	FILE* fp;
	size_t i;

	fp = fopen(BD_MAC_BIN, "r");
	if (fp == NULL)
		return 1;

	memset(content, 0, sizeof(content));
	fread(content, 1, sizeof(content) - 1, fp);
	fclose(fp);

	for (i = 0; i < xiaomi_oui_list_size; i++) {
		if(content[0] == xiaomi_oui_list[i][0] && content[1] == xiaomi_oui_list[i][1] && content[2] == xiaomi_oui_list[i][2])
			return 0;
	}

	fprintf(stderr, "invalid mac addr in %s\n", BD_MAC_BIN);
	return 1;
}

static int write_bd_mac_bin_file(uint8_t addr[MAC_ADDR_SIZE])
{
	FILE* fp;

	fp = fopen(BD_MAC_BIN, "w");
	if (fp == NULL)
		return 0;

	fwrite((void *)addr, MAC_ADDR_SIZE, 1, fp);
	fclose(fp);

	return 1;
}

int main() {
	int rc, i;

	qmi_idl_service_object_type dms_service;
	struct qmi_idl_service_object dms_service_object;
	qmi_client_type client, notifier;
	qmi_cci_os_signal_type params;
	unsigned int num_entries, num_services;
	qmi_service_info info[10];

	qminvapi_req_t  req;
	qminvapi_resp_t resp;

	uint8_t wlan_addr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t bd_addr[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	if ( (check_wlan_mac_bin_file() == 0) && (check_bd_mac_bin_file() == 0) ) {
		printf("mac addr files already exist! returning.\n");
		return 0;
	}

	if (SUCCESS != setup_dlsym()) {
		goto generate_random;
	}

	dms_service = (*xiaomi_qmi_nv_get_service_object_internal_v01_shim)(1, 6, 5);
	if (dms_service == NULL) {
		fprintf(stderr, "%s: Not able to get the service handle", __func__);
		ALOGE("%s: Not able to get the service handle", __func__);
		goto generate_random;
	}

	dms_service_object = *dms_service;
	fprintf(stderr, "%s: dms_service: ", __func__ );
	dump_struct(&dms_service_object, sizeof(struct qmi_idl_service_object));

	rc = (*qmi_client_notifier_init_shim)(dms_service, &params, &notifier);
	if (rc) {
		fprintf(stderr, "%s: qmi_client_notifier_init returned %d\n", __func__, rc);
		ALOGE("%s: qmi_client_notifier_init returned %d\n", __func__, rc);
		goto generate_random;
	}

	while(1) {
		rc = (*qmi_client_get_service_list_shim)(dms_service, NULL, NULL, &num_services);
		fprintf(stderr, "%s: qmi_client_get_service_list() returned %d num_services = %d\n", __func__, rc, num_services);
		ALOGI("%s: qmi_client_get_service_list() returned %d num_services = %d\n", __func__, rc, num_services);
		if(rc == QMI_NO_ERR)
			break;

		/* wait for server to come up */
		sleep(1);
	}

	num_entries = num_services;

	rc = (*qmi_client_get_service_list_shim)(dms_service, info, &num_entries, &num_services);
	fprintf(stderr, "%s: qmi_client_get_service_list() returned %d num_entries = %d num_services = %d\n", __func__, rc, num_entries, num_services);
	ALOGI("%s: qmi_client_get_service_list() returned %d num_entries = %d num_services = %d\n", __func__, rc, num_entries, num_services);

	rc = (*qmi_client_init_shim)(&info[0], dms_service, NULL, NULL, NULL, &client);
	if (rc) {
		fprintf(stderr, "%s: qmi_client_init failed %d\n", __func__, rc);
		ALOGE("%s: qmi_client_init failed %d\n", __func__, rc);
		goto generate_random;
	}

	req.index = 4678;
	req.offset = 0;
	memset(&resp, 0, sizeof(resp));
	rc = (*qmi_client_send_msg_sync_shim)(client, 1, &req, sizeof(req), &resp, sizeof(resp), 100);
	if (rc) {
		fprintf(stderr, "%s: wlan nv read failed %d\n", __func__, rc);
		ALOGE("%s: wlan nv read failed %d\n", __func__, rc);
		goto generate_random;
	}
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		wlan_addr[i] = resp.buf[8+i];
	}

	req.index = 447;
	req.offset = 0;
	memset(&resp, 0, sizeof(resp));
	rc = (*qmi_client_send_msg_sync_shim)(client, 1, &req, sizeof(req), &resp, sizeof(resp), 100);
	if (rc) {
		fprintf(stderr, "%s: bd nv read failed %d\n", __func__, rc);
		ALOGE("%s: bd nv read failed %d\n", __func__, rc);
		goto generate_random;
	}
	for (i = 0; i < MAC_ADDR_SIZE; i++) {
		bd_addr[i] = resp.buf[13-i];
	}

	rc = (*qmi_client_release_shim)(client);
	if (rc) {
		fprintf(stderr, "%s: qmi_client_release of client failed %d\n", __func__, rc);
		ALOGE("%s: qmi_client_release of client failed %d\n", __func__, rc);
	}

	rc = (*qmi_client_release_shim)(notifier);
	if (rc) {
		fprintf(stderr, "%s: qmi_client_release of client notifier %d\n", __func__, rc);
		ALOGE("%s: qmi_client_release of client notifier %d\n", __func__, rc);
	}

	goto out;

generate_random:
	fprintf(stderr, "using randomized MAC address\n");
	ALOGI("using randomized MAC address\n");

	// We don't need strong randomness, and if the NV is corrupted
	// any hardware values are suspect, so just seed it with the
	// current time
	srand(time(NULL));

	i = rand() % xiaomi_oui_list_size;
	memcpy(wlan_addr, xiaomi_oui_list[i], 3);
	memcpy(bd_addr, xiaomi_oui_list[i], 3);

	for (i = 3; i < MAC_ADDR_SIZE; i++) {
		wlan_addr[i] = rand() % 255;
		bd_addr[i] = rand() % 255;
	}

out:
	if (libqmi_cci_handle)
		dlclose(libqmi_cci_handle);
	if (libqminvapi_handle)
		dlclose(libqminvapi_handle);

	rc = write_wlan_mac_bin_file(wlan_addr);
	if (!rc) {
		fprintf(stderr, "writing %s failed!\n", WLAN_MAC_BIN);
	}

	rc = write_bd_mac_bin_file(bd_addr);
	if (!rc) {
		fprintf(stderr, "writing %s failed!\n", BD_MAC_BIN);
	}

	printf("wlan=%02x%02x%02x%02x%02x%02x\n", wlan_addr[0], wlan_addr[1],
			wlan_addr[2], wlan_addr[3], wlan_addr[4], wlan_addr[5]);
	printf("bd=%02x%02x%02x%02x%02x%02x\n", bd_addr[0], bd_addr[1],
			bd_addr[2], bd_addr[3], bd_addr[4], bd_addr[5]);

	return 0;
}
