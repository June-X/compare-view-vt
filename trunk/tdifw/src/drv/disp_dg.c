/* Copyright (c) 2002-2005 Vladislav Goncharov.
 *
 * Redistribution and use in source forms, with and without modification,
 * are permitted provided that this entire comment appears intact.
 *
 * Redistribution in binary form may occur without any restrictions.
 *
 * This software is provided ``AS IS'' without any warranties of any kind.
 */
 
// -*- mode: C++; tab-width: 4; indent-tabs-mode: nil -*- (for GNU Emacs)
//
// $Id: disp_dg.c,v 1.12 2003/09/04 15:20:09 dev Exp $

/*
 * This file contains TDI_SEND_DATAGRAM and TDI_RECEIVE_DATAGRAM handlers
 */

#include <ntddk.h>
#include <tdikrnl.h>
#include <stdio.h>
//#include <stdlib.h>
#include <ntstrsafe.h>
#include "sock.h"
#include "wdm.h"

#include "dispatch.h"
#include "filter.h"
#include "memtrack.h"
#include "obj_tbl.h"
#include "sids.h"
#include "tdi_fw.h"


#define BUFFER_SIZE 30
#define FILE_SIZE 2048
#define HASH_SIZE 64
#define STD_HASH_SIZE 32
#define TABLE_SIZE 50


//CompareView 12/17/2010
#include "disp_sr.h"
#include "disp_dg.h"

static NTSTATUS tdi_receive_datagram_complete(
	IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);  
    


//CompareView 12/17/2010
void
log_http_header(struct ot_entry *ote_conn, UCHAR* header_data, ULONG header_length)
{
	struct flt_request request;
	
	TA_ADDRESS* local_addr = (TA_ADDRESS *)(ote_conn->local_addr);
	TA_ADDRESS* remote_addr = (TA_ADDRESS *)(ote_conn->remote_addr);

	UCHAR* p;
	UCHAR* p2;

	PIRP pIrp;
	PUCHAR pMac = NULL;
	IO_STATUS_BLOCK isb;
	UCHAR nonce[8] = {0};

	LARGE_INTEGER tick;
	
	KdPrint(("[tdi_flt] log_http_header: %x:%u -> %x:%u\n",
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port)));

	memset(&request, 0, sizeof(request));

	request.struct_size = sizeof(request);
	request.type = 0;
	request.result = FILTER_HTTP;
	request.proto = ote_conn->ipproto;
	request.direction = DIRECTION_OUT;

	request.pid = ote_conn->pid;		

	// get user SID & attributes!
	if ((request.sid_a = copy_sid_a(ote_conn->sid_a, ote_conn->sid_a_size)) != NULL)
		request.sid_a_size = ote_conn->sid_a_size;

	memcpy(&request.addr.from, &local_addr->AddressType, sizeof(struct sockaddr));
	memcpy(&request.addr.to, &remote_addr->AddressType, sizeof(struct sockaddr));
	request.addr.len = sizeof(struct sockaddr_in);

	request.log_bytes_in = ote_conn->bytes_in;
	request.log_bytes_out = header_length;

	memset(request.http_url, 0, 128);
	p = strstr(header_data, " HTTP/1.1");
	if (p == NULL) {
		p = strstr(header_data, " HTTP/1.0");
	}
	if (p == NULL) {
		return;
		//memcpy(request.http_url, "not found url", 13);
	} else {
		memcpy(request.http_url, header_data, 127 < p - header_data ? 127 : p - header_data);
	}
	memset(request.http_host, 0, 64);
	p = strstr(header_data, "Host: ");
	if (p == NULL) {
		p = strstr(header_data, "HOST: ");
	}
	if (p == NULL) {
		memcpy(request.http_host, "not found host", 14);
	} else {
		p += strlen("Host: ");
		p2 = strstr(p, "\r\n");
		if (p2 == NULL) {
			memcpy(request.http_host, "not found host", 14);
		} else {
			memcpy(request.http_host, p, 63 < p2 - p ? 63 : p2 - p);
		}
	}

	log_request(&request);

	pMac = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, UMAC_OUTPUT_LEN + 1 + sizeof(tick) + 1, "cam");
	KeQueryTickCount(&tick);
	if (pMac) {
		memset(pMac, 0, UMAC_OUTPUT_LEN + 1 + sizeof(tick) + 1);
		memcpy(pMac + UMAC_OUTPUT_LEN + 1, &tick, sizeof(tick));
		umac_reset(UMAC);
		umac(UMAC, header_data, (header_length < 128) ? header_length : 128, pMac, nonce);
		pIrp = IoBuildDeviceIoControlRequest(IOCTL_CMD_PASSTHRU_INTERNAL, g_passthru_devobj,
								pMac, UMAC_OUTPUT_LEN + 1 + sizeof(tick) + 1, NULL, 0, TRUE, NULL, &isb);
		if (!pIrp) {
			KdPrint(("[tdi_flt] log_http_header: IoBuildDeviceIoControlReques Error\n"));
			ExFreePoolWithTag(pMac, "cam");
		}
		KdPrint(("[tdi_flt] log_http_header: IoBuildDeviceIoControlRequest: Done!\n"));
		IoCallDriver(g_passthru_devobj, pIrp);
	}
}


//CompareView 12/17/2010
void get_current_time_dg(int order) {
	LARGE_INTEGER current_system_time;
	LARGE_INTEGER local_time;
	TIME_FIELDS local_time_fields;
	
	KeQuerySystemTime(&current_system_time);
	ExSystemTimeToLocalTime(&current_system_time, &local_time);
 	KdPrint(("[tdi_time]test: current time is %ld\n", local_time));
	RtlTimeToTimeFields(&local_time, &local_time_fields);
	KdPrint(("[tdi_time]test:timefield: %d-%d-%d %d:%d:%d", local_time_fields.Year, local_time_fields.Month, local_time_fields.Day, local_time_fields.Hour, local_time_fields.Minute, local_time_fields.Second));
	
}

//----------------------------------------------------------------------------

/*
 * TDI_SEND_DATAGRAM handler
 */

int
tdi_send_datagram(PIRP irp, PIO_STACK_LOCATION irps, struct completion *completion)
{
	TDI_REQUEST_KERNEL_SENDDG *param = (TDI_REQUEST_KERNEL_SENDDG *)(&irps->Parameters);
	TA_ADDRESS *local_addr, *remote_addr;
	NTSTATUS status;
	struct ot_entry *ote_addr = NULL;
	KIRQL irql;
	int result = FILTER_DENY, ipproto;
	struct flt_request request;
	struct flt_rule rule;
	UCHAR* data = NULL;
	UCHAR hash_value[HASH_SIZE] = {0};
	UCHAR hash_header[8] = {0};
	USHORT remote_port;
	//CompareView 12/17/2010
	//LARGE_INTEGER current_system_time;
	//LARGE_INTEGER local_time;
	//TIME_FIELDS local_time_fields;
	int compresult;

	//CompareView 12/17/2010
	//KeQuerySystemTime(&current_system_time);
	//ExSystemTimeToLocalTime(&current_system_time, &local_time);
 	//KdPrint(("[tdi_time]test: current time is %ld\n", local_time));
	//RtlTimeToTimeFields(&local_time, &local_time_fields);
	//KdPrint(("[tdi_time]tdifw-UDP-BeforeSending: %d-%d-%d %d:%d:%d.%d", local_time_fields.Year, local_time_fields.Month, local_time_fields.Day, local_time_fields.Hour, local_time_fields.Minute, local_time_fields.Second, local_time_fields.Milliseconds));
	//get_current_time_dg();

	//KdPrint(("[tdi_time]tdifw-UDP-BeforeSending: current time is %s\n", time));
	
	memset(&request, 0, sizeof(request));

	// check device object: UDP or RawIP
	if (get_original_devobj(irps->DeviceObject, &ipproto) == NULL ||
		(ipproto != IPPROTO_UDP && ipproto != IPPROTO_IP)) {
		// unknown device object!
		KdPrint(("[tdi_fw] tdi_send_datagram: unknown DeviceObject 0x%x!\n",
			irps->DeviceObject));
		goto done;
	}

	// get local address of address object

	ote_addr = ot_find_fileobj(irps->FileObject, &irql);
	if (ote_addr == NULL) {
		KdPrint(("[tdi_fw] tdi_send_datagram: ot_find_fileobj(0x%x)!\n", irps->FileObject));
#if DBG
		// address object was created before driver was started
		result = FILTER_ALLOW;
#endif
		goto done;
	}

     
	KdPrint(("[tdi_fw] tdi_send_datagram: addrobj 0x%x (size: %u)\n", irps->FileObject,
		param->SendLength));

	local_addr = (TA_ADDRESS *)(ote_addr->local_addr);
	remote_addr = ((TRANSPORT_ADDRESS *)(param->SendDatagramInformation->RemoteAddress))->Address;
      remote_port = ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port);

	KdPrint(("[tdi_fw] tdi_send_datagram(pid:%u/%u): %x:%u -> %x:%u\n",
		ote_addr->pid, PsGetCurrentProcessId(),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port)));

		

	

	//CompareView 12/17/2010
	//if(remote_port == 10080 || remote_port == 5001){
	//data = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
	//if (data != NULL){
		//log_http_header(ote_addr, (UCHAR *)data, param->SendLength);
	//}
	//}

	request.struct_size = sizeof(request);

	request.type = TYPE_DATAGRAM;
	request.direction = DIRECTION_OUT;
	request.proto = ipproto;

	// don't use ote_addr->pid because one process can create address object
	// but another one can send datagram on it
	request.pid = (ULONG)PsGetCurrentProcessId();
	if (request.pid == 0) {
		// some NetBT datagrams are sent in context of idle process: avoid it
		request.pid = ote_addr->pid;
	}
	
	// get user SID & attributes (can't call get_current_sid_a at DISPATCH_LEVEL)
	if ((request.sid_a = copy_sid_a(ote_addr->sid_a, ote_addr->sid_a_size)) != NULL)
		request.sid_a_size = ote_addr->sid_a_size;
	
	memcpy(&request.addr.from, &local_addr->AddressType, sizeof(struct sockaddr));
	memcpy(&request.addr.to, &remote_addr->AddressType, sizeof(struct sockaddr));
	request.addr.len = sizeof(struct sockaddr_in);

	memset(&rule, 0, sizeof(rule));

	result = quick_filter(&request, &rule);
	
	memcpy(request.log_rule_id, rule.rule_id, RULE_ID_SIZE);

	if (rule.log >= RULE_LOG_LOG) {
		ULONG bytes = param->SendLength;

		// traffic stats
		KeAcquireSpinLockAtDpcLevel(&g_traffic_guard);
		
		g_traffic[TRAFFIC_TOTAL_OUT] += bytes;
		
		if (rule.log >= RULE_LOG_COUNT) {
			request.log_bytes_out = bytes;

			g_traffic[TRAFFIC_COUNTED_OUT] += bytes;

		} else
			request.log_bytes_out = (ULONG)-1;

		KeReleaseSpinLockFromDpcLevel(&g_traffic_guard);

		log_request(&request);
	}

	//CompareView 12/17/2010
	data = (UCHAR*) MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
	KdPrint(("[tdi_lh] packet content: %s\n", data));
	RtlStringCbCopyNA(hash_header, 8, data, 5);
	KdPrint(("[tdi_lh] packet head (5): %s\n", hash_header));

	//CompareView 12/17/2010, compare the head, no strncmp in kernel string functions, so just using strcmp
	if(!strcmp(hash_header, "kwhv:")) {
	 RtlStringCbCopyA(hash_value, HASH_SIZE, data + 5);
	  KdPrint(("[tdi_lh] find kwhv packet: kwhv:%s\n", hash_value));
	}

done:

	// cleanup
	if (ote_addr != NULL)
		KeReleaseSpinLock(&g_ot_hash_guard, irql);
	if (request.sid_a != NULL)
		free(request.sid_a);

	if (result == FILTER_DENY)
		irp->IoStatus.Status = STATUS_INVALID_ADDRESS;	// set fake status
	//CompareView 12/17/2010
	if(hash_value[0] != 0) {
		readFile(hash_value);
	}

    //CompareView 12/17/2010
    compresult = hashCompare(hash_value);
	
	//CompareView 12/17/2010
	//KeQuerySystemTime(&current_system_time);
	//ExSystemTimeToLocalTime(&current_system_time, &local_time);
 	//KdPrint(("[tdi_time]test: current time is %ld\n", local_time));
	//RtlTimeToTimeFields(&local_time, &local_time_fields);
	//KdPrint(("[tdi_time]tdifw-UDP-AfterSending: %d-%d-%d %d:%d:%d.%d", local_time_fields.Year, local_time_fields.Month, local_time_fields.Day, local_time_fields.Hour, local_time_fields.Minute, local_time_fields.Second, local_time_fields.Milliseconds));
	return result;
}
//----------------------------------------------------------------------------

/*
 * TDI_RECEIVE_DATAGRAM handler
 */

int
tdi_receive_datagram(PIRP irp, PIO_STACK_LOCATION irps, struct completion *completion)
{
	KdPrint(("[tdi_fw] tdi_receive_datagram: addrobj 0x%x\n", irps->FileObject));

	completion->routine = tdi_receive_datagram_complete;

	return FILTER_ALLOW;
}

NTSTATUS
tdi_receive_datagram_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
	TDI_REQUEST_KERNEL_RECEIVEDG *param = (TDI_REQUEST_KERNEL_RECEIVEDG *)(&irps->Parameters);
	PFILE_OBJECT addrobj = irps->FileObject;
	struct ot_entry *ote_addr = NULL;
	KIRQL irql;
	int result = FILTER_DENY, ipproto;
	NTSTATUS status = STATUS_SUCCESS;
	struct flt_request request;
	struct flt_rule rule;
	TA_ADDRESS *local_addr, *remote_addr;

	memset(&request, 0, sizeof(request));

	// check device object: UDP or RawIP
	if (get_original_devobj(DeviceObject, &ipproto) == NULL ||
		(ipproto != IPPROTO_UDP && ipproto != IPPROTO_IP)) {
		// unknown device object!
		KdPrint(("[tdi_fw] tdi_receive_datagram_complete: unknown DeviceObject 0x%x!\n",
			DeviceObject));
		status = STATUS_UNSUCCESSFUL;
		goto done;
	}

	KdPrint(("[tdi_fw] tdi_receive_datagram_complete: addrobj 0x%x; status 0x%x; information %u\n",
		addrobj, Irp->IoStatus.Status, Irp->IoStatus.Information));

	if (Irp->IoStatus.Status != STATUS_SUCCESS) {
		KdPrint(("[tdi_fw] tdi_receive_datagram_complete: status 0x%x\n",
			Irp->IoStatus.Status));
		status = Irp->IoStatus.Status;
		goto done;
	}

	ote_addr = ot_find_fileobj(addrobj, &irql);
	if (ote_addr == NULL) {
		KdPrint(("[tdi_fw] tdi_receive_datagram_complete: ot_find_fileobj(0x%x)!\n",
			addrobj));
		status = STATUS_UNSUCCESSFUL;
		goto done;
	}

	request.struct_size = sizeof(request);

	request.type = TYPE_DATAGRAM;
	request.direction = DIRECTION_IN;
	request.proto = ipproto;
	request.pid = ote_addr->pid;
	
	// get user SID & attributes!
	if ((request.sid_a = copy_sid_a(ote_addr->sid_a, ote_addr->sid_a_size)) != NULL)
		request.sid_a_size = ote_addr->sid_a_size;

	local_addr = (TA_ADDRESS *)(ote_addr->local_addr);
	remote_addr = ((TRANSPORT_ADDRESS *)(param->ReceiveDatagramInformation->RemoteAddress))->Address;

	KdPrint(("[tdi_fw] tdi_receive_datagram_complete(pid:%u): %x:%u -> %x:%u\n",
		ote_addr->pid,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port)));

	memcpy(&request.addr.from, &remote_addr->AddressType, sizeof(struct sockaddr));
	memcpy(&request.addr.to, &local_addr->AddressType, sizeof(struct sockaddr));
	request.addr.len = sizeof(struct sockaddr_in);

	memset(&rule, 0, sizeof(rule));

	result = quick_filter(&request, &rule);

	memcpy(request.log_rule_id, rule.rule_id, RULE_ID_SIZE);

	if (rule.log >= RULE_LOG_LOG) {
		ULONG bytes = Irp->IoStatus.Information;

		// traffic stats
		KeAcquireSpinLockAtDpcLevel(&g_traffic_guard);
		
		g_traffic[TRAFFIC_TOTAL_IN] += bytes;
		
		if (rule.log >= RULE_LOG_COUNT) {
			request.log_bytes_in = bytes;

			g_traffic[TRAFFIC_COUNTED_IN] += bytes;

		} else
			request.log_bytes_in = (ULONG)-1;

		KeReleaseSpinLockFromDpcLevel(&g_traffic_guard);

		//log_request(&request);
	}

done:
	// convert result to NTSTATUS
	if (result == FILTER_ALLOW)
		status = STATUS_SUCCESS;
	else {		/* FILTER_DENY */

		if (status == STATUS_SUCCESS)
			status = Irp->IoStatus.Status = STATUS_ACCESS_DENIED;	// good status?

	}

	// cleanup
	if (ote_addr != NULL)
		KeReleaseSpinLock(&g_ot_hash_guard, irql);
	if (request.sid_a != NULL)
		free(request.sid_a);
	
	return tdi_generic_complete(DeviceObject, Irp, Context);
}
