// USBHIDHELPER64.cpp : DLL アプリケーション用にエクスポートされる関数を定義します。
//

#include "stdafx.h"


#include <tchar.h>
#include <setupapi.h>	//From Platform SDK. Definitions needed for the SetupDixxx() functions, which we use to
						//find our plug and play device.
#include <malloc.h>

#pragma comment(lib, "setupapi.lib")

//#define MY_DEVICE_ID  _T("Vid_04d8&Pid_003F")


static HANDLE	WriteHandle;
static HANDLE	ReadHandle;


static int strcontain(LPTSTR buf, LPTSTR str)
{
	int	l1 = lstrlen(buf);
	int	l2 = lstrlen(str);
	int	i, h;
	for (i = 0; i < (l1-l2); i++) {
		for (h = 0; h < l2; h++) {
			if (buf[i+h] != str[h]) {
				break;
			}
		}
		if (h >= l2) {
			return(TRUE);
		}
	}
	return(FALSE);
}

/* 
Before we can "connect" our application to our USB embedded device, we must first find the device.
A USB bus can have many devices simultaneously connected, so somehow we have to find our device, and only
our device.  This is done with the Vendor ID (VID) and Product ID (PID).  Each USB product line should have
a unique combination of VID and PID.  

Microsoft has created a number of functions which are useful for finding plug and play devices.  Documentation
for each function used can be found in the MSDN library.  We will be using the following functions:

SetupDiGetClassDevs()					//provided by setupapi.dll, which comes with Windows
SetupDiEnumDeviceInterfaces()			//provided by setupapi.dll, which comes with Windows
GetLastError()							//provided by kernel32.dll, which comes with Windows
SetupDiDestroyDeviceInfoList()			//provided by setupapi.dll, which comes with Windows
SetupDiGetDeviceInterfaceDetail()		//provided by setupapi.dll, which comes with Windows
SetupDiGetDeviceRegistryProperty()		//provided by setupapi.dll, which comes with Windows
malloc()								//part of C runtime library, msvcrt.dll?
CreateFile()							//provided by kernel32.dll, which comes with Windows

We will also be using the following unusual data types and structures.  Documentation can also be found in
the MSDN library:

PSP_DEVICE_INTERFACE_DATA
PSP_DEVICE_INTERFACE_DETAIL_DATA
SP_DEVINFO_DATA
HDEVINFO
HANDLE
GUID

The ultimate objective of the following code is to call CreateFile(), which opens a communications
pipe to a specific device (such as a HID class USB device endpoint).  CreateFile() returns a "handle" 
which is needed later when calling ReadFile() or WriteFile().  These functions are used to actually 
send and receive application related data to/from the USB peripheral device.

However, in order to call CreateFile(), we first need to get the device path for the USB device
with the correct VID and PID.  Getting the device path is a multi-step round about process, which
requires calling several of the SetupDixxx() functions provided by setupapi.dll.
*/

/*
HID_ENUM()
HID_OPEN()
HID_WRITE()
HID_READ()
*/
#define BUF_SIZE	(2048)
extern "C"  __declspec(dllexport)
BOOL APIENTRY HID_ENUM(DWORD vid, DWORD pid, LPDWORD pcnt)
{
	//Globally Unique Identifier (GUID) for HID class devices.  Windows uses GUIDs to identify things.
	static
	GUID		InterfaceClassGuid = {0x4d1e55b2, 0xf16f, 0x11cf, 0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}; 
	static
	BYTE		buf2048_0[BUF_SIZE];
	static
	BYTE		buf2048_1[BUF_SIZE];

	HDEVINFO	hdi = INVALID_HANDLE_VALUE;
	PSP_DEVICE_INTERFACE_DATA
				pdid = (PSP_DEVICE_INTERFACE_DATA)buf2048_0;
	PSP_DEVICE_INTERFACE_DETAIL_DATA
				pdidd = (PSP_DEVICE_INTERFACE_DETAIL_DATA)buf2048_1;
	SP_DEVINFO_DATA
				DevInfoData;

	DWORD		ifidx = 0;
	DWORD		StatusLastError = 0;
	DWORD		dwRegType;
	DWORD		dwRegSize;
	DWORD		StructureSize = 0;
	PBYTE		PropertyValueBuffer;
	BOOL		MatchFound = FALSE;
	DWORD		ErrorStatus;
	BOOL		rc = FALSE;
	int			match_cnt = 0;
	static
	TCHAR		DeviceIDToFind[256];
	TCHAR		DeviceIDFromRegistry[256];

//#define MY_DEVICE_ID  _T("Vid_04d8&Pid_003F")
	wsprintf(DeviceIDToFind, _T("Vid_%04x&Pid_%04x"), vid, pid);

	//First populate a list of plugged in devices (by specifying "DIGCF_PRESENT"), which are of the specified class GUID. 
	hdi = SetupDiGetClassDevs(&InterfaceClassGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

	//Now look through the list we just populated.  We are trying to see if any of them match our device. 
	while(TRUE)
	{
		pdid->cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
		if(SetupDiEnumDeviceInterfaces(hdi, NULL, &InterfaceClassGuid, ifidx, pdid))
		{
			ErrorStatus = GetLastError();
			if(ERROR_NO_MORE_ITEMS == ErrorStatus)	//Did we reach the end of the list of matching devices in the DeviceInfoTable?
			{	//Cound not find the device.  Must not have been attached.
				break;
			}
		}
		else	//Else some other kind of unknown error ocurred...
		{
			ErrorStatus = GetLastError();
//			goto skip;
			break;
		}

		//Now retrieve the hardware ID from the registry.  The hardware ID contains the VID and PID, which we will then 
		//check to see if it is the correct device or not.

		//Initialize an appropriate SP_DEVINFO_DATA structure.  We need this structure for SetupDiGetDeviceRegistryProperty().
		DevInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
		SetupDiEnumDeviceInfo(hdi, ifidx, &DevInfoData);

		//First query for the size of the hardware ID, so we can know how big a buffer to allocate for the data.
		SetupDiGetDeviceRegistryProperty(hdi, &DevInfoData, SPDRP_HARDWAREID, &dwRegType, NULL, 0, &dwRegSize);

		//Allocate a buffer for the hardware ID.
		PropertyValueBuffer = (BYTE *) malloc (dwRegSize);
		if(PropertyValueBuffer == NULL)	//if null, error, couldn't allocate enough memory
		{	//Can't really recover from this situation, just exit instead.
			goto skip;		
		}

		//Retrieve the hardware IDs for the current device we are looking at.  PropertyValueBuffer gets filled with a 
		//REG_MULTI_SZ (array of null terminated strings).  To find a device, we only care about the very first string in the
		//buffer, which will be the "device ID".  The device ID is a string which contains the VID and PID, in the example 
		//format "Vid_04d8&Pid_003f".
		SetupDiGetDeviceRegistryProperty(hdi, &DevInfoData, SPDRP_HARDWAREID, &dwRegType, PropertyValueBuffer, dwRegSize, NULL);

		//Now check if the first string in the hardware ID matches the device ID of my USB device.
#ifdef UNICODE
//■		String^ DeviceIDFromRegistry = gcnew String((wchar_t *)PropertyValueBuffer);
#else
//■		String^ DeviceIDFromRegistry = gcnew String((char *)PropertyValueBuffer);
#endif
		lstrcpyn(DeviceIDFromRegistry, (TCHAR*)PropertyValueBuffer, sizeof(DeviceIDFromRegistry));

		free(PropertyValueBuffer);		//No longer need the PropertyValueBuffer, free the memory to prevent potential memory leaks

		//Convert both strings to lower case.  This makes the code more robust/portable accross OS Versions
#if 1
		CharLower(DeviceIDFromRegistry);
		CharLower(DeviceIDToFind);
#else
		DeviceIDFromRegistry = DeviceIDFromRegistry->ToLowerInvariant();	
		DeviceIDToFind = DeviceIDToFind->ToLowerInvariant();				
#endif
		//Now check if the hardware ID we are looking at contains the correct VID/PID
#if 1
		MatchFound = strcontain(DeviceIDFromRegistry, DeviceIDToFind);
#else
		MatchFound = DeviceIDFromRegistry->Contains(DeviceIDToFind);		
#endif
		if(MatchFound == TRUE) {
			match_cnt++;
		}

		ifidx++;	
		//Keep looping until we either find a device with matching VID and PID, or until we run out of items.
	}
	*pcnt = match_cnt;
	rc = TRUE;
skip:
	if (hdi != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(hdi);	//Clean up the old structure we no longer need.
		hdi = INVALID_HANDLE_VALUE;
	}
	return(rc);
}


extern "C"  __declspec(dllexport)
BOOL APIENTRY HID_OPEN(DWORD vid, DWORD pid, DWORD did)
{
	//Globally Unique Identifier (GUID) for HID class devices.  Windows uses GUIDs to identify things.
	static
	GUID		InterfaceClassGuid = {0x4d1e55b2, 0xf16f, 0x11cf, 0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}; 
	static
	BYTE		buf2048_0[BUF_SIZE];
	static
	BYTE		buf2048_1[BUF_SIZE];

	HDEVINFO	hdi = INVALID_HANDLE_VALUE;
	PSP_DEVICE_INTERFACE_DATA
				pdid = (PSP_DEVICE_INTERFACE_DATA)buf2048_0;
	PSP_DEVICE_INTERFACE_DETAIL_DATA
				pdidd = (PSP_DEVICE_INTERFACE_DETAIL_DATA)buf2048_1;
	SP_DEVINFO_DATA
				DevInfoData;

	DWORD		ifidx = 0;
	DWORD		StatusLastError = 0;
	DWORD		dwRegType;
	DWORD		dwRegSize;
	DWORD		StructureSize = 0;
	PBYTE		PropertyValueBuffer;
	BOOL		MatchFound = FALSE;
	DWORD		ErrorStatus;
	BOOL		rc = FALSE;
	int			match_cnt = 0;
	static
	TCHAR		DeviceIDToFind[256];
	TCHAR		DeviceIDFromRegistry[256];

//#define MY_DEVICE_ID  _T("Vid_04d8&Pid_003F")
	wsprintf(DeviceIDToFind, _T("Vid_%04x&Pid_%04x"), vid, pid);

	//First populate a list of plugged in devices (by specifying "DIGCF_PRESENT"), which are of the specified class GUID. 
	hdi = SetupDiGetClassDevs(&InterfaceClassGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

	//Now look through the list we just populated.  We are trying to see if any of them match our device. 
	while(TRUE)
	{
		pdid->cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);
		if(SetupDiEnumDeviceInterfaces(hdi, NULL, &InterfaceClassGuid, ifidx, pdid))
		{
			ErrorStatus = GetLastError();
			if(ERROR_NO_MORE_ITEMS == ErrorStatus)	//Did we reach the end of the list of matching devices in the DeviceInfoTable?
			{	//Cound not find the device.  Must not have been attached.
				goto skip;
			}
		}
		else	//Else some other kind of unknown error ocurred...
		{
			ErrorStatus = GetLastError();
			goto skip;
		}

		//Now retrieve the hardware ID from the registry.  The hardware ID contains the VID and PID, which we will then 
		//check to see if it is the correct device or not.

		//Initialize an appropriate SP_DEVINFO_DATA structure.  We need this structure for SetupDiGetDeviceRegistryProperty().
		DevInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
		SetupDiEnumDeviceInfo(hdi, ifidx, &DevInfoData);

		//First query for the size of the hardware ID, so we can know how big a buffer to allocate for the data.
		SetupDiGetDeviceRegistryProperty(hdi, &DevInfoData, SPDRP_HARDWAREID, &dwRegType, NULL, 0, &dwRegSize);

		//Allocate a buffer for the hardware ID.
		PropertyValueBuffer = (BYTE *) malloc (dwRegSize);
		if(PropertyValueBuffer == NULL)	//if null, error, couldn't allocate enough memory
		{	//Can't really recover from this situation, just exit instead.
			goto skip;		
		}

		//Retrieve the hardware IDs for the current device we are looking at.  PropertyValueBuffer gets filled with a 
		//REG_MULTI_SZ (array of null terminated strings).  To find a device, we only care about the very first string in the
		//buffer, which will be the "device ID".  The device ID is a string which contains the VID and PID, in the example 
		//format "Vid_04d8&Pid_003f".
		SetupDiGetDeviceRegistryProperty(hdi, &DevInfoData, SPDRP_HARDWAREID, &dwRegType, PropertyValueBuffer, dwRegSize, NULL);

		//Now check if the first string in the hardware ID matches the device ID of my USB device.
#ifdef UNICODE
//■		String^ DeviceIDFromRegistry = gcnew String((wchar_t *)PropertyValueBuffer);
#else
//■		String^ DeviceIDFromRegistry = gcnew String((char *)PropertyValueBuffer);
#endif
		lstrcpyn(DeviceIDFromRegistry, (TCHAR*)PropertyValueBuffer, sizeof(DeviceIDFromRegistry));

		free(PropertyValueBuffer);		//No longer need the PropertyValueBuffer, free the memory to prevent potential memory leaks

		//Convert both strings to lower case.  This makes the code more robust/portable accross OS Versions
#if 1
		CharLower(DeviceIDFromRegistry);
		CharLower(DeviceIDToFind);
#else
		DeviceIDFromRegistry = DeviceIDFromRegistry->ToLowerInvariant();	
		DeviceIDToFind = DeviceIDToFind->ToLowerInvariant();				
#endif
		//Now check if the hardware ID we are looking at contains the correct VID/PID
#if 1
		MatchFound = strcontain(DeviceIDFromRegistry, DeviceIDToFind);
#else
		MatchFound = DeviceIDFromRegistry->Contains(DeviceIDToFind);		
#endif
		if(MatchFound == TRUE) {
			if (did > 0) {
				did--;
			}
			else {
			//Device must have been found.  Open read and write handles.  In order to do this, we will need the actual device path first.
			//We can get the path by calling SetupDiGetDeviceInterfaceDetail(), however, we have to call this function twice:  The first
			//time to get the size of the required structure/buffer to hold the detailed interface data, then a second time to actually 
			//get the structure (after we have allocated enough memory for the structure.)
			pdidd->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

			//First call populates "StructureSize" with the correct value
			SetupDiGetDeviceInterfaceDetail(hdi, pdid, NULL, 0, &StructureSize, NULL);	
			if (StructureSize > BUF_SIZE) {
				goto skip;
			}
			pdidd->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
				//Now call SetupDiGetDeviceInterfaceDetail() a second time to receive the goods.  
			SetupDiGetDeviceInterfaceDetail(hdi, pdid, pdidd, StructureSize, NULL, NULL); 

			//We now have the proper device path, and we can finally open read and write handles to the device.
			//We store the handles in the global variables "WriteHandle" and "ReadHandle", which we will use later to actually communicate.
			WriteHandle = CreateFile((pdidd->DevicePath), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);

			ErrorStatus = GetLastError();
			//■if(ErrorStatus == ERROR_SUCCESS) {
			//■	ToggleLED_btn->Enabled = true;				//Make button no longer greyed out
			//■}
			ReadHandle = CreateFile((pdidd->DevicePath), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
			ErrorStatus = GetLastError();
			//■if(ErrorStatus == ERROR_SUCCESS)
			//■{
			//■	GetPushbuttonState_btn->Enabled = true;		//Make button no longer greyed out
			//■	StateLabel->Enabled = true;					//Make label no longer greyed out
			//■}
			break;
			}
		}

		ifidx++;	
		//Keep looping until we either find a device with matching VID and PID, or until we run out of items.
	}
	rc = TRUE;
skip:
	if (hdi != INVALID_HANDLE_VALUE) {
		SetupDiDestroyDeviceInfoList(hdi);	//Clean up the old structure we no longer need.
		hdi = INVALID_HANDLE_VALUE;
	}
	return(rc);
}

extern "C"  __declspec(dllexport)
BOOL APIENTRY HID_CLOSE(void)
{
	if (ReadHandle != NULL && ReadHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(ReadHandle);
		ReadHandle = NULL;
	}
	if (WriteHandle != NULL && WriteHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(WriteHandle);
		WriteHandle = NULL;
	}
	return(TRUE);
}

extern "C"  __declspec(dllexport)
BOOL APIENTRY WRITE_HID(LPBYTE pbuf, DWORD size)
{
	DWORD	BytesWritten = 0;
	unsigned
	char	OutputPacketBuffer[65];	//Allocate a memory buffer equal to our endpoint size + 1
	BOOL	rc;

	OutputPacketBuffer[0] = 0;			//The first byte is the "Report ID".  This number is used by the USB driver, but does not
				//get tranmitted accross the USB bus.  The custom HID class firmware is only configured for
				//one type of report, therefore, we must always initializate this byte to "0" before sending
				//a data packet to the device.
	#if 1
	if (size > 64) {
	size = 64;
	}
	memcpy(&OutputPacketBuffer[1], pbuf, size);
	#else
	OutputPacketBuffer[1] = 0x80;		//0x80 is the "Toggle LED(s)" command in the firmware
				//For simplicity, we will leave the rest of the buffer uninitialized, but you could put real
				//data in it if you like.
	#endif

	//The basic Windows I/O functions WriteFile() and ReadFile() can be used to read and write to HID class USB devices.
	//Note that we need the handle which we got earlier when we called CreateFile() (when we hit the connect button).
	//The following function call will send out 64 bytes (starting from OutputPacketBuffer[1]) to the USB device.  The data will
	//arrive on the OUT interrupt endpoint.
	rc = WriteFile(WriteHandle, OutputPacketBuffer, 65, &BytesWritten, 0);	//Blocking function, unless an "overlapped" structure is used
	if (rc == FALSE || BytesWritten != 65) {
		return(FALSE);
	}
	return(TRUE);
}

extern "C"  __declspec(dllexport)
BOOL APIENTRY READ_HID(LPBYTE pbuf, DWORD size)
{
	DWORD	BytesRead = 0;
	unsigned
	char	InputPacketBuffer[65];	//Allocate a memory buffer equal to our endpoint size + 1
	BOOL	rc;

	InputPacketBuffer[0] = 0;				//The first byte is the "Report ID" and does not get transmitted over the USB bus.  Always set = 0.

	//Now get the response packet from the firmware.
	//The following call to ReadFIle() retrieves 64 bytes of data from the USB device.
	rc = ReadFile(ReadHandle, InputPacketBuffer, 65, &BytesRead, 0);		//Blocking function, unless an "overlapped" structure is used	
	if (rc == FALSE || BytesRead != 65) {
		return(FALSE);
	}

	//InputPacketBuffer[0] is the report ID, which we don't care about.
	//InputPacketBuffer[1] is an echo back of the command.
	//InputPacketBuffer[2] contains the I/O port pin value for the pushbutton.  

	if (size > 64) {
	size = 64;
	}
	memcpy(pbuf, &InputPacketBuffer[1], size);

	return(TRUE);
}
