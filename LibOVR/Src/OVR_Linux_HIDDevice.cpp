/************************************************************************************
Filename    :   OVR_Linux_HIDDevice.cpp
Content     :   Linux HID device implementation.
Created     :   February 26, 2013
Authors     :   Lee Cooper
 
Copyright   :   Copyright 2014 Oculus VR, Inc. All Rights reserved.

Licensed under the Oculus VR Rift SDK License Version 3.1 (the "License"); 
you may not use the Oculus VR Rift SDK except in compliance with the License, 
which is provided at the time of installation or download, or which 
otherwise accompanies this software in either electronic or hard copy form.

You may obtain a copy of the License at

http://www.oculusvr.com/licenses/LICENSE-3.1 

Unless required by applicable law or agreed to in writing, the Oculus VR SDK 
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*************************************************************************************/

#include "OVR_Linux_HIDDevice.h"

#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/hidraw.h>
#include "OVR_HIDDeviceImpl.h"
#include "hidapi.h"

//http://kernel.opensuse.org/cgit/kernel/tree/samples/hidraw/hid-example.c
/*
 * Ugly hack to work around failing compilation on systems that don't
 * yet populate new version of hidraw.h to userspace.
 */
#ifndef HIDIOCSFEATURE
#warning Please have your distro update the userspace kernel headers
//#define HIDIOCSFEATURE(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x06, len)
//#define HIDIOCGFEATURE(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x07, len)
#endif

namespace OVR { namespace Linux {

static const UInt32 MAX_QUEUED_INPUT_REPORTS = 5;
    
//-------------------------------------------------------------------------------------
// **** Linux::DeviceManager
//-----------------------------------------------------------------------------
HIDDeviceManager::HIDDeviceManager(DeviceManager* manager) : DevManager(manager)
{
    UdevInstance = NULL;
    HIDMonitor = NULL;
    HIDMonHandle = -1;
}

//-----------------------------------------------------------------------------
HIDDeviceManager::~HIDDeviceManager()
{
}

//-----------------------------------------------------------------------------
bool HIDDeviceManager::initializeManager()
{
	hid_init();

    if (HIDMonitor)
    {
        return true;
    }

    // Create a udev_monitor handle to watch for device changes (hot-plug detection)
    HIDMonitor = udev_monitor_new_from_netlink(UdevInstance, "udev");
    if (HIDMonitor == NULL)
    {
        return false;
    }

    udev_monitor_filter_add_match_subsystem_devtype(HIDMonitor, "hidraw", NULL);  // filter for hidraw only
	
    int err = udev_monitor_enable_receiving(HIDMonitor);
    if (err)
    {
        udev_monitor_unref(HIDMonitor);
        HIDMonitor = NULL;
        return false;
    }
	
    // Get the file descriptor (fd) for the monitor.  
    HIDMonHandle = udev_monitor_get_fd(HIDMonitor);
    if (HIDMonHandle < 0)
    {
        udev_monitor_unref(HIDMonitor);
        HIDMonitor = NULL;
        return false;
    }

    // This file handle will be polled along-side with the device hid handles for changes
    // Add the handle to the polling list
    if (!DevManager->pThread->AddSelectFd(this, HIDMonHandle))
    {
        close(HIDMonHandle);
        HIDMonHandle = -1;

        udev_monitor_unref(HIDMonitor);
        HIDMonitor = NULL;
        return false;
    }

    return true;
}

//-----------------------------------------------------------------------------
bool HIDDeviceManager::Initialize()
{
    // Get a udev library handle.  This handle must stay active during the
    // duration the lifetime of device monitoring handles
    UdevInstance = udev_new();
    if (!UdevInstance)
        return false;

    return initializeManager();
}

//-----------------------------------------------------------------------------
void HIDDeviceManager::Shutdown()
{
    OVR_ASSERT_LOG((UdevInstance), ("Should have called 'Initialize' before 'Shutdown'."));

    if (HIDMonitor)
    {
        DevManager->pThread->RemoveSelectFd(this, HIDMonHandle);
        close(HIDMonHandle);
        HIDMonHandle = -1;

        udev_monitor_unref(HIDMonitor);
        HIDMonitor = NULL;
    }

    udev_unref(UdevInstance);  // release the library
    
    LogText("OVR::Linux::HIDDeviceManager - shutting down.\n");
}

//-------------------------------------------------------------------------------
bool HIDDeviceManager::AddNotificationDevice(HIDDevice* device)
{
    NotificationDevices.PushBack(device);
    return true;
}

//-------------------------------------------------------------------------------
bool HIDDeviceManager::RemoveNotificationDevice(HIDDevice* device)
{
    for (UPInt i = 0; i < NotificationDevices.GetSize(); i++)
    {
        if (NotificationDevices[i] == device)
        {
            NotificationDevices.RemoveAt(i);
            return true;
        }
    }
    return false;
}


//-----------------------------------------------------------------------------
bool HIDDeviceManager::initVendorProductVersion(hid_device_info* device, HIDDeviceDesc* pDevDesc)
{
	pDevDesc->VendorId = device->vendor_id;
	pDevDesc->ProductId = device->product_id;
	pDevDesc->VersionNumber = device->release_number;
/*
    SInt32 result;
    if (getIntProperty(device, "idVendor", &result))
        pDevDesc->VendorId = result;
    else
        return false;

    if (getIntProperty(device, "idProduct", &result))
        pDevDesc->ProductId = result;
    else
        return false;

    if (getIntProperty(device, "bcdDevice", &result))
        pDevDesc->VersionNumber = result;
    else
        return false;
 */

    return true;
}

//-----------------------------------------------------------------------------
bool HIDDeviceManager::Enumerate(HIDEnumerateVisitor* enumVisitor)
{
    if (!initializeManager())
    {
        return false;
    }
    // Enumerate and print the HID devices on the system
	struct hid_device_info *devs, *cur_dev;

	devs = hid_enumerate(0x0, 0x0);
	cur_dev = devs;
	while (cur_dev) {

		// Check the VID/PID for a match
		if(enumVisitor->MatchVendorProduct(cur_dev->vendor_id, cur_dev->product_id))
		{
			HIDDeviceDesc devDesc;
			devDesc.Path = String(cur_dev->path);
			getFullDesc(cur_dev, &devDesc);

			// Look for the device to check if it is already opened.
			Ptr<DeviceCreateDesc> existingDevice = DevManager->FindHIDDevice(devDesc, true);
			// if device exists and it is opened then most likely the device open()
			// will fail; therefore, we just set Enumerated to 'true' and continue.
			if (existingDevice && existingDevice->pDevice)
			{
				existingDevice->Enumerated = true;
			}
			else
			{
				//libusb does not support 'minimal'

				Linux::HIDDevice device(this);
				device.openDevice(devDesc.Path.ToCStr());
				enumVisitor->Visit(device, devDesc);
				device.closeDevice(false);
			}
		}

		cur_dev = cur_dev->next;
	}

	hid_free_enumeration(devs);

    return true;
}

//-----------------------------------------------------------------------------
OVR::HIDDevice* HIDDeviceManager::Open(const String& path)
{
    Ptr<Linux::HIDDevice> device = *new Linux::HIDDevice(this);

    if (device->HIDInitialize(path))
    {
        device->AddRef();        
        return device;
    }

    return NULL;
}

//-----------------------------------------------------------------------------
bool HIDDeviceManager::getFullDesc(hid_device_info* device, HIDDeviceDesc* desc)
{
        
    if (!initVendorProductVersion(device, desc))
    {
        return false;
    }
        
    desc->SerialNumber = String(device->serial_number);
    desc->Manufacturer = String(device->manufacturer_string);
    desc->Product = String(device->product_string);

    /*
    if (!getStringProperty(device, "serial", &(desc->SerialNumber)))
    {
        return false;
    }
    
    getStringProperty(device, "manufacturer", &(desc->Manufacturer));
    getStringProperty(device, "product", &(desc->Product));
    */
        
    return true;
}

//-----------------------------------------------------------------------------
bool HIDDeviceManager::GetDescriptorFromPath(const char* dev_path, HIDDeviceDesc* desc)
{
    if (!initializeManager())
    {
        return false;
    }

    struct hid_device_info *devs, *cur_dev;

	devs = hid_enumerate(0x0, 0x0);
	cur_dev = devs;
	while (cur_dev) {

		if(strcmp(cur_dev->path,dev_path)==0)
		{
			desc->Path = String(cur_dev->path);
			getFullDesc(cur_dev, desc);
		}

		cur_dev = cur_dev->next;
	}

    hid_free_enumeration(devs);

    return true;
}

//-----------------------------------------------------------------------------
void HIDDeviceManager::OnEvent(int i, int fd)
{
    OVR_UNUSED(i);
    OVR_UNUSED(fd);

    // There is a device status change
    udev_device* hid = udev_monitor_receive_device(HIDMonitor);
    if (hid)
    {
        const char* dev_path = udev_device_get_devnode(hid);
        const char* action = udev_device_get_action(hid);

        HIDDeviceDesc device_info;
        device_info.Path = dev_path;

        MessageType notify_type;
        if (OVR_strcmp(action, "add") == 0)
        {
            notify_type = Message_DeviceAdded;

            // Retrieve the device info.  This can only be done on a connected
            // device and is invalid for a disconnected device

            // Get the USB device
            hid = udev_device_get_parent_with_subsystem_devtype(hid, "usb", "usb_device");
            if (!hid)
            {
                return;
            }

            const char* path = udev_device_get_syspath(hid);

            GetDescriptorFromPath(path, &device_info);
        }
        else if (OVR_strcmp(action, "remove") == 0)
        {
            notify_type = Message_DeviceRemoved;
        }
        else
        {
            return;
        }

        bool error = false;
        bool deviceFound = false;
        for (UPInt i = 0; i < NotificationDevices.GetSize(); i++)
        {
            if (NotificationDevices[i] &&
                NotificationDevices[i]->OnDeviceNotification(notify_type, &device_info, &error))
            {
                // The notification was for an existing device
                deviceFound = true;
                break;
            }
        }

        if (notify_type == Message_DeviceAdded && !deviceFound)
        {
            DevManager->DetectHIDDevice(device_info);
        }

        udev_device_unref(hid);
    }
}

//=============================================================================
//                           Linux::HIDDevice
//=============================================================================
HIDDevice::HIDDevice(HIDDeviceManager* manager)
 :  InMinimalMode(false), HIDManager(manager)
{
    DeviceHandle = NULL;
}

//-----------------------------------------------------------------------------
HIDDevice::~HIDDevice()
{
    if (!InMinimalMode)
    {
        HIDShutdown();
    }
}

//-----------------------------------------------------------------------------
bool HIDDevice::HIDInitialize(const String& path)
{
    const char* hid_path = path.ToCStr();
    if (!openDevice(hid_path))
    {
        LogText("OVR::Linux::HIDDevice - Failed to open HIDDevice: %s", hid_path);
        return false;
    }
    
    HIDManager->DevManager->pThread->AddTicksNotifier(this);
    HIDManager->AddNotificationDevice(this);

    LogText("OVR::Linux::HIDDevice - Opened '%s'\n"
            "                    Manufacturer:'%s'  Product:'%s'  Serial#:'%s'\n",
            DevDesc.Path.ToCStr(),
            DevDesc.Manufacturer.ToCStr(), DevDesc.Product.ToCStr(),
            DevDesc.SerialNumber.ToCStr());
    
    return true;
}

//-----------------------------------------------------------------------------
bool HIDDevice::initInfo()
{
    // Device must have been successfully opened.
    OVR_ASSERT(DeviceHandle >= 0);

    // Get report lengths.
    // TODO: hard-coded for now.  Need to interpret these values from the report descriptor
    InputReportBufferLength = 62;
    OutputReportBufferLength = 0;
    FeatureReportBufferLength = 69;
    
    if (ReadBufferSize < InputReportBufferLength)
    {
        OVR_ASSERT_LOG(false, ("Input report buffer length is bigger than read buffer."));
        return false;
    }
      
    return true;
}

//-----------------------------------------------------------------------------
bool HIDDevice::openDevice(const char* device_path)
{
    // First fill out the device descriptor
    if (!HIDManager->GetDescriptorFromPath(device_path, &DevDesc))
    {
        return false;
    }

    DeviceHandle = hid_open_path(device_path);

    if(!DeviceHandle)
    {
    	LogError("Could not open %s error: %s", device_path, strerror(errno));
    	return false;
    }

    hid_set_nonblocking(DeviceHandle,0);

    HIDManager->DevManager->pThread->AddSelectFd(this, -1); //set this up to be polled
    

    return true;
}
    
//-----------------------------------------------------------------------------
void HIDDevice::HIDShutdown()
{

    HIDManager->DevManager->pThread->RemoveTicksNotifier(this);
    HIDManager->RemoveNotificationDevice(this);
    
    HIDManager->DevManager->pThread->RemoveSelectFd(this,-1);

    if (DeviceHandle >= 0) // Device may already have been closed if unplugged.
    {
    	hid_close(DeviceHandle);
    	DeviceHandle = NULL;
    }
    
    LogText("OVR::Linux::HIDDevice - HIDShutdown '%s'\n", DevDesc.Path.ToCStr());
}

//-----------------------------------------------------------------------------
void HIDDevice::closeDevice(bool wasUnplugged)
{
    OVR_UNUSED(wasUnplugged);
    OVR_ASSERT(DeviceHandle >= 0);
    
    HIDManager->DevManager->pThread->RemoveSelectFd(this,-1);

	hid_close(DeviceHandle);
	DeviceHandle = NULL;
        
    LogText("OVR::Linux::HIDDevice - HID Device Closed '%s'\n", DevDesc.Path.ToCStr());
}

//-----------------------------------------------------------------------------
void HIDDevice::closeDeviceOnIOError()
{
	HIDManager->DevManager->pThread->RemoveSelectFd(this,-1);

    LogText("OVR::Linux::HIDDevice - Lost connection to '%s'\n", DevDesc.Path.ToCStr());
	hid_close(DeviceHandle);
	DeviceHandle = NULL;
}

//http://stackoverflow.com/questions/30519625/remove-input-driver-bound-to-the-hid-interface/30661555#30661555
//http://www.libusb.org/browser/libusb/libusb/os/linux_usbfs.c
//http://www.libusb.org/browser/libusb/libusb/sync.c
//http://stackoverflow.com/questions/30519625/remove-input-driver-bound-to-the-hid-interface/30661555#30661555

//-----------------------------------------------------------------------------
bool HIDDevice::SetFeatureReport(UByte* data, UInt32 length)
{
    
    if (DeviceHandle < 0)
        return false;
    
    UByte reportID = data[0];

    if (reportID == 0)
    {
        // Not using reports so remove from data packet.
        data++;
        length--;
    }

	int r = hid_send_feature_report(DeviceHandle, data, length);
  //  int r = ioctl(DeviceHandle, HIDIOCSFEATURE(length), data);

	return (r >= 0);
}

//-----------------------------------------------------------------------------
bool HIDDevice::GetFeatureReport(UByte* data, UInt32 length)
{
    if (DeviceHandle < 0)
        return false;

	int skipped_report_id = 0;
	int report_number = data[0];

	if (report_number == 0x0) {
		/* Offset the return buffer by 1, so that the report ID
		   will remain in byte 0. */
		data++;
		length--;
		skipped_report_id = 1;
	}

	int r = hid_get_feature_report(DeviceHandle, data, length);
//  int r = ioctl(DeviceHandle, HIDIOCGFEATURE(length), data);

	if(r < 0)
	{
		OVR_DEBUG_LOG(("Error in LibOVR GetFeatureReport: %s",strerror(errno)));
	}

    return (r >= 0);
}

//-----------------------------------------------------------------------------
double HIDDevice::OnTicks(double tickSeconds)
{
    if (Handler)
    {
        return Handler->OnTicks(tickSeconds);
    }
    
    return DeviceManagerThread::Notifier::OnTicks(tickSeconds);
}

//-----------------------------------------------------------------------------
void HIDDevice::OnEvent(int i, int fd)
{
    OVR_UNUSED(i);

    int bytes = 0;

    if(DeviceHandle){

    	bytes = hid_read(DeviceHandle, ReadBuffer, ReadBufferSize);
    }

    // We have data to read from the device
    //int bytes = read(fd, ReadBuffer, ReadBufferSize);
    if (bytes >= 0)
    {
// TODO: I need to handle partial messages and package reconstruction
    	if(bytes > 0){
			if (Handler)
			{
				Handler->OnInputReport(ReadBuffer, bytes);
			}
    	}
    }
    else
    {   // Close the device on read error.
        closeDeviceOnIOError();
    }
}

//-----------------------------------------------------------------------------
bool HIDDevice::OnDeviceNotification(MessageType messageType,
                                     HIDDeviceDesc* device_info,
                                     bool* error)
{
    const char* device_path = device_info->Path.ToCStr();

    if (messageType == Message_DeviceAdded && DeviceHandle < 0)
    {
        // Is this the correct device?
        if (!(device_info->VendorId == DevDesc.VendorId
            && device_info->ProductId == DevDesc.ProductId
            && device_info->SerialNumber == DevDesc.SerialNumber))
        {
            return false;
        }

        // A closed device has been re-added. Try to reopen.
        if (!openDevice(device_path))
        {
            LogError("OVR::Linux::HIDDevice - Failed to reopen a device '%s' that was re-added.\n", 
                     device_path);
            *error = true;
            return true;
        }

        LogText("OVR::Linux::HIDDevice - Reopened device '%s'\n", device_path);

        if (Handler)
        {
            Handler->OnDeviceMessage(HIDHandler::HIDDeviceMessage_DeviceAdded);
        }
    }
    else if (messageType == Message_DeviceRemoved)
    {
        // Is this the correct device?
        // For disconnected device, the device description will be invalid so
        // checking the path is the only way to match them
        if (DevDesc.Path.CompareNoCase(device_path) != 0)
        {
            return false;
        }

        if (DeviceHandle >= 0)
        {
            closeDevice(true);
        }

        if (Handler)
        {
            Handler->OnDeviceMessage(HIDHandler::HIDDeviceMessage_DeviceRemoved);
        }
    }
    else
    {
        OVR_ASSERT(0);
    }

    *error = false;
    return true;
}

//-----------------------------------------------------------------------------
HIDDeviceManager* HIDDeviceManager::CreateInternal(Linux::DeviceManager* devManager)
{
        
    if (!System::IsInitialized())
    {
        // Use custom message, since Log is not yet installed.
        OVR_DEBUG_STATEMENT(Log::GetDefaultLog()->
                            LogMessage(Log_Debug, "HIDDeviceManager::Create failed - OVR::System not initialized"); );
        return 0;
    }

    Ptr<Linux::HIDDeviceManager> manager = *new Linux::HIDDeviceManager(devManager);

    if (manager)
    {
        if (manager->Initialize())
        {
            manager->AddRef();
        }
        else
        {
            manager.Clear();
        }
    }

    return manager.GetPtr();
}
    
} // namespace Linux

//-------------------------------------------------------------------------------------
// ***** Creation

// Creates a new HIDDeviceManager and initializes OVR.
HIDDeviceManager* HIDDeviceManager::Create(Ptr<OVR::DeviceManager>& deviceManager)
{
    
    if (!System::IsInitialized())
    {
        // Use custom message, since Log is not yet installed.
        OVR_DEBUG_STATEMENT(Log::GetDefaultLog()->
            LogMessage(Log_Debug, "HIDDeviceManager::Create failed - OVR::System not initialized"); );
        return 0;
    }

    Ptr<Linux::DeviceManager> deviceManagerLinux = *new Linux::DeviceManager;

    if (!deviceManagerLinux)
    {
		return NULL;
	}

    if (!deviceManagerLinux->Initialize(NULL))
    {         
		return NULL;
    }

	deviceManager = deviceManagerLinux;

	return deviceManagerLinux->GetHIDDeviceManager();
}

} // namespace OVR
