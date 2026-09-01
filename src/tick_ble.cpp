// Copyright (C) 2024, 2025 Jakub "lenwe" Kramarz
// This file is part of The Tick.
// 
// The Tick is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// The Tick is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License

#ifdef USE_BLE

#include <NimBLEDevice.h>
#include "Arduino.h"
#include "tick_capture.h"
#include "tick_utils.h"

static NimBLEServer *pServer;
static NimBLECharacteristic *cardCharacteristic;

static bool deviceConnected = false;
static bool oldDeviceConnected = false;

class ServerCallbacks : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo) override {
    deviceConnected = true;
  };

  void onDisconnect(NimBLEServer* pServer, NimBLEConnInfo& connInfo, int reason) override {
    deviceConnected = false;
  }
} serverCallbacks;

class CharacteristicCallbacks : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic *cardCharacteristic, NimBLEConnInfo& connInfo) override {
    String value = String(cardCharacteristic->getValue().c_str());
    DBG_OUTPUT_PORT.print(F("BLE WRITE: "));
    DBG_OUTPUT_PORT.println(value);

    // Queue it; the main loop transmits. This callback runs on the NimBLE
    // host task, and bit-banging a waveform here would block the BLE stack
    // for tens of milliseconds while racing the capture path on the main
    // loop - on a dual core part, genuinely in parallel.
    if (!tick_tx_submit_pair(value.c_str())) {
      DBG_OUTPUT_PORT.println(F("BLE WRITE rejected"));
    }
  }
} chrCallbacks;

void ble_init(void){
  // Create the BLE Device
  NimBLEDevice::init(dhcp_hostname.c_str());

  if(ble_passkey != 0){
    NimBLEDevice::setSecurityPasskey(ble_passkey);
    NimBLEDevice::setSecurityAuth(true, true, true);
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_DISPLAY_ONLY);
  }

  // Create the BLE Server
  pServer = NimBLEDevice::createServer();
  pServer->setCallbacks(&serverCallbacks);

  // Create the BLE Service
  NimBLEService *pService = pServer->createService(ble_uuid_wiegand_service);
  
  uint32_t service_connection_properties = NIMBLE_PROPERTY::READ | NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::NOTIFY | NIMBLE_PROPERTY::INDICATE;
  // Protect characteristic access only if passkey is set
  if(ble_passkey != 0){
    service_connection_properties |= NIMBLE_PROPERTY::READ_ENC | NIMBLE_PROPERTY::READ_AUTHEN;
    service_connection_properties |= NIMBLE_PROPERTY::WRITE_ENC | NIMBLE_PROPERTY::WRITE_AUTHEN;
  }

  // Create a BLE Characteristic
  cardCharacteristic = pService->createCharacteristic(
    ble_uuid_wiegand_characteristic,
    service_connection_properties,
    300
  );
 
  // Creates BLE Descriptor 0x2904: Characteristic Presentation Format
  NimBLE2904* p2904Descriptor = cardCharacteristic->create2904();
  p2904Descriptor->setFormat(NimBLE2904::FORMAT_UTF8);

  cardCharacteristic->setCallbacks(&chrCallbacks);
  cardCharacteristic->setValue("0000:0");

  // Start the service
  pService->start();

  // Start advertising
  NimBLEAdvertising *pAdvertising = NimBLEDevice::getAdvertising();
  pAdvertising->setName(dhcp_hostname.c_str());
  pAdvertising->addServiceUUID(
    pService->getUUID()
  );

  pAdvertising->enableScanResponse(true);
  pAdvertising->start();
  Serial.println("Waiting a client connection to notify...");
}

void ble_loop(void){
  // disconnecting
  if (!deviceConnected && oldDeviceConnected) {
    pServer->startAdvertising();
    oldDeviceConnected = deviceConnected;
  }
  // connecting
  if (deviceConnected && !oldDeviceConnected) {
    oldDeviceConnected = deviceConnected;
  }
}

void ble_card_read(const char * card_id){
  cardCharacteristic->setValue(
    std::string(card_id)
  );
  if (deviceConnected) {
    cardCharacteristic->notify();
  }
}

#else

void ble_init(void){}
void ble_loop(void){}
void ble_card_read(const char * card_id){}

#endif