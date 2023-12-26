/*
          ______                            __ 
   _  __/ ____/___  ____  ____  ___  _____/ /_
  | |/_/ /   / __ \/ __ \/ __ \/ _ \/ ___/ __/
 _>  </ /___/ /_/ / / / / / / /  __/ /__/ /_  
/_/|_|\____/\____/_/ /_/_/ /_/\___/\___/\__/  
 xconnect.cc Copyright 2023, all rights reserved       

*/

#include <Arduino.h>

#include <mcp_can.h>
#include <SPI.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <Arduino_JSON.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#define WIFI_SSID "dupa"
#define WIFI_PASSWD "sraka"
#define SERVER_PATH "http://127.0.0.1:3000/validate"

#define UP_BTN_PIN 16
#define DOWN_BTN_PIN 4

MCP_CAN CAN(9);


boolean keyVerification(String key) {
  // tss.xconnect.cc publicKey;

  String publicKey = "-----BEGIN PUBLIC KEY-----\n"\
  "MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEOGr4oFdJT4lmncPk5X0qM\n"\
  "YS0G7Qxza740+qI20VT8/YrQy4isrR+MK1B1mnBsPp4mT9z1T+ItzDEoBDUwb173\n"\
  "TuR6GOImhetiUFwyn9TOKnXL2mb9aVV3AGMy6QkWNJO1DEMeq6u1Fp/zyWzlfRs2\n"\
  "J1WUv58xETL5tv8QzjCPhbZV3QRNPc1sNjBGoO3DkhDn9CGgvA1CrQKw1XJ3prLX\n"\
  "Q4JPPxk8egZsAI/5ZNHKFzV1THohX3A07wrWiwDCQu5vnflRLiqQ/1MarxrUoGFF\n"\
  "DRyZcDBd8fS9Cl4NG+V7gv1yufqtGPzBVxZHA7DNsT5YD/aeJG2oShHEAZbi/Ux6\n"\
  "rROS8yVmEG5u5krdUEGTr6kLDcoIpfFJJ0uDHkg2jr1wIU9Qt0oSTjAiqp450yDX\n"\
  "OzAoxuzDOea80I1/ax0fZa33ne0RbYYaOZGQNxJ4DGBSqouoXmeyo32kcRvSp4o4\n"\
  "LUPoT7MEyjduK6P9uUCwy0n5K7Rqqtx8Q2wAG9b9BkRr3dFY+3RZNCfEd/sIejug\n"\
  "DezOKAa08Vo9nvQHlNkbXX2zIr3jHVPOqQrduMFUXrmWYM/CiqB8JP6EjAwaxmmr\n"\
  "AcDYndY0F1g7h53rD9HLmR0br7yaJl9PF5ngCpksPSRZ2e3hgJuOY2VQ9Hw5Xv1y\n"\
  "xPCuw7SKoFuf6bmFbhMRcV7Wd9VhkyUZGtiSC0aLS9/Rec13dx50az/9JaAEzNrN\n"\
  "MIgRI5KZ6P/Nhyfw9f61GdSz4MKEyXtdJgbOoTTjJYO7BTxsGjkHq/MS+ly+4lVU\n"\
  "YESYP0oQADQ4c5t14/vF+74qmuqTrWdx33hFcJmvs75r0HW6eaj8W37JDjdSyGLw\n"\
  "YbinuU7ExNUhMV8QC0FTfmS+ftvJXgg1AnThJj+nBUQ3nUi2oZQHDGbeEJLvKaxi\n"\
  "cOK5d1E9GPEIF4URCgwiPuuIPb4KsHtiT5WZTkDZah5Ql9V95PX9B0ZjN6h9RRWN\n"\
  "///xebddN0Nrj7QdTigmoD6V2RkCKXh0lTi3HcZUwW575+QOyhsNpq9x9zebli/2\n"\
  "QvoESYiU7rVsW17rofgJzcKUqY9dmN5PsfhiNRNhmpYXBy0bTODJkzwBnaaxX+HI\n"\
  "mLOLLIm5FuFMbiL/8JccelBQY3bequxnUY7/n+pFKhpJtxkAfN8uGTTKMjlWv/kF\n"\
  "AlTtcK+1nvKWEn2481p+XN8k5hf6bTlQQLgcrtaohtfrSMRZLvrbsi4WbG39LCyX\n"\
  "lfgeb1MZE0yLBNpzM6HAG4WRIm52tocR6+xzWRENZ6HgfOLXJUEUwYM/bzLzICpP\n"\
  "X/O2KdL0cqhw8k2aaxnrMi9IsPSY/BztjMaTH6RJUIaP5rgOE1LB/TscGkvP78so\n"\
  "7QIDAQAB\n"\
  "-----END PUBLIC KEY-----\n";
  
  // Start WiFi connectivity controller
  WiFi.begin(WIFI_SSID, WIFI_PASSWD);
  while(WiFi.status() != WL_CONNECTED) {
    vTaskDelay(200);
  }
  
  // Initialize the http client
  HTTPClient http;
  String path = (String)SERVER_PATH + "?key=" + key + "&neu=" + "randomshitidk";
  http.begin(path.c_str());

  // GET the server response for the key
  int httpResponse = http.GET();

  // Process the JSON response + verify key
  if(httpResponse>0) {
    // Parse the payload
    String payload = http.getString();
    http.end(); // End the HTTP client to free up resources
    WiFi.disconnect(true); // Disconnect from WiFi and disable radio for power saving.
    JSONVar rtnObject = JSON.parse(payload);
    if(JSON.typeof(rtnObject) == "undefined") {
      Serial.println("ERROR whilst parsing JSON! service malfunction?");
      return false;
    }
    String signature = rtnObject["signature"]; // The process token signature provided by API.
    if(!key) return false;
    
    // Verify JWT key signature
    String hpayload = rtnObject["header"] + "." + rtnObject["payload"];

    EVP_PKEY* pubKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(publicKey, rsa);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();
    if(EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0 | EVP_DigestVerifyUpdate(m_RSAVerifyCtx, hpayload, hpayload.length) <= 0) {
      return false;
    }
    
    // Hashing the payload with SHA256
    SHA256 hashit;
    hashit.doUpdate(hpayload);
    byte hpayloadhashed[32]; // Hashit
    hashit.doFinal(hpayloadhashed);

    int auth = EVP_DigestVerifyFinal(m_RSAVerifyCtx, hpayloadhashed, hpayloadhashed.length);
    if(auth == 1) {
      return true;
    }
    
    return false;

  } else {
    Serial.println("ERROR whilst getting HTTP! service unavailable?");
    Serial.println(httpResponse);
    http.end(); // End the HTTP client to free up resources
    WiFi.disconnect(true); // Disconnect from WiFi and disable radio for power saving.
    return false;
  }
  
}


void setup() {
  Serial.begin(115200);
CAN_INIT:
  if (CAN.begin(MCP_ANY, CAN_500KBPS, MCP_16MHZ) == CAN_OK) {
    Serial.println("CAN BUS CONTROLLER initiation ok");
  } else {
    Serial.println("CAN BUS CONTROLLER initiation failed, retrying in 500ms");
    delay(500);
    goto CAN_INIT;
  }

  // Set CAN BUS mode to MCP_ANY
  CAN.setMode(MCP_ANY);

  pinMode(UP_BTN_PIN, INPUT_PULLUP);
  pinMode(DOWN_BTN_PIN, INPUT_PULLUP);

  //! Start license key verification
  String key = "5DF5EF0FF800000-2511-TEST01";

  if(!keyVerification(key)) {
    
    while(true) {
      vTaskDelay(10);
    }
  }

}


void opSend(short addr, byte a, byte b, byte c, byte d, byte e, byte f, byte g, byte h) {
  unsigned char data[8] = { a, b, c, d, e, f, g, h };
  CAN.sendMsgBuf(addr, 0, 8, data);
}
void loop() {
  vTaskDelay(10);
  opSend(0x10, 22, 41, 52, 11, 51, 12, 0, 0); // Successful auth
  
}