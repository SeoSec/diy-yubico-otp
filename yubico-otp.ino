  #include "EEPROM.h"
  #include <stdio.h>
  #include <stdint.h>
  #include "libkey.h"
  unsigned long time;
  
  #define POLY 0x8408
  #define AES_BLOCK_SIZE      16
  #define AES_ROUNDS          10
  #define AES_ROUND_KEY_SIZE  176
  
  void aes_key_schedule_128(const uint8_t *key, uint8_t *roundkeys);
  void aes_encrypt_128(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext);
  void aes_decrypt_128(const uint8_t *roundkeys, const uint8_t *ciphertext, uint8_t *plaintext);
  static uint8_t RC[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
  static uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  };
  
  static uint8_t INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
  };
  
  static inline uint8_t mul2(uint8_t a) {
    return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1);
  }
  
  static void shift_rows(uint8_t *state) {
    uint8_t temp;
    temp        = *(state + 1);
    *(state + 1)  = *(state + 5);
    *(state + 5)  = *(state + 9);
    *(state + 9)  = *(state + 13);
    *(state + 13) = temp;
    temp        = *(state + 2);
    *(state + 2)  = *(state + 10);
    *(state + 10) = temp;
    temp        = *(state + 6);
    *(state + 6)  = *(state + 14);
    *(state + 14) = temp;
    temp        = *(state + 15);
    *(state + 15) = *(state + 11);
    *(state + 11) = *(state + 7);
    *(state + 7)  = *(state + 3);
    *(state + 3)  = temp;
  }
  static void inv_shift_rows(uint8_t *state) {
    uint8_t temp;
    temp        = *(state + 13);
    *(state + 13) = *(state + 9);
    *(state + 9)  = *(state + 5);
    *(state + 5)  = *(state + 1);
    *(state + 1)  = temp;
    temp        = *(state + 14);
    *(state + 14) = *(state + 6);
    *(state + 6)  = temp;
    temp        = *(state + 10);
    *(state + 10) = *(state + 2);
    *(state + 2)  = temp;
    temp        = *(state + 3);
    *(state + 3)  = *(state + 7);
    *(state + 7)  = *(state + 11);
    *(state + 11) = *(state + 15);
    *(state + 15) = temp;
  }
  
  void aes_key_schedule_128(const uint8_t *key, uint8_t *roundkeys) {
  
    uint8_t temp[4];
    uint8_t *last4bytes;
    uint8_t *lastround;
    uint8_t i;
  
    for (i = 0; i < 16; ++i) {
      *roundkeys++ = *key++;
    }
  
    last4bytes = roundkeys - 4;
    for (i = 0; i < AES_ROUNDS; ++i) {
      temp[3] = SBOX[*last4bytes++];
      temp[0] = SBOX[*last4bytes++];
      temp[1] = SBOX[*last4bytes++];
      temp[2] = SBOX[*last4bytes++];
      temp[0] ^= RC[i];
      lastround = roundkeys - 16;
      *roundkeys++ = temp[0] ^ *lastround++;
      *roundkeys++ = temp[1] ^ *lastround++;
      *roundkeys++ = temp[2] ^ *lastround++;
      *roundkeys++ = temp[3] ^ *lastround++;
      *roundkeys++ = *last4bytes++ ^ *lastround++;
      *roundkeys++ = *last4bytes++ ^ *lastround++;
      *roundkeys++ = *last4bytes++ ^ *lastround++;
      *roundkeys++ = *last4bytes++ ^ *lastround++;
      *roundkeys++ = *last4bytes++ ^ *lastround++;
      *roundkeys++ = *last4bytes++ ^ *lastround++;
      *roundkeys++ = *last4bytes++ ^ *lastround++;
      *roundkeys++ = *last4bytes++ ^ *lastround++;
      *roundkeys++ = *last4bytes++ ^ *lastround++;
      *roundkeys++ = *last4bytes++ ^ *lastround++;
      *roundkeys++ = *last4bytes++ ^ *lastround++;
      *roundkeys++ = *last4bytes++ ^ *lastround++;
    }
  }
  
  void aes_encrypt_128(const uint8_t *roundkeys, const uint8_t *plaintext, uint8_t *ciphertext) {
  
    uint8_t tmp[16], t;
    uint8_t i, j;
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
      *(ciphertext + i) = *(plaintext + i) ^ *roundkeys++;
    }
    for (j = 1; j < AES_ROUNDS; ++j) {
      for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(tmp + i) = SBOX[*(ciphertext + i)];
      }
      shift_rows(tmp);
  
      for (i = 0; i < AES_BLOCK_SIZE; i += 4)  {
        t = tmp[i] ^ tmp[i + 1] ^ tmp[i + 2] ^ tmp[i + 3];
        ciphertext[i]   = mul2(tmp[i]   ^ tmp[i + 1]) ^ tmp[i]   ^ t;
        ciphertext[i + 1] = mul2(tmp[i + 1] ^ tmp[i + 2]) ^ tmp[i + 1] ^ t;
        ciphertext[i + 2] = mul2(tmp[i + 2] ^ tmp[i + 3]) ^ tmp[i + 2] ^ t;
        ciphertext[i + 3] = mul2(tmp[i + 3] ^ tmp[i]  ) ^ tmp[i + 3] ^ t;
      }
  
      for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        *(ciphertext + i) ^= *roundkeys++;
      }
  
    }
  
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
      *(ciphertext + i) = SBOX[*(ciphertext + i)];
    }
    shift_rows(ciphertext);
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
      *(ciphertext + i) ^= *roundkeys++;
    }
  
  }
  
  void aes_decrypt_128(const uint8_t *roundkeys, const uint8_t *ciphertext, uint8_t *plaintext) {
  
    uint8_t tmp[16];
    uint8_t t, u, v;
    uint8_t i, j;
  
    roundkeys += 160;
  
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
      *(plaintext + i) = *(ciphertext + i) ^ *(roundkeys + i);
    }
    roundkeys -= 16;
    inv_shift_rows(plaintext);
    for (i = 0; i < AES_BLOCK_SIZE; ++i) {
      *(plaintext + i) = INV_SBOX[*(plaintext + i)];
    }
  
    for (j = 1; j < AES_ROUNDS; ++j) {
  
      for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
        *(tmp + i) = *(plaintext + i) ^ *(roundkeys + i);
      }
  
      for (i = 0; i < AES_BLOCK_SIZE; i += 4) {
        t = tmp[i] ^ tmp[i + 1] ^ tmp[i + 2] ^ tmp[i + 3];
        plaintext[i]   = t ^ tmp[i]   ^ mul2(tmp[i]   ^ tmp[i + 1]);
        plaintext[i + 1] = t ^ tmp[i + 1] ^ mul2(tmp[i + 1] ^ tmp[i + 2]);
        plaintext[i + 2] = t ^ tmp[i + 2] ^ mul2(tmp[i + 2] ^ tmp[i + 3]);
        plaintext[i + 3] = t ^ tmp[i + 3] ^ mul2(tmp[i + 3] ^ tmp[i]);
        u = mul2(mul2(tmp[i]   ^ tmp[i + 2]));
        v = mul2(mul2(tmp[i + 1] ^ tmp[i + 3]));
        t = mul2(u ^ v);
        plaintext[i]   ^= t ^ u;
        plaintext[i + 1] ^= t ^ v;
        plaintext[i + 2] ^= t ^ u;
        plaintext[i + 3] ^= t ^ v;
      }
  
      inv_shift_rows(plaintext);
  
      for (i = 0; i < AES_BLOCK_SIZE; ++i) {
        *(plaintext + i) = INV_SBOX[*(plaintext + i)];
      }
  
      roundkeys -= 16;
  
    }
  
    for ( i = 0; i < AES_BLOCK_SIZE; ++i ) {
      *(plaintext + i) ^= *(roundkeys + i);
    }
  
  }
  
  int reverse_bytes(int bytes);
  unsigned short crc16(char *data_p, unsigned short length);
  char fim[32];
  char str2hexstr( char texto[]);
  
  void counterboot() {
    if (EEPROM.read(0) == 0xffff) {
      EEPROM.write(0, 0);
    } else {
      EEPROM.write(0, EEPROM.read(0) + 1);
    }
  }
  uint32_t hs2int(uint8_t c) {
    return (c & 0xF) + 9 * (c >> 6);
  }
  char TK[] = "cbdefghijklnrtuv";
  int byteReverso(int bytes);
  unsigned int tshinv, timestampH = 0x00;
  void setup() {
    // put your setup code here, to run once:
    Serial.begin(9600);
    Keyboard.begin();
    randomSeed(analogRead(0));
    EEPROM.write(1, 0);
    counterboot();
  }
  
  unsigned int ctr = 0;
  unsigned int now = 0;
  unsigned int last = 0;
  unsigned int flag2 = 0;
  
  int byteReverso(int bytes)
  {
    int aux = 0;
    int byte;
    int i;
    for (i = 0; i < 32; i += 8)
    {
      byte = (bytes >> i) & 0xff;
      aux |= byte << (16 - 8 - i);
    }
    return aux;
  }
  
  unsigned short crc16(char *data_p, unsigned short length)
  {
    unsigned char i;
    unsigned int data;
    unsigned int crc = 0xffff;
  
    if (length == 0)
      return (~crc);
  
    do
    {
      for (i = 0, data = (unsigned int)0xff & *data_p++;
           i < 8;
           i++, data >>= 1)
      {
        if ((crc & 0x0001) ^ (data & 0x0001))
          crc = (crc >> 1) ^ POLY;
        else  crc >>= 1;
      }
    } while (--length);
  
    crc = ~crc;
    data = crc;
    crc = (crc << 8) | (data >> 8 & 0xff);
  
    return (crc);
    ctr = 5;
  }
  
  void loop() {
    if (Serial.available() > 0) {
    // read incoming serial data:
    String inChar = Serial.readString();
    //PUBLIC         PRIV UID   KEY
    //vvccccjddvhv 8792ebfe26cc ecde18dbe76fbd0c33330f1c354871db
    if(inChar.substring(0,9) == "hardreset"){
    
    }
    

    
    }
    if ((now - last) > 4) {
      ctr = 0;
    }
    if (ctr == 4) {
      unsigned int rnds = random(0x0000, 0xffff);
      unsigned int timestpL = millis();
      if (timestpL < 0xffff) {
        unsigned  char OTPPLAIN[14];
        unsigned  char OTPPLAINCRC[16];
        //Valores fake
        char uid[] = {0x87, 0x92, 0xeb, 0xfe, 0x26, 0xcc};
        int ctinv, counter = EEPROM.read(0);
        unsigned int tslinv, timestampL = timestpL;
        int s3inv, session = EEPROM.read(1);
        EEPROM.write(1, EEPROM.read(1) + 1);
        int rdinv, rad = rnds;
        int ccinv, crc = {0xc823};
        //Inverte os bytes
        ctinv = byteReverso(counter);
        tslinv = byteReverso(timestampL);
        rdinv = byteReverso(rad);
        ccinv = byteReverso(crc);
  
        //Preenche o valor do UID
        for (int i = 0; i < sizeof(uid); i++)
          OTPPLAIN[i] = uid[i];
        unsigned int dr = (ctinv >> 8) & 0xff;
        unsigned int eq = ctinv & 0xff;
        OTPPLAIN[6] = dr;
        OTPPLAIN[7] = eq;
        dr = (timestampL >> 8) & 0xff;
        eq = timestampL & 0xff;
        OTPPLAIN[8] = eq;
        OTPPLAIN[9] = dr;
        OTPPLAIN[10] = timestampH;
        OTPPLAIN[11] = session;
  
        dr = (rdinv >> 8) & 0xff;
        eq = rdinv & 0xff;
        OTPPLAIN[12] = dr;
        OTPPLAIN[13] = eq;
  
        dr = (crc16(OTPPLAIN, 14) >> 8) & 0xff;
        eq = crc16(OTPPLAIN, 14) & 0xff;
        OTPPLAINCRC[14] = dr;
        OTPPLAINCRC[15] = eq;
  
  
        for (int i = 0; i < sizeof(OTPPLAIN); i++)
          OTPPLAINCRC[i] = OTPPLAIN[i];
        char h[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        for (int i = 0; i < sizeof(OTPPLAINCRC); i++) {
          Serial.print(h[OTPPLAINCRC[i] >> 4]);
          Serial.print(h[OTPPLAINCRC[i] & 0x0F]);
        }
        Serial.println();
  
  
        uint8_t i;
  
        uint8_t key[] = {
          0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec
        };
  
  
        unsigned  char roundkeys[AES_ROUND_KEY_SIZE];
        unsigned  char ciphertext[AES_ROUND_KEY_SIZE];
  
        aes_key_schedule_128(key, roundkeys);
        aes_encrypt_128(roundkeys, OTPPLAINCRC, ciphertext);
        Serial.println();
        Serial.println("Texto criptografado\n");
  
        for (int i = 0; i < AES_BLOCK_SIZE; i++) {
          //Serial.print(ciphertext[i],HEX);
          Serial.print(h[ciphertext[i] >> 4]);
          Serial.print(h[ciphertext[i] & 0x0F]);
        }
        Serial.println();
        Keyboard.print("vvccccjddvhv");
        Serial.println();
        delay(30);
        for (int i = 0; i < 16; i++) {
          Keyboard.print(TK[hs2int(h[ciphertext[i] >> 4])]);
          delay(30);
          Keyboard.print(TK[hs2int(h[ciphertext[i] & 0x0F])]);
        }
  
  
        Keyboard.println();
        // put your main code here, to run repeatedly:
  
      } else {
        timestampH += 1;
      }
      delay(10000);
    }
  
  
  
    if (Keyboard.getLedStatus(LED_SCROLL_LOCK)) {
      now = millis() / 1000;
      if (!flag2) {
        ctr = ctr + 1;
        flag2 = 1;
        last = millis() / 1000;
      }
    } else {
      now = millis() / 1000;
      if (flag2) {
        ctr = ctr + 1;
        flag2 = 0;
        last = millis() / 1000;
  
      }
    }
    delay(500);
  }
