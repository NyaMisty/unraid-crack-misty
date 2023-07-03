#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <libudev.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>
#include "LightHook.h"

typedef void *RSA;
#define DISK_LABEL "UNRAID"
#define BTRS_FORMAT \
  "regGUID=%s&regTy=%s&regTo=\"%s\"&regTm=%s&regGen=0&regDays=0"

typedef int (*RSA_PUBLIC_DECRYPT_FUNC)(int flen, unsigned char* from,
                                       unsigned char* to, RSA* rsa,
                                       int padding);

static char* unraid_uuid = NULL;
static char* unraid_name = NULL;
static char* unraid_date = NULL;
static char* unraid_version = NULL;
RSA_PUBLIC_DECRYPT_FUNC rsa_public_decrypt;
static HookInformation HOOKINFO_rsa_public_decrypt;

// must be static or /usr/lib64/libsmbd-base-samba4.so(smbd_smb2_request_process_read+0x70d) will reference us
// also needs -fvisibility=hidden
static int get_serial_string(char* buffer, size_t size);
static int hook_RSA_public_decrypt(int flen, unsigned char* from, unsigned char* to,
                       RSA* rsa, int padding);

static const char* get_self_exe_name(int full) {
  static char buffer[4096] = "";
  readlink("/proc/self/exe", buffer, 4096);
  if (full) {
    return buffer;
  }
  char* ptr = &buffer[strlen(buffer)];
  while (*ptr != '/') --ptr;
  return (ptr + 1);
}

static void init_unraid_uuid() {
  if (!unraid_uuid) {
    unraid_uuid = (char*)malloc(1024);
    strcpy(unraid_uuid, "1234-1234-1234-1234567890AB");
    int err = get_serial_string(unraid_uuid, 1024);
    if (err && getenv("UNRAID_UUID")) {
      strcpy(unraid_uuid, getenv("UNRAID_UUID"));
    }
    unraid_name = getenv("UNRAID_NAME");
    unraid_date = getenv("UNRAID_DATE");
    unraid_version = getenv("UNRAID_VERSION");
  }
}

static void init_unraid_hook() {
  void *libcrypto = dlopen("/lib64/libcrypto.so.1.1", RTLD_NOW);
  void *ori_rsa_public_decrypt = dlsym(libcrypto, "RSA_public_decrypt");
  assert(ori_rsa_public_decrypt != NULL);

  HOOKINFO_rsa_public_decrypt = CreateHook((void*)ori_rsa_public_decrypt, (void*)&hook_RSA_public_decrypt);
  int status = EnableHook(&HOOKINFO_rsa_public_decrypt);
  assert(status == 1);
  rsa_public_decrypt = (RSA_PUBLIC_DECRYPT_FUNC)HOOKINFO_rsa_public_decrypt.Trampoline;
}

__attribute__((constructor)) void unraid_init() {
  if (!strcmp(get_self_exe_name(0), "emhttpd") ||
      !strcmp(get_self_exe_name(0), "shfs")) {
    init_unraid_uuid();
    init_unraid_hook();
  }
}

static int hook_RSA_public_decrypt(int flen, unsigned char* from, unsigned char* to,
                       RSA* rsa, int padding) {
  if (!strcmp(get_self_exe_name(0), "emhttpd") ||
      !strcmp(get_self_exe_name(0), "shfs")) {
    sprintf(to, BTRS_FORMAT, unraid_uuid, unraid_version, unraid_name,
            unraid_date);
    int len = strlen(to);
    return len;
  } else {
    return rsa_public_decrypt(flen, from, to, rsa, padding);
  }
}

/**** udev stuff ****/
static int get_dev_path(char* buffer, size_t size) {
  char link_device[1024];
  char real_device[1024];

  sprintf(link_device, "/dev/disk/by-label/%s", DISK_LABEL);
  char* rv = realpath(link_device, real_device);
  if (!rv) return 2;

  struct udev* udev;
  struct udev_device* dev;
  struct udev_enumerate* enumerate;
  struct udev_list_entry *devices, *dev_list_entry;

  int find = -1;

  udev = udev_new();
  if (!udev) {
    return 1;
  }

  enumerate = udev_enumerate_new(udev);
  if (!enumerate) {
    return 1;
  }

  udev_enumerate_add_match_subsystem(enumerate, "block");
  udev_enumerate_scan_devices(enumerate);

  devices = udev_enumerate_get_list_entry(enumerate);
  if (!devices) {
    return 1;
  }

  udev_list_entry_foreach(dev_list_entry, devices) {
    const char *path, *tmp;
    unsigned long long disk_size = 0;

    path = udev_list_entry_get_name(dev_list_entry);
    dev = udev_device_new_from_syspath(udev, path);

    if (strncmp(udev_device_get_devtype(dev), "partition", 9) != 0 &&
        strncmp(udev_device_get_sysname(dev), "loop", 4) != 0) {
      const char* devnode = udev_device_get_devnode(dev);
      char* ptr = strstr(real_device, devnode);
      if (ptr && ptr == real_device) {  // prefix
        find = 0;
        strcpy(buffer, udev_device_get_devpath(dev));
      }
    }

    udev_device_unref(dev);
  }

  udev_enumerate_unref(enumerate);
  udev_unref(udev);

  return find;
}

static int get_usb_device(char* buffer, size_t size) {
  char dev_path[1024];
  if (get_dev_path(dev_path, 1024)) {
    return 2;
  }

  int slash_index[1024];
  int slash_count = 0;
  for (int i = 0; i < strlen(dev_path); ++i) {
    if (dev_path[i] == '/') {
      slash_index[slash_count++] = i;
    }
  }

  int find = -1;
  for (int i = slash_count - 1; i >= 0; --i) {
    char usb_device[1024] = "/sys";
    strcpy(&dev_path[slash_index[i]], "/serial");
    strcat(usb_device, dev_path);
    if (!access(usb_device, F_OK | R_OK)) {
      strcpy(buffer, usb_device);
      buffer[strlen(buffer) - strlen("/serial")] = '\0';
      find = 0;
      break;
    }
  }

  return find;
}

static void read_file(char* buff_ptr, char* base_ptr, char* file_ptr, char* file) {
  strcpy(file_ptr, file);
  FILE* fp = fopen(base_ptr, "r");
  fscanf(fp, "%s", buff_ptr);
  fclose(fp);
}

static int get_serial_string(char* buffer, size_t size) {
  char usb_device[1024];
  if (get_usb_device(usb_device, 1024)) {
    return 2;
  }

  char* file_ptr = &usb_device[strlen(usb_device)];
  char* buff_ptr = buffer;

  read_file(buff_ptr, usb_device, file_ptr, "/idVendor");
  strcat(buff_ptr, "-");
  buff_ptr += strlen(buff_ptr);

  read_file(buff_ptr, usb_device, file_ptr, "/idProduct");
  strcat(buff_ptr, "-");
  buff_ptr += strlen(buff_ptr);

  char raw_serial_buffer[1024];
  read_file(raw_serial_buffer, usb_device, file_ptr, "/serial");
  int serial_length = strlen(raw_serial_buffer);
  char* serial_buffer = &raw_serial_buffer[serial_length - 16];
  strcpy(buff_ptr, serial_buffer);
  *(buff_ptr + 4) = '-';
  strcpy(buff_ptr + 5, &serial_buffer[4]);

  int offset = 'A' - 'a';
  for (int i = 0; i < strlen(buffer); ++i) {
    if (buffer[i] >= 'a' && buffer[i] <= 'z') {
      buffer[i] += offset;
    }
  }

  return 0;
}

/*int main() {
  char serial[1024];
  int err = get_serial_string(serial, 1024);
  if (!err) {
    printf("SERIAL: %s\n", serial);
  }
  return 0;
}*/