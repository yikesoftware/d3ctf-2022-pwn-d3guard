### d3guard

> It's a pity that this challenge was not solved in the end, maybe there is still some space for improvement in the challenge, and we welcome players interested in UEFI PWN to communicate with us in a private message!

#### 1. Analysis

Looking at the parameters of the boot script, you can see that QEMU writes a firmware called OVMF.fd to pflash (which can be seen as bios) at boot time, and mounts the `./content` directory as a fat format drive. Players familiar with UEFI development should quickly think of this as a UEFI PWN, i.e., completing a power-up by completing a vulnerability exploit in a UEFI environment

> All changes to the source file of the challenge are based on the edk2 project: [https://github.com/tianocore/edk2](https://github.com/tianocore/edk2)

Running the startup script without doing anything will take you directly to the operating system and switch to the low privilege user. This user does not have read access to the flag file in the root directory. Combined with the `cat /flag` in the title description, we can tell that we need to elevate privileges in some way to read the contents of the flag

```
/ $ ls -al /flag
-r--------    1 0        0               25 Feb 17 17:33 /flag
/ $ id
uid=1000 gid=1000 groups=1000
```

In general, edk2 provides two interactive ways for users to run EFI programs or set Boot parameters, UI and EFI SHELL. Checking boot.nsh we can see that by default the kernel boot parameters are: `bzImage console=ttyS0 initrd=rootfs.img rdinit=/init quiet`, that is, if we can enter the UI or EFI SHELL and then modify the boot parameters to `bzImage console=ttyS0 initrd=rootfs.img rdinit=/bin/ash` then we can enter the OS as a root shell and read the flag.

However, if you pay attention to the output of the startup process, you will find that the countdown before entering EFI shell is directly skipped (because I patched the entry logic). So you can only try to enter the UI interface. Edk2 the shortcut key to enter the UI interactive interface is F2 (or F12). Long press this key during startup to enter the UI interactive program. However, in this problem, instead of directly entering the UI interactive interface, you first enter the d3guard subroutine, as follows:

```
BdsDxe: loading Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
BdsDxe: starting Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
```

![](https://i.imgur.com/fpyojin.png)

#### 2. Reverse

Then the first task is to reverse analyze the `UiApp` to find the way to be able to access the normal Ui interaction. The `UiApp` module image can be easily extracted with the help of some tools, here we use: https://github.com/yeggor/uefi_retool

Two main vulnerabilities can be found through reverse. One is that there is a format string vulnerability when trying to log in as administrator, which can leak the address saved on the stack, including image address and stack address:

![](https://i.imgur.com/DfCEqEY.png)

Another vulnerability is a heap overflow when editing user description information (which has been discovered by a number of teams): 

![](https://i.imgur.com/Xhubiq9.png)

In addition to the reverse analysis of the `UiApp` image, you also need to read the specific implementation of AllocatePool in edk2, which relates to some details of vulnerability exploitation, this part is temporarily omitted.

> Related codes are located at: https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Core/Dxe/Mem/Pool.c

#### 3. Exploit

Through dynamic debugging, we found that after `New Visitor`, `visitor->name` and `visitor->desc` are located on adjacent memory intervals, so we can overwrite the `POOL_TAIL` of `visitor->desc` and the `POOL_HEAD` of `visitor->name` through a heap overflow vulnerability by swapping their positions so that `visitor->desc` is located at a lower address.

> Focus on the POOL_HEAD structure

```
typedef struct {
  UINT32             Signature;
  UINT32             Reserved;
  EFI_MEMORY_TYPE    Type;
  UINTN              Size;
  CHAR8              Data[1];
} POOL_HEAD;
```

Combined with reading the source code related to AllocatePool, we found that when the `FreePool` function is called, edk2 puts the heap mem into different chains depending on `POOL_HEAD->EFI_MEMORY_TYPE`, and when allocating `visitor->name` and `visitor->desc`, the The `EFI_MEMORY_TYPE` used for the `AllocatePool()` parameter is `EfiReservedMemoryType` (i.e. constant 0). If the `POOL_HEAD->EFI_MEMORY_TYPE` of `visitor->name` is changed to another value by heap overflow, it can be put into other chains and will not be removed when requested again.

![](https://i.imgur.com/13bukEs.png)


![](https://i.imgur.com/aaLRcqD.png)

Finally, in `4. Confirm && Enter OS`, heap memory is allocated once more to copy `visitor->name` & `visitor->desc` and save it. The `EFI_MEMORY_TYPE` requested by `AllocatePool()` at this time is `EfiACPIMemoryNVS` (i.e. constant 10).

![](https://i.imgur.com/bNrOtQr.png)

Combined with the above analysis, set `POOL_HEAD->EFI_MEMORY_TYPE` of `visitor->name` to 10 and free it. the heap mem originally assigned to `visitor->name` enters the free link list (this is a double-linked list), and by hijacking the FD and BK pointers of the double-linked list you can write a custom value to any address write a custom value to any address. Combined with the stack address leaked at the beginning, We can overwrite the return address of the d3guard function.

> Actually the solution of the last step is open, as long as it achieves the purpose of hijacking the control flow

Since the location of `_ModuleEntryPoint+718`, the upper function of `d3guard()`, will judge the return value of `d3guard()` to decide whether to enter the UI interaction interface, the most straightforward approach is to overwrite the d3guard return address to skip the if branch and enter the UI interaction interface directly. However, when actually writing the script, we found that the leaked program address is not stable with the target address offset of the jump, so we overwrite the d3guard return address as the address of a shellcode on the stack, which can be deployed in advance when entering the Admin pass key. With the help of the shellcode and the mirror address in the register, a stable jump target address can be calculated.

After successfully entering the Ui interactive interface, you only need to add a new boot item through the menu and set the parameter `rdinit` to `/bin/sh` and then enter the operating system through it to gain root access

> At first, I didn't think that the step of adding boot options could be a pitfall... In fact, you can compile a copy of the original OVMF.fd, then enter `Boot Maintenance Manager`->enter `Boot Options`->select `Add Boot Option`->select the kernel image `bzImage`->set the boot item name `rootshell`->set the additional parameters for the kernel boot ` console=ttyS0 initrd=rootfs.img rdinit=/bin/sh quiet`->finally return to the main page and select the boot option menu->find the item `rootshell`

---

> Challenge attachment and exploit：https://github.com/yikesoftware/d3ctf-2022-pwn-d3guard

---
