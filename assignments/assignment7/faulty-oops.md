# DISCUSSION ABOUT THE ERROR
- Following log was displayed on the terminal at the time of error
```
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
Mem abort info:
  ESR = 0x96000045
  EC = 0x25: DABT (current EL), IL = 32 bits
  SET = 0, FnV = 0
  EA = 0, S1PTW = 0
  FSC = 0x05: level 1 translation fault
Data abort info:
  ISV = 0, ISS = 0x00000045
  CM = 0, WnR = 1
user pgtable: 4k pages, 39-bit VAs, pgdp=000000004205f000
[0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
Internal error: Oops: 96000045 [#1] SMP
Modules linked in: hello(O) faulty(O) scull(O)
CPU: 0 PID: 158 Comm: sh Tainted: G           O      5.15.18 #1
Hardware name: linux,dummy-virt (DT)
pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : faulty_write+0x14/0x20 [faulty]
lr : vfs_write+0xa8/0x2b0
sp : ffffffc008d23d80
x29: ffffffc008d23d80 x28: ffffff80020d0000 x27: 0000000000000000
x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
x23: 0000000040001000 x22: 0000000000000012 x21: 000000555fd72a70
x20: 000000555fd72a70 x19: ffffff8002006d00 x18: 0000000000000000
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
x5 : 0000000000000001 x4 : ffffffc0006f7000 x3 : ffffffc008d23df0
x2 : 0000000000000012 x1 : 0000000000000000 x0 : 0000000000000000
Call trace:
 faulty_write+0x14/0x20 [faulty]
 ksys_write+0x68/0x100
 __arm64_sys_write+0x20/0x30
 invoke_syscall+0x54/0x130
 el0_svc_common.constprop.0+0x44/0xf0
 do_el0_svc+0x40/0xa0
 el0_svc+0x20/0x60
 el0t_64_sync_handler+0xe8/0xf0
 el0t_64_sync+0x1a0/0x1a4
Code: d2800001 d2800000 d503233f d50323bf (b900003f) 
---[ end trace fb0b1365aae11947 ]---
```

_The above error was due to a **null pointer dereference** which resulted in a kernel oops, eventually leading to rebooting the kernel_

## Analysing the generation of error
- The error was generated in response to an echo command shown below.
- ```echo “hello_world” > /dev/faulty```
- Prior to running this, the system had already loaded the faulty.ko module and had created the faulty node in /dev.
- The ```echo``` command invokes a write operation of the faulty kernel module.
- After investigating the faulty.c file_ops, the faulty_write method contains an inherent bug which does a null pointer dereference as shown below on line 3.
```
   1. ssize_t faulty_write(struct file *filp, const char __user *buf, size_t count, loff_t *pos) {
   2.   /* make a simple fault by dereferencing a NULL pointer */
   3.   *(int *)0 = 0;
   4.   return 0;
   5.  }
```  

## Analysing the effect
- The invocation of the error caused a _kernel oops_. 
- At this stage the kernel terminates all the user-space processes, unmounts the file system and starts to obtain debug information about the error.
- This is what is displayed on the terminal regarding the error.
- If the kernel is unable to recover, the system is _rebooted_, which did happen in our case.

## Analysing the debug message
- The debug log of the oops shows the cause of panic and the kernel state as well as the userspace process state.
- The memory fault registers and their state is displayed in the **Mem abort info** and  **Data abort info** section.
- A brief about the userspace process memory state that caused the error is also shown in the **user pgtable** section. The page size, virtual address fields used are shown.
- Also, what modules were loaded duuring the occurance of this panic is also provided in **Modules linked in**.
- Finally, a detailed call trace showing what values were present at the process stack _(program counter(**pc**), link register (**lr**), stack pointer (**sp**))_ also showning **faulty_write+0x14/0x20 [faulty]** was the location of the last function call when the error happened justifies the resoning of the null pointer dereference.


