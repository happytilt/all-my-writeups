# PIE TIME - PicoCTF

**Position Independent Executable (PIE)**

- If a binary is compiled as PIE, its base address changes every run.
- but relative offsets between functions stay constant because they’re defined at compile time.

The address of main() is different each time we connect to the server running the vuln.c binary

![image.png](image.png)

The goal of this challenge is to call the win() function, which reads out the flag.

**Understanding main()**

- & (amphersand) is the address operator
    - Returns the memory address of a variable, function, etc
- %p is a format specifier for showing memory address
- %lx = long and hexidecimal format

- `void (*foo)(void) = (void (*)())val;
foo();`
    - This code takes an address stored in `val`, and then calls the function at that address.
- We can use this to call the win() function

![image.png](image%201.png)

Because the offset between the two functions are the same, we can do PIE bypass via finding relative offsets

**Using GDB**

- `x`  = examine memory
- Left side of output = memory address being examined

![image.png](image%202.png)

Relative offset between win() and main() in hex is:

![image.png](image%203.png)

**Getting the Flag**

- Connect to the challenge instance
- Get the address of main() and subtract it by the offset (0x96)
    - Subtract because win() is at a lower address than main()
- The difference of those two hex values above will equal the address of win() in memory
- Input that memory address and the flag will be returned

**Closing Notes**

- Same relative offset? Isn’t that dangerous?
- ASLR (Address Space Layout Randomization) is used to add another layer of randomization
    - Randomizes stack, heap, libraries, and PIE binaries
    - But relative offsets within one PIE binary stay fixed
- Real binaries don’t try to leak memory address and exploits try to leak those addresses
-