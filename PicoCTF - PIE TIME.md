# PIE TIME - PicoCTF

**Position Independent Executable (PIE)**

- If a binary is compiled as PIE, its base address changes every run.
- but relative offsets between functions stay constant because they’re defined at compile time.

The address of main() is different each time we connect to the server running the vuln.c binary

<img width="480" height="225" alt="image" src="https://github.com/user-attachments/assets/8766b615-03ce-48d5-8151-4066f921afb4" />

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

<img width="427" height="821" alt="image 1" src="https://github.com/user-attachments/assets/540fc07e-13c5-4cec-a76f-0d7249001a81" />

Because the offset between the two functions are the same, we can do PIE bypass via finding relative offsets

**Using GDB**

- `x`  = examine memory
- Left side of output = memory address being examined

<img width="550" height="439" alt="image 2" src="https://github.com/user-attachments/assets/206cc134-939b-46de-a9d4-f3c21d22902f" />

Relative offset between win() and main() in hex is:

<img width="217" height="63" alt="image 3" src="https://github.com/user-attachments/assets/7b24eab4-247f-4199-a681-3c787734576f" />

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
- Real binaries don’t try to leak memory addresses and exploits try to leak those addresses
