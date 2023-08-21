# eraser

Library for erasure coding using binary finite fields.
The code was originally based on [vishesh-khemani/erasure-coding](https://github.com/vishesh-khemani/erasure-coding).

To test it out on the command line:

1. `zig build`
2. `./zig-out/bin/eraser encode --data <input file> --code <code file prefix>`
3. `./zig-out/bin/eraser decode --data <output file> --code <code file prefix>`

Note that you have to make sure to use the same `<code file prefix>` for encode and decode operations.
The default program will create a _3 of 5_ erasure coder *(N=5, K=3)*. In other words, it will spread the data into 5 chunks but only requires any 3 out of 5 chunks to reconstruct the data.
