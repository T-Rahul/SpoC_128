## Hardware Implementation of SpoC-128
This repository has the Verilog code of API compliant SpoC-128

`Code_files` folder consists all the project files.

`Input_and_Expected_Output_Files` consists the test vectors.

For example, the fifth case in `pdi.txt` describes the public data that is undergoing encryption,

>\#### Authenticated Encryption
>
>\#### MsgID=5, KeyID=5, AD Size=0, PT Size=2
>
>\# Instruction: Opcode=Activate Key
>
>INS = 70000000
>
>\# Instruction: Opcode=Authenticated Encryption
>
>INS = 20000000
>
>\# Info :                     Npub, EOI=0 EOT=1, Last=0, Length=16 bytes
>
>HDR = D2000010
>
>DAT = B60630159532A930058CBDEDFA567430
>
>\# Info :          Associated Data, EOI=0 EOT=1, Last=0, Length=0 bytes
>
>HDR = 12000000
>
>\# Info :                Plaintext, EOI=1 EOT=1, Last=1, Length=2 bytes
>
>HDR = 47000002
>
>DAT = A3EE0000

Plaintext is A3EE and the key for the same case is provided as the fifth case of `sdi.txt`. The fifth case of `do.txt` is verified against which generated outputs ciphertext and the tag. The status of the verification (i.e, Success) will be printed in the `log.txt` file as shown in the video below.

https://user-images.githubusercontent.com/85212290/150531722-78eafc43-9e59-4193-9766-1b0b136d6fd8.mov


`Controller flowchart` is the detailed flowchart of the controller states.

