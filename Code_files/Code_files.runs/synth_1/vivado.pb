
p
Command: %s
53*	vivadotcl2?
+synth_design -top LWC -part xc7z020clg484-12default:defaultZ4-113h px? 
:
Starting synth_design
149*	vivadotclZ4-321h px? 
?
@Attempting to get a license for feature '%s' and/or device '%s'
308*common2
	Synthesis2default:default2
xc7z0202default:defaultZ17-347h px? 
?
0Got license for feature '%s' and/or device '%s'
310*common2
	Synthesis2default:default2
xc7z0202default:defaultZ17-349h px? 
?
%s*synth2?
rStarting Synthesize : Time (s): cpu = 00:00:02 ; elapsed = 00:00:02 . Memory (MB): peak = 410.094 ; gain = 96.859
2default:defaulth px? 
?
synthesizing module '%s'638*oasys2
LWC2default:default25
C:/After 19-5-2020/spoc/LWC.vhd2default:default2
512default:default8@Z8-638h px? 
?
synthesizing module '%s'638*oasys2 
PreProcessor2default:default2>
(C:/After 19-5-2020/spoc/PreProcessor.vhd2default:default2
752default:default8@Z8-638h px? 
?
synthesizing module '%s'638*oasys2#
StepDownCountLd2default:default2A
+C:/After 19-5-2020/spoc/StepDownCountLd.vhd2default:default2
452default:default8@Z8-638h px? 
W
%s
*synth2?
+	Parameter N bound to: 16 - type: integer 
2default:defaulth p
x
? 
Y
%s
*synth2A
-	Parameter step bound to: 4 - type: integer 
2default:defaulth p
x
? 
?
%done synthesizing module '%s' (%s#%s)256*oasys2#
StepDownCountLd2default:default2
12default:default2
12default:default2A
+C:/After 19-5-2020/spoc/StepDownCountLd.vhd2default:default2
452default:default8@Z8-256h px? 
?
synthesizing module '%s'638*oasys2
KEY_PISO2default:default2:
$C:/After 19-5-2020/spoc/key_piso.vhd2default:default2
502default:default8@Z8-638h px? 
?
%done synthesizing module '%s' (%s#%s)256*oasys2
KEY_PISO2default:default2
22default:default2
12default:default2:
$C:/After 19-5-2020/spoc/key_piso.vhd2default:default2
502default:default8@Z8-256h px? 
?
synthesizing module '%s'638*oasys2
	DATA_PISO2default:default2;
%C:/After 19-5-2020/spoc/data_piso.vhd2default:default2
662default:default8@Z8-638h px? 
?
%done synthesizing module '%s' (%s#%s)256*oasys2
	DATA_PISO2default:default2
32default:default2
12default:default2;
%C:/After 19-5-2020/spoc/data_piso.vhd2default:default2
662default:default8@Z8-256h px? 
?
%done synthesizing module '%s' (%s#%s)256*oasys2 
PreProcessor2default:default2
42default:default2
12default:default2>
(C:/After 19-5-2020/spoc/PreProcessor.vhd2default:default2
752default:default8@Z8-256h px? 
?
Hmodule '%s' declared at '%s:%s' bound to instance '%s' of component '%s'3392*oasys2

CryptoCore2default:default28
$C:/After 19-5-2020/spoc/CryptoCore.v2default:default2
22default:default2
Inst_Cipher2default:default2

CryptoCore2default:default25
C:/After 19-5-2020/spoc/LWC.vhd2default:default2
1692default:default8@Z8-3491h px? 
?
synthesizing module '%s'%s4497*oasys2

CryptoCore2default:default2
 2default:default2:
$C:/After 19-5-2020/spoc/CryptoCore.v2default:default2
22default:default8@Z8-6157h px? 
?
synthesizing module '%s'%s4497*oasys2
Datapath2default:default2
 2default:default28
"C:/After 19-5-2020/spoc/Datapath.v2default:default2
32default:default8@Z8-6157h px? 
[
%s
*synth2C
/	Parameter WIDTH bound to: 64 - type: integer 
2default:defaulth p
x
? 
X
%s
*synth2@
,	Parameter PW bound to: 32 - type: integer 
2default:defaulth p
x
? 
X
%s
*synth2@
,	Parameter SW bound to: 32 - type: integer 
2default:defaulth p
x
? 
a
%s
*synth2I
5	Parameter G_KEY_SIZE bound to: 128 - type: integer 
2default:defaulth p
x
? 
b
%s
*synth2J
6	Parameter G_NPUB_SIZE bound to: 128 - type: integer 
2default:defaulth p
x
? 
\
%s
*synth2D
0	Parameter MAXCTR bound to: 17 - type: integer 
2default:defaulth p
x
? 
R
%s
*synth2:
&	Parameter AD_TYPE bound to: 4'b0001 
2default:defaulth p
x
? 
?
%s
*synth2?
?	Parameter ZEROES112 bound to: 112'b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 
2default:defaulth p
x
? 
?
%s
*synth2?
?	Parameter ZEROES104 bound to: 104'b00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 
2default:defaulth p
x
? 
?
%s
*synth2?
?	Parameter ZEROES96 bound to: 96'b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 
2default:defaulth p
x
? 
?
%s
*synth2?
|	Parameter ZEROES88 bound to: 88'b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 
2default:defaulth p
x
? 
?
%s
*synth2?
t	Parameter ZEROES80 bound to: 80'b00000000000000000000000000000000000000000000000000000000000000000000000000000000 
2default:defaulth p
x
? 
?
%s
*synth2?
l	Parameter ZEROES72 bound to: 72'b000000000000000000000000000000000000000000000000000000000000000000000000 
2default:defaulth p
x
? 
?
%s
*synth2x
d	Parameter ZEROES64 bound to: 64'b0000000000000000000000000000000000000000000000000000000000000000 
2default:defaulth p
x
? 
?
%s
*synth2p
\	Parameter ZEROES56 bound to: 56'b00000000000000000000000000000000000000000000000000000000 
2default:defaulth p
x
? 
?
%s
*synth2h
T	Parameter ZEROES48 bound to: 48'b000000000000000000000000000000000000000000000000 
2default:defaulth p
x
? 
x
%s
*synth2`
L	Parameter ZEROES40 bound to: 40'b0000000000000000000000000000000000000000 
2default:defaulth p
x
? 
]
%s
*synth2E
1	Parameter ZEROES32 bound to: 0 - type: integer 
2default:defaulth p
x
? 
h
%s
*synth2P
<	Parameter ZEROES24 bound to: 24'b000000000000000000000000 
2default:defaulth p
x
? 
`
%s
*synth2H
4	Parameter ZEROES16 bound to: 16'b0000000000000000 
2default:defaulth p
x
? 
V
%s
*synth2>
*	Parameter ZEROES8 bound to: 8'b00000000 
2default:defaulth p
x
? 
W
%s
*synth2?
+	Parameter t bound to: 56 - type: integer 
2default:defaulth p
x
? 
O
%s
*synth27
#	Parameter INIT_ST bound to: 1'b0 
2default:defaulth p
x
? 
N
%s
*synth26
"	Parameter RUN_ST bound to: 1'b1 
2default:defaulth p
x
? 
?
synthesizing module '%s'%s4497*oasys2
SLiSCP_step2default:default2
 2default:default2;
%C:/After 19-5-2020/spoc/SliSCP_step.v2default:default2
22default:default8@Z8-6157h px? 
[
%s
*synth2C
/	Parameter WIDTH bound to: 64 - type: integer 
2default:defaulth p
x
? 
?
synthesizing module '%s'%s4497*oasys2
SB2default:default2
 2default:default22
C:/After 19-5-2020/spoc/SB.v2default:default2
32default:default8@Z8-6157h px? 
[
%s
*synth2C
/	Parameter WIDTH bound to: 64 - type: integer 
2default:defaulth p
x
? 
P
%s
*synth28
$	Parameter MAXCTR bound to: 3'b111 
2default:defaulth p
x
? 
?
synthesizing module '%s'%s4497*oasys2
d_ff2default:default2
 2default:default24
C:/After 19-5-2020/spoc/d_ff.v2default:default2
32default:default8@Z8-6157h px? 
Z
%s
*synth2B
.	Parameter WIDTH bound to: 3 - type: integer 
2default:defaulth p
x
? 
?
'done synthesizing module '%s'%s (%s#%s)4495*oasys2
d_ff2default:default2
 2default:default2
52default:default2
12default:default24
C:/After 19-5-2020/spoc/d_ff.v2default:default2
32default:default8@Z8-6155h px? 
?
synthesizing module '%s'%s4497*oasys2(
d_ff__parameterized02default:default2
 2default:default24
C:/After 19-5-2020/spoc/d_ff.v2default:default2
32default:default8@Z8-6157h px? 
[
%s
*synth2C
/	Parameter WIDTH bound to: 64 - type: integer 
2default:defaulth p
x
? 
?
'done synthesizing module '%s'%s (%s#%s)4495*oasys2(
d_ff__parameterized02default:default2
 2default:default2
52default:default2
12default:default24
C:/After 19-5-2020/spoc/d_ff.v2default:default2
32default:default8@Z8-6155h px? 
?
synthesizing module '%s'%s4497*oasys2(
d_ff__parameterized12default:default2
 2default:default24
C:/After 19-5-2020/spoc/d_ff.v2default:default2
32default:default8@Z8-6157h px? 
Z
%s
*synth2B
.	Parameter WIDTH bound to: 8 - type: integer 
2default:defaulth p
x
? 
?
'done synthesizing module '%s'%s (%s#%s)4495*oasys2(
d_ff__parameterized12default:default2
 2default:default2
52default:default2
12default:default24
C:/After 19-5-2020/spoc/d_ff.v2default:default2
32default:default8@Z8-6155h px? 
?
'done synthesizing module '%s'%s (%s#%s)4495*oasys2
SB2default:default2
 2default:default2
62default:default2
12default:default22
C:/After 19-5-2020/spoc/SB.v2default:default2
32default:default8@Z8-6155h px? 
?
Ginstance '%s' of module '%s' requires %s connections, but only %s given350*oasys2
S32default:default2
SB2default:default2
72default:default2
62default:default2;
%C:/After 19-5-2020/spoc/SliSCP_step.v2default:default2
472default:default8@Z8-350h px? 
?
'done synthesizing module '%s'%s (%s#%s)4495*oasys2
SLiSCP_step2default:default2
 2default:default2
72default:default2
12default:default2;
%C:/After 19-5-2020/spoc/SliSCP_step.v2default:default2
22default:default8@Z8-6155h px? 
?
synthesizing module '%s'%s4497*oasys2(
d_ff__parameterized22default:default2
 2default:default24
C:/After 19-5-2020/spoc/d_ff.v2default:default2
32default:default8@Z8-6157h px? 
Z
%s
*synth2B
.	Parameter WIDTH bound to: 5 - type: integer 
2default:defaulth p
x
? 
?
'done synthesizing module '%s'%s (%s#%s)4495*oasys2(
d_ff__parameterized22default:default2
 2default:default2
72default:default2
12default:default24
C:/After 19-5-2020/spoc/d_ff.v2default:default2
32default:default8@Z8-6155h px? 
?
default block is never used226*oasys28
"C:/After 19-5-2020/spoc/Datapath.v2default:default2
2592default:default8@Z8-226h px? 
?
synthesizing module '%s'%s4497*oasys2(
d_ff__parameterized32default:default2
 2default:default24
C:/After 19-5-2020/spoc/d_ff.v2default:default2
32default:default8@Z8-6157h px? 
\
%s
*synth2D
0	Parameter WIDTH bound to: 128 - type: integer 
2default:defaulth p
x
? 
?
'done synthesizing module '%s'%s (%s#%s)4495*oasys2(
d_ff__parameterized32default:default2
 2default:default2
72default:default2
12default:default24
C:/After 19-5-2020/spoc/d_ff.v2default:default2
32default:default8@Z8-6155h px? 
?
synthesizing module '%s'%s4497*oasys2(
d_ff__parameterized42default:default2
 2default:default24
C:/After 19-5-2020/spoc/d_ff.v2default:default2
32default:default8@Z8-6157h px? 
\
%s
*synth2D
0	Parameter WIDTH bound to: 256 - type: integer 
2default:defaulth p
x
? 
?
'done synthesizing module '%s'%s (%s#%s)4495*oasys2(
d_ff__parameterized42default:default2
 2default:default2
72default:default2
12default:default24
C:/After 19-5-2020/spoc/d_ff.v2default:default2
32default:default8@Z8-6155h px? 
?
'done synthesizing module '%s'%s (%s#%s)4495*oasys2
Datapath2default:default2
 2default:default2
82default:default2
12default:default28
"C:/After 19-5-2020/spoc/Datapath.v2default:default2
32default:default8@Z8-6155h px? 
?
synthesizing module '%s'%s4497*oasys2

Controller2default:default2
 2default:default2:
$C:/After 19-5-2020/spoc/Controller.v2default:default2
32default:default8@Z8-6157h px? 
S
%s
*synth2;
'	Parameter RESET_ST bound to: 4'b0000 
2default:defaulth p
x
? 
W
%s
*synth2?
+	Parameter CHECK_KEY_ST bound to: 4'b0001 
2default:defaulth p
x
? 
V
%s
*synth2>
*	Parameter LOAD_KEY_ST bound to: 4'b0010 
2default:defaulth p
x
? 
W
%s
*synth2?
+	Parameter LOAD_NPUB_ST bound to: 4'b0011 
2default:defaulth p
x
? 
R
%s
*synth2:
&	Parameter INIT_ST bound to: 4'b0100 
2default:defaulth p
x
? 
Y
%s
*synth2A
-	Parameter FINISH_INIT_ST bound to: 4'b0101 
2default:defaulth p
x
? 
T
%s
*synth2<
(	Parameter UPDATE_ST bound to: 4'b0110 
2default:defaulth p
x
? 
R
%s
*synth2:
&	Parameter PROC_ST bound to: 4'b0111 
2default:defaulth p
x
? 
X
%s
*synth2@
,	Parameter STORE_PROC_ST bound to: 4'b1000 
2default:defaulth p
x
? 
Y
%s
*synth2A
-	Parameter FINISH_PROC_ST bound to: 4'b1001 
2default:defaulth p
x
? 
X
%s
*synth2@
,	Parameter WRITE_PTCT_ST bound to: 4'b1010 
2default:defaulth p
x
? 
U
%s
*synth2=
)	Parameter PRE_TAG_ST bound to: 4'b1011 
2default:defaulth p
x
? 
Q
%s
*synth29
%	Parameter TAG_ST bound to: 4'b1100 
2default:defaulth p
x
? 
X
%s
*synth2@
,	Parameter LD_EXP_TAG_ST bound to: 4'b1101 
2default:defaulth p
x
? 
W
%s
*synth2?
+	Parameter STORE_TAG_ST bound to: 4'b1110 
2default:defaulth p
x
? 
X
%s
*synth2@
,	Parameter FINISH_TAG_ST bound to: 4'b1111 
2default:defaulth p
x
? 
R
%s
*synth2:
&	Parameter AD_TYPE bound to: 4'b0001 
2default:defaulth p
x
? 
S
%s
*synth2;
'	Parameter KEY_WORDS bound to: 3'b100 
2default:defaulth p
x
? 
T
%s
*synth2<
(	Parameter NPUB_WORDS bound to: 3'b100 
2default:defaulth p
x
? 
?
'done synthesizing module '%s'%s (%s#%s)4495*oasys2

Controller2default:default2
 2default:default2
92default:default2
12default:default2:
$C:/After 19-5-2020/spoc/Controller.v2default:default2
32default:default8@Z8-6155h px? 
?
Ginstance '%s' of module '%s' requires %s connections, but only %s given350*oasys2
	ctrl_inst2default:default2

Controller2default:default2
392default:default2
382default:default2:
$C:/After 19-5-2020/spoc/CryptoCore.v2default:default2
862default:default8@Z8-350h px? 
?
0Net %s in module/entity %s does not have driver.3422*oasys2
bdo_type2default:default2

CryptoCore2default:default2:
$C:/After 19-5-2020/spoc/CryptoCore.v2default:default2
412default:default8@Z8-3848h px? 
?
'done synthesizing module '%s'%s (%s#%s)4495*oasys2

CryptoCore2default:default2
 2default:default2
102default:default2
12default:default2:
$C:/After 19-5-2020/spoc/CryptoCore.v2default:default2
22default:default8@Z8-6155h px? 
?
synthesizing module '%s'638*oasys2!
PostProcessor2default:default2?
)C:/After 19-5-2020/spoc/PostProcessor.vhd2default:default2
712default:default8@Z8-638h px? 
?
synthesizing module '%s'638*oasys2
	DATA_SIPO2default:default2;
%C:/After 19-5-2020/spoc/data_sipo.vhd2default:default2
522default:default8@Z8-638h px? 
?
%done synthesizing module '%s' (%s#%s)256*oasys2
	DATA_SIPO2default:default2
112default:default2
12default:default2;
%C:/After 19-5-2020/spoc/data_sipo.vhd2default:default2
522default:default8@Z8-256h px? 
?
%done synthesizing module '%s' (%s#%s)256*oasys2!
PostProcessor2default:default2
122default:default2
12default:default2?
)C:/After 19-5-2020/spoc/PostProcessor.vhd2default:default2
712default:default8@Z8-256h px? 
?
synthesizing module '%s'638*oasys2
	fwft_fifo2default:default2;
%C:/After 19-5-2020/spoc/fwft_fifo.vhd2default:default2
432default:default8@Z8-638h px? 
Y
%s
*synth2A
-	Parameter G_W bound to: 32 - type: integer 
2default:defaulth p
x
? 
`
%s
*synth2H
4	Parameter G_LOG2DEPTH bound to: 2 - type: integer 
2default:defaulth p
x
? 
?
%done synthesizing module '%s' (%s#%s)256*oasys2
	fwft_fifo2default:default2
132default:default2
12default:default2;
%C:/After 19-5-2020/spoc/fwft_fifo.vhd2default:default2
432default:default8@Z8-256h px? 
?
%done synthesizing module '%s' (%s#%s)256*oasys2
LWC2default:default2
142default:default2
12default:default25
C:/After 19-5-2020/spoc/LWC.vhd2default:default2
512default:default8@Z8-256h px? 
{
!design %s has unconnected port %s3331*oasys2
	DATA_SIPO2default:default2
clk2default:defaultZ8-3331h px? 
{
!design %s has unconnected port %s3331*oasys2
	DATA_SIPO2default:default2
rst2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2
	DATA_SIPO2default:default2 
end_of_input2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
bdo_type[3]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
bdo_type[2]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
bdo_type[1]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
bdo_type[0]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
cmd[27]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
cmd[26]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
cmd[24]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
cmd[23]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
cmd[22]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
cmd[21]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
cmd[20]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
cmd[19]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
cmd[18]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
cmd[17]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2!
PostProcessor2default:default2
cmd[16]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

Controller2default:default2
bdi_partial2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2
Datapath2default:default2

init_state2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2
Datapath2default:default2
bdi_type[3]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2
Datapath2default:default2
bdi_type[2]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2
Datapath2default:default2
bdi_type[1]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2
Datapath2default:default2
bdi_type[0]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2
bdo_type[3]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2
bdo_type[2]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2
bdo_type[1]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2
bdo_type[0]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2
hash_in2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2&
bdi_valid_bytes[3]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2&
bdi_valid_bytes[2]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2&
bdi_valid_bytes[1]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2&
bdi_valid_bytes[0]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2"
bdi_pad_loc[3]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2"
bdi_pad_loc[2]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2"
bdi_pad_loc[1]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2

CryptoCore2default:default2"
bdi_pad_loc[0]2default:defaultZ8-3331h px? 
{
!design %s has unconnected port %s3331*oasys2
	DATA_PISO2default:default2
clk2default:defaultZ8-3331h px? 
{
!design %s has unconnected port %s3331*oasys2
	DATA_PISO2default:default2
rst2default:defaultZ8-3331h px? 
z
!design %s has unconnected port %s3331*oasys2
KEY_PISO2default:default2
clk2default:defaultZ8-3331h px? 
z
!design %s has unconnected port %s3331*oasys2
KEY_PISO2default:default2
rst2default:defaultZ8-3331h px? 
?
%s*synth2?
sFinished Synthesize : Time (s): cpu = 00:00:03 ; elapsed = 00:00:03 . Memory (MB): peak = 469.977 ; gain = 156.742
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
~Finished Constraint Validation : Time (s): cpu = 00:00:03 ; elapsed = 00:00:03 . Memory (MB): peak = 469.977 ; gain = 156.742
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
V
%s
*synth2>
*Start Loading Part and Timing Information
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
J
%s
*synth22
Loading part: xc7z020clg484-1
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
?Finished Loading Part and Timing Information : Time (s): cpu = 00:00:03 ; elapsed = 00:00:03 . Memory (MB): peak = 469.977 ; gain = 156.742
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
V
Loading part %s157*device2#
xc7z020clg484-12default:defaultZ21-403h px? 
?
3inferred FSM for state register '%s' in module '%s'802*oasys2*
FSM_32BIT.pr_state_reg2default:default2 
PreProcessor2default:defaultZ8-802h px? 
?
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2%
bdi_valid_bytes_p2default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_loc_p2default:defaultZ8-5546h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
sel_sdi_length2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2

key_update2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2$
nx_hash_internal2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
x
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2
nx_state2default:defaultZ8-5546h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
rnd_done2default:default2
32default:default2
52default:defaultZ8-5544h px? 
y
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2
	step_done2default:defaultZ8-5546h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
?
^ROM "%s" won't be mapped to RAM because address size (%s) is larger than maximum supported(%s)3997*oasys2
set_TR2default:default2
562default:default2
252default:defaultZ8-5545h px? 
?
3inferred FSM for state register '%s' in module '%s'802*oasys2!
fsm_state_reg2default:default2

Controller2default:defaultZ8-802h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2!
reset_bdo_ctr2default:default2
22default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
	en_ld_ctr2default:default2
22default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
en_decrypt_reg2default:default2
22default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2!
reset_bdi_ctr2default:default2
22default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2

en_bdi_ctr2default:default2
22default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2

en_bdo_ctr2default:default2
22default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2 
bdi_type_reg2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
reset_eoi_flag2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
lock_tag_state2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
	init_lock2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
start2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
22default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
22default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
22default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
22default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
next_fsm_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
3inferred FSM for state register '%s' in module '%s'802*oasys2*
FSM_32BIT.pr_state_reg2default:default2!
PostProcessor2default:defaultZ8-802h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_eot2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
do_last2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2"
msg_auth_ready2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
42default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
nx_state2default:default2
12default:default2
52default:defaultZ8-5544h px? 
?
%s
*synth2x
d---------------------------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s
*synth2t
`                   State |                     New Encoding |                Previous Encoding 
2default:defaulth p
x
? 
?
%s
*synth2x
d---------------------------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s
*synth2s
_              s_int_mode |                  000000000000001 |                             0000
2default:defaulth p
x
? 
?
%s
*synth2s
_               s_int_key |                  000000000000010 |                             0001
2default:defaulth p
x
? 
?
%s
*synth2s
_               s_hdr_key |                  000000000000100 |                             0010
2default:defaulth p
x
? 
?
%s
*synth2s
_                s_ld_key |                  000000000001000 |                             0011
2default:defaulth p
x
? 
?
%s
*synth2s
_              s_hdr_npub |                  000000000010000 |                             0100
2default:defaulth p
x
? 
?
%s
*synth2s
_               s_ld_npub |                  000000000100000 |                             0101
2default:defaulth p
x
? 
?
%s
*synth2s
_                s_hdr_ad |                  000000001000000 |                             0110
2default:defaulth p
x
? 
?
%s
*synth2s
_                 s_ld_ad |                  000000010000000 |                             0111
2default:defaulth p
x
? 
?
%s
*synth2s
_               s_hdr_msg |                  000000100000000 |                             1000
2default:defaulth p
x
? 
?
%s
*synth2s
_                s_ld_msg |                  000001000000000 |                             1001
2default:defaulth p
x
? 
?
%s
*synth2s
_               s_hdr_tag |                  000010000000000 |                             1010
2default:defaulth p
x
? 
?
%s
*synth2s
_                s_ld_tag |                  000100000000000 |                             1011
2default:defaulth p
x
? 
?
%s
*synth2s
_              s_hdr_hash |                  001000000000000 |                             1100
2default:defaulth p
x
? 
?
%s
*synth2s
_            s_empty_hash |                  010000000000000 |                             1110
2default:defaulth p
x
? 
?
%s
*synth2s
_               s_ld_hash |                  100000000000000 |                             1101
2default:defaulth p
x
? 
?
%s
*synth2x
d---------------------------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
Gencoded FSM with state register '%s' using encoding '%s' in module '%s'3353*oasys2*
FSM_32BIT.pr_state_reg2default:default2
one-hot2default:default2 
PreProcessor2default:defaultZ8-3354h px? 
?
%s
*synth2x
d---------------------------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s
*synth2t
`                   State |                     New Encoding |                Previous Encoding 
2default:defaulth p
x
? 
?
%s
*synth2x
d---------------------------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s
*synth2s
_                RESET_ST |                  000000000000001 |                             0000
2default:defaulth p
x
? 
?
%s
*synth2s
_            CHECK_KEY_ST |                  000000000000010 |                             0001
2default:defaulth p
x
? 
?
%s
*synth2s
_             LOAD_KEY_ST |                  000000000000100 |                             0010
2default:defaulth p
x
? 
?
%s
*synth2s
_            LOAD_NPUB_ST |                  000000000001000 |                             0011
2default:defaulth p
x
? 
?
%s
*synth2s
_                 INIT_ST |                  000000000010000 |                             0100
2default:defaulth p
x
? 
?
%s
*synth2s
_               UPDATE_ST |                  000000000100000 |                             0110
2default:defaulth p
x
? 
?
%s
*synth2s
_                 PROC_ST |                  000000001000000 |                             0111
2default:defaulth p
x
? 
?
%s
*synth2s
_           STORE_PROC_ST |                  000000010000000 |                             1000
2default:defaulth p
x
? 
?
%s
*synth2s
_          FINISH_PROC_ST |                  000000100000000 |                             1001
2default:defaulth p
x
? 
?
%s
*synth2s
_           WRITE_PTCT_ST |                  000001000000000 |                             1010
2default:defaulth p
x
? 
?
%s
*synth2s
_              PRE_TAG_ST |                  000010000000000 |                             1011
2default:defaulth p
x
? 
?
%s
*synth2s
_                  TAG_ST |                  000100000000000 |                             1100
2default:defaulth p
x
? 
?
%s
*synth2s
_           LD_EXP_TAG_ST |                  001000000000000 |                             1101
2default:defaulth p
x
? 
?
%s
*synth2s
_            STORE_TAG_ST |                  010000000000000 |                             1110
2default:defaulth p
x
? 
?
%s
*synth2s
_           FINISH_TAG_ST |                  100000000000000 |                             1111
2default:defaulth p
x
? 
?
%s
*synth2x
d---------------------------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
Gencoded FSM with state register '%s' using encoding '%s' in module '%s'3353*oasys2!
fsm_state_reg2default:default2
one-hot2default:default2

Controller2default:defaultZ8-3354h px? 
?
%s
*synth2x
d---------------------------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s
*synth2t
`                   State |                     New Encoding |                Previous Encoding 
2default:defaulth p
x
? 
?
%s
*synth2x
d---------------------------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s
*synth2s
_                  s_init |                       0000000001 |                             0000
2default:defaulth p
x
? 
?
%s
*synth2s
_        s_hdr_hash_value |                       0000000010 |                             0001
2default:defaulth p
x
? 
?
%s
*synth2s
_        s_out_hash_value |                       0000000100 |                             0010
2default:defaulth p
x
? 
?
%s
*synth2s
_               s_hdr_msg |                       0000001000 |                             0011
2default:defaulth p
x
? 
?
%s
*synth2s
_               s_out_msg |                       0000010000 |                             0100
2default:defaulth p
x
? 
?
%s
*synth2s
_               s_ver_tag |                       0000100000 |                             0111
2default:defaulth p
x
? 
?
%s
*synth2s
_           s_status_fail |                       0001000000 |                             1000
2default:defaulth p
x
? 
?
%s
*synth2s
_               s_hdr_tag |                       0010000000 |                             0101
2default:defaulth p
x
? 
?
%s
*synth2s
_               s_out_tag |                       0100000000 |                             0110
2default:defaulth p
x
? 
?
%s
*synth2s
_        s_status_success |                       1000000000 |                             1001
2default:defaulth p
x
? 
?
%s
*synth2x
d---------------------------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
Gencoded FSM with state register '%s' using encoding '%s' in module '%s'3353*oasys2*
FSM_32BIT.pr_state_reg2default:default2
one-hot2default:default2!
PostProcessor2default:defaultZ8-3354h px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
?Finished RTL Optimization Phase 2 : Time (s): cpu = 00:00:05 ; elapsed = 00:00:05 . Memory (MB): peak = 504.965 ; gain = 191.730
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
E
%s
*synth2-

Report RTL Partitions: 
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
W
%s
*synth2?
+| |RTL Partition |Replication |Instances |
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
L
%s
*synth24
 Start RTL Component Statistics 
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
:
%s
*synth2"
+---Adders : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      5 Bit       Adders := 4     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      3 Bit       Adders := 3     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      2 Bit       Adders := 5     
2default:defaulth p
x
? 
8
%s
*synth2 
+---XORs : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   3 Input     64 Bit         XORs := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input     64 Bit         XORs := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   4 Input     32 Bit         XORs := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input     32 Bit         XORs := 4     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      4 Bit         XORs := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      1 Bit         XORs := 1     
2default:defaulth p
x
? 
=
%s
*synth2%
+---Registers : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	              256 Bit    Registers := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	              128 Bit    Registers := 4     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	               64 Bit    Registers := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                8 Bit    Registers := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                5 Bit    Registers := 4     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                3 Bit    Registers := 3     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                2 Bit    Registers := 3     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                1 Bit    Registers := 13    
2default:defaulth p
x
? 
8
%s
*synth2 
+---RAMs : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	              128 Bit         RAMs := 1     
2default:defaulth p
x
? 
9
%s
*synth2!
+---Muxes : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input    256 Bit        Muxes := 3     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input    128 Bit        Muxes := 18    
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   4 Input    128 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input     32 Bit        Muxes := 22    
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  10 Input     32 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input     16 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  43 Input     15 Bit        Muxes := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  28 Input     10 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      8 Bit        Muxes := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      5 Bit        Muxes := 3     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  15 Input      4 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      4 Bit        Muxes := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   4 Input      4 Bit        Muxes := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      3 Bit        Muxes := 3     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      2 Bit        Muxes := 7     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   4 Input      2 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  15 Input      2 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      1 Bit        Muxes := 29    
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  15 Input      1 Bit        Muxes := 33    
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  10 Input      1 Bit        Muxes := 8     
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
O
%s
*synth27
#Finished RTL Component Statistics 
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
Y
%s
*synth2A
-Start RTL Hierarchical Component Statistics 
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
O
%s
*synth27
#Hierarchical RTL Component report 
2default:defaulth p
x
? 
D
%s
*synth2,
Module StepDownCountLd 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
9
%s
*synth2!
+---Muxes : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      1 Bit        Muxes := 1     
2default:defaulth p
x
? 
A
%s
*synth2)
Module PreProcessor 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
=
%s
*synth2%
+---Registers : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                1 Bit    Registers := 4     
2default:defaulth p
x
? 
9
%s
*synth2!
+---Muxes : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input     16 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  43 Input     15 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  15 Input      4 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      4 Bit        Muxes := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   4 Input      4 Bit        Muxes := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      3 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      1 Bit        Muxes := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  15 Input      1 Bit        Muxes := 9     
2default:defaulth p
x
? 
9
%s
*synth2!
Module d_ff 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
=
%s
*synth2%
+---Registers : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                3 Bit    Registers := 1     
2default:defaulth p
x
? 
I
%s
*synth21
Module d_ff__parameterized0 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
=
%s
*synth2%
+---Registers : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	               64 Bit    Registers := 1     
2default:defaulth p
x
? 
I
%s
*synth21
Module d_ff__parameterized1 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
=
%s
*synth2%
+---Registers : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                8 Bit    Registers := 1     
2default:defaulth p
x
? 
7
%s
*synth2
Module SB 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
:
%s
*synth2"
+---Adders : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      3 Bit       Adders := 1     
2default:defaulth p
x
? 
8
%s
*synth2 
+---XORs : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   4 Input     32 Bit         XORs := 1     
2default:defaulth p
x
? 
9
%s
*synth2!
+---Muxes : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input     32 Bit        Muxes := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      8 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      3 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      2 Bit        Muxes := 1     
2default:defaulth p
x
? 
@
%s
*synth2(
Module SLiSCP_step 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
8
%s
*synth2 
+---XORs : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   3 Input     64 Bit         XORs := 2     
2default:defaulth p
x
? 
I
%s
*synth21
Module d_ff__parameterized2 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
=
%s
*synth2%
+---Registers : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                5 Bit    Registers := 1     
2default:defaulth p
x
? 
I
%s
*synth21
Module d_ff__parameterized3 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
=
%s
*synth2%
+---Registers : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	              128 Bit    Registers := 1     
2default:defaulth p
x
? 
I
%s
*synth21
Module d_ff__parameterized4 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
=
%s
*synth2%
+---Registers : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	              256 Bit    Registers := 1     
2default:defaulth p
x
? 
=
%s
*synth2%
Module Datapath 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
:
%s
*synth2"
+---Adders : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      5 Bit       Adders := 3     
2default:defaulth p
x
? 
8
%s
*synth2 
+---XORs : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input     64 Bit         XORs := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input     32 Bit         XORs := 4     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      4 Bit         XORs := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      1 Bit         XORs := 1     
2default:defaulth p
x
? 
=
%s
*synth2%
+---Registers : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	              128 Bit    Registers := 3     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                5 Bit    Registers := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                1 Bit    Registers := 2     
2default:defaulth p
x
? 
9
%s
*synth2!
+---Muxes : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input    256 Bit        Muxes := 3     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input    128 Bit        Muxes := 18    
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   4 Input    128 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input     32 Bit        Muxes := 16    
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      5 Bit        Muxes := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      2 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      1 Bit        Muxes := 8     
2default:defaulth p
x
? 
?
%s
*synth2'
Module Controller 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
:
%s
*synth2"
+---Adders : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      5 Bit       Adders := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      2 Bit       Adders := 3     
2default:defaulth p
x
? 
=
%s
*synth2%
+---Registers : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                2 Bit    Registers := 3     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                1 Bit    Registers := 5     
2default:defaulth p
x
? 
9
%s
*synth2!
+---Muxes : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  43 Input     15 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      5 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      2 Bit        Muxes := 3     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   4 Input      2 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  15 Input      2 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      1 Bit        Muxes := 14    
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  15 Input      1 Bit        Muxes := 24    
2default:defaulth p
x
? 
B
%s
*synth2*
Module PostProcessor 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
=
%s
*synth2%
+---Registers : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                1 Bit    Registers := 2     
2default:defaulth p
x
? 
9
%s
*synth2!
+---Muxes : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input     32 Bit        Muxes := 2     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  10 Input     32 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  28 Input     10 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	  10 Input      1 Bit        Muxes := 8     
2default:defaulth p
x
? 
>
%s
*synth2&
Module fwft_fifo 
2default:defaulth p
x
? 
K
%s
*synth23
Detailed RTL Component Info : 
2default:defaulth p
x
? 
:
%s
*synth2"
+---Adders : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      3 Bit       Adders := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      2 Bit       Adders := 2     
2default:defaulth p
x
? 
=
%s
*synth2%
+---Registers : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	                3 Bit    Registers := 1     
2default:defaulth p
x
? 
8
%s
*synth2 
+---RAMs : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	              128 Bit         RAMs := 1     
2default:defaulth p
x
? 
9
%s
*synth2!
+---Muxes : 
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      2 Bit        Muxes := 1     
2default:defaulth p
x
? 
Z
%s
*synth2B
.	   2 Input      1 Bit        Muxes := 3     
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
[
%s
*synth2C
/Finished RTL Hierarchical Component Statistics
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
H
%s
*synth20
Start Part Resource Summary
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s
*synth2k
WPart Resources:
DSPs: 220 (col length:60)
BRAMs: 280 (col length: RAMB18 60 RAMB36 30)
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
K
%s
*synth23
Finished Part Resource Summary
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
W
%s
*synth2?
+Start Cross Boundary and Area Optimization
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
]
%s
*synth2E
1Warning: Parallel synthesis criteria is not met 
2default:defaulth p
x
? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
?
[ROM "%s" won't be mapped to Block RAM because address size (%s) smaller than threshold (%s)3996*oasys2
bdo12default:default2
32default:default2
52default:defaultZ8-5544h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
}
8ROM "%s" won't be mapped to RAM because it is too sparse3998*oasys2!
bdi_pad_half12default:defaultZ8-5546h px? 
?
+Unused sequential element %s was removed. 
4326*oasys27
#Inst_PreProcessor/hash_internal_reg2default:default2>
(C:/After 19-5-2020/spoc/PreProcessor.vhd2default:default2
1792default:default8@Z8-6014h px? 
?
!design %s has unconnected port %s3331*oasys2
Datapath2default:default2

init_state2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2
Datapath2default:default2
bdi_type[3]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2
Datapath2default:default2
bdi_type[2]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2
Datapath2default:default2
bdi_type[1]2default:defaultZ8-3331h px? 
?
!design %s has unconnected port %s3331*oasys2
Datapath2default:default2
bdi_type[0]2default:defaultZ8-3331h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2J
6Inst_Cipher/data_path_inst/step_func/S3/rc_rg/q_reg[7]2default:default2
FDRE2default:default2J
6Inst_Cipher/data_path_inst/step_func/S1/rc_rg/q_reg[7]2default:defaultZ8-3886h px? 
?
6propagating constant %s across sequential element (%s)3333*oasys2
02default:default2N
:\Inst_Cipher/data_path_inst /step_func/\S1/rc_rg/q_reg[7] 2default:defaultZ8-3333h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[0]2default:default2
FDSE2default:default2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[1]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[1]2default:default2
FDSE2default:default2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[2]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[2]2default:default2
FDSE2default:default2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[3]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[3]2default:default2
FDSE2default:default2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[4]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[4]2default:default2
FDSE2default:default2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[5]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[5]2default:default2
FDSE2default:default2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[6]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[6]2default:default2
FDSE2default:default2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[7]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[8]2default:default2
FDSE2default:default2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[9]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2@
,Inst_Cipher/data_path_inst/trunc_mask_reg[9]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[10]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[10]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[11]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[11]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[12]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[12]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[13]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[13]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[14]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[14]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[15]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[16]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[17]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[17]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[18]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[18]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[19]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[19]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[20]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[20]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[21]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[21]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[22]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[22]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[23]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[24]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[25]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[25]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[26]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[26]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[27]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[27]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[28]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[28]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[29]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[29]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[30]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[30]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[31]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[32]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[33]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[33]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[34]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[34]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[35]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[35]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[36]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[36]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[37]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[37]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[38]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[38]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[39]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[40]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[41]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[41]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[42]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[42]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[43]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[43]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[44]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[44]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[45]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[45]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[46]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[46]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[47]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[48]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[49]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[49]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[50]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[50]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[51]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[51]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[52]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[52]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[53]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[53]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[54]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[54]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[55]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[56]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[57]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[57]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[58]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[58]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[59]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[59]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[60]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[60]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[61]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[61]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[62]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[62]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[63]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[64]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[65]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[65]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[66]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[66]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[67]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[67]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[68]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[68]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[69]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[69]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[70]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[70]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[71]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[72]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[73]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[73]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[74]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[74]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[75]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[75]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[76]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[76]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[77]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[77]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[78]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[78]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[79]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[80]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[81]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[81]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[82]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[82]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[83]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[83]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[84]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[84]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[85]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[85]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[86]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[86]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[87]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[88]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[89]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[89]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[90]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[90]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[91]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[91]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[92]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[92]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[93]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[93]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[94]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[94]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[95]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[96]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[97]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[97]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[98]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[98]2default:default2
FDSE2default:default2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[99]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2A
-Inst_Cipher/data_path_inst/trunc_mask_reg[99]2default:default2
FDSE2default:default2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[100]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[100]2default:default2
FDSE2default:default2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[101]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[101]2default:default2
FDSE2default:default2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[102]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[102]2default:default2
FDSE2default:default2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[103]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[104]2default:default2
FDSE2default:default2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[105]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[105]2default:default2
FDSE2default:default2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[106]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[106]2default:default2
FDSE2default:default2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[107]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[107]2default:default2
FDSE2default:default2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[108]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[108]2default:default2
FDSE2default:default2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[109]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[109]2default:default2
FDSE2default:default2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[110]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[110]2default:default2
FDSE2default:default2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[111]2default:defaultZ8-3886h px? 
?
"merging instance '%s' (%s) to '%s'3436*oasys2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[112]2default:default2
FDSE2default:default2B
.Inst_Cipher/data_path_inst/trunc_mask_reg[113]2default:defaultZ8-3886h px? 
?
?Message '%s' appears more than %s times and has been disabled. User can change this message limit to see more message instances.
14*common2 
Synth 8-38862default:default2
1002default:defaultZ17-14h px? 
?
ESequential element (%s) is unused and will be removed from module %s.3332*oasys2%
S1/rc_rg/q_reg[7]2default:default2
SLiSCP_step2default:defaultZ8-3332h px? 
?
ESequential element (%s) is unused and will be removed from module %s.3332*oasys2

set_TR_reg2default:default2
Datapath2default:defaultZ8-3332h px? 
?
+multi-driven net %s with %s driver pin '%s'3351*oasys2
Q2default:default2
1st2default:default2;
'Inst_Cipher/data_path_inst/set_TR_reg/Q2default:default28
"C:/After 19-5-2020/spoc/Datapath.v2default:default2
3572default:default8@Z8-3352h px? 
?
+multi-driven net %s with %s driver pin '%s'3351*oasys2
Q2default:default2
2nd2default:default2
VCC2default:default28
"C:/After 19-5-2020/spoc/Datapath.v2default:default2
3572default:default8@Z8-3352h px? 
?
Lmulti-driven net %s is connected to constant driver, other driver is ignored4012*oasys2
Q2default:default28
"C:/After 19-5-2020/spoc/Datapath.v2default:default2
3572default:default8@Z8-5559h px? 
?
ESequential element (%s) is unused and will be removed from module %s.3332*oasys2!
set_TR_reg__02default:default2
Datapath2default:defaultZ8-3332h px? 
?
ESequential element (%s) is unused and will be removed from module %s.3332*oasys2>
*Inst_Cipher/ctrl_inst/cum_size_rg/q_reg[4]2default:default2
LWC2default:defaultZ8-3332h px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
?Finished Cross Boundary and Area Optimization : Time (s): cpu = 00:00:14 ; elapsed = 00:00:14 . Memory (MB): peak = 707.520 ; gain = 394.285
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
?---------------------------------------------------------------------------------
Start ROM, RAM, DSP and Shift Register Reporting
2default:defaulth px? 
~
%s*synth2f
R---------------------------------------------------------------------------------
2default:defaulth px? 
2
%s*synth2

ROM:
2default:defaulth px? 
i
%s*synth2Q
=+------------+------------+---------------+----------------+
2default:defaulth px? 
j
%s*synth2R
>|Module Name | RTL Object | Depth x Width | Implemented As | 
2default:defaulth px? 
i
%s*synth2Q
=+------------+------------+---------------+----------------+
2default:defaulth px? 
j
%s*synth2R
>|Datapath    | rc1        | 32x8          | LUT            | 
2default:defaulth px? 
j
%s*synth2R
>|Datapath    | rc0        | 32x8          | LUT            | 
2default:defaulth px? 
j
%s*synth2R
>|Datapath    | sc1        | 32x8          | LUT            | 
2default:defaulth px? 
j
%s*synth2R
>|Datapath    | sc0        | 32x8          | LUT            | 
2default:defaulth px? 
j
%s*synth2R
>|Datapath    | rc1        | 32x8          | LUT            | 
2default:defaulth px? 
j
%s*synth2R
>|Datapath    | sc1        | 32x8          | LUT            | 
2default:defaulth px? 
j
%s*synth2R
>|Datapath    | sc0        | 32x8          | LUT            | 
2default:defaulth px? 
j
%s*synth2R
>+------------+------------+---------------+----------------+

2default:defaulth px? 
k
%s*synth2S
?
Distributed RAM: Preliminary Mapping  Report (see note below)
2default:defaulth px? 
?
%s*synth2r
^+------------+----------------------------+-----------+----------------------+--------------+
2default:defaulth px? 
?
%s*synth2s
_|Module Name | RTL Object                 | Inference | Size (Depth x Width) | Primitives   | 
2default:defaulth px? 
?
%s*synth2r
^+------------+----------------------------+-----------+----------------------+--------------+
2default:defaulth px? 
?
%s*synth2s
_|LWC         | Inst_Header_Fifo/mem_s_reg | Implied   | 4 x 32               | RAM32M x 6   | 
2default:defaulth px? 
?
%s*synth2s
_+------------+----------------------------+-----------+----------------------+--------------+

2default:defaulth px? 
?
%s*synth2?
?Note: The table above is a preliminary report that shows the Distributed RAMs at the current stage of the synthesis flow. Some Distributed RAMs may be reimplemented as non Distributed RAM primitives later in the synthesis flow. Multiple instantiated RAMs are reported only once.
2default:defaulth px? 
?
%s*synth2?
?---------------------------------------------------------------------------------
Finished ROM, RAM, DSP and Shift Register Reporting
2default:defaulth px? 
~
%s*synth2f
R---------------------------------------------------------------------------------
2default:defaulth px? 
E
%s
*synth2-

Report RTL Partitions: 
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
W
%s
*synth2?
+| |RTL Partition |Replication |Instances |
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
F
%s
*synth2.
Start Timing Optimization
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
|Finished Timing Optimization : Time (s): cpu = 00:00:15 ; elapsed = 00:00:15 . Memory (MB): peak = 707.520 ; gain = 394.285
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s
*synth2?
?---------------------------------------------------------------------------------
Start ROM, RAM, DSP and Shift Register Reporting
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
T
%s
*synth2<
(
Distributed RAM: Final Mapping  Report
2default:defaulth p
x
? 
?
%s
*synth2r
^+------------+----------------------------+-----------+----------------------+--------------+
2default:defaulth p
x
? 
?
%s
*synth2s
_|Module Name | RTL Object                 | Inference | Size (Depth x Width) | Primitives   | 
2default:defaulth p
x
? 
?
%s
*synth2r
^+------------+----------------------------+-----------+----------------------+--------------+
2default:defaulth p
x
? 
?
%s
*synth2s
_|LWC         | Inst_Header_Fifo/mem_s_reg | Implied   | 4 x 32               | RAM32M x 6   | 
2default:defaulth p
x
? 
?
%s
*synth2s
_+------------+----------------------------+-----------+----------------------+--------------+

2default:defaulth p
x
? 
?
%s
*synth2?
?---------------------------------------------------------------------------------
Finished ROM, RAM, DSP and Shift Register Reporting
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
E
%s
*synth2-

Report RTL Partitions: 
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
W
%s
*synth2?
+| |RTL Partition |Replication |Instances |
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
E
%s
*synth2-
Start Technology Mapping
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
{Finished Technology Mapping : Time (s): cpu = 00:00:15 ; elapsed = 00:00:16 . Memory (MB): peak = 707.520 ; gain = 394.285
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
E
%s
*synth2-

Report RTL Partitions: 
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
W
%s
*synth2?
+| |RTL Partition |Replication |Instances |
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s
*synth2'
Start IO Insertion
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
Q
%s
*synth29
%Start Flattening Before IO Insertion
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
T
%s
*synth2<
(Finished Flattening Before IO Insertion
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
H
%s
*synth20
Start Final Netlist Cleanup
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
K
%s
*synth23
Finished Final Netlist Cleanup
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
uFinished IO Insertion : Time (s): cpu = 00:00:16 ; elapsed = 00:00:17 . Memory (MB): peak = 707.520 ; gain = 394.285
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
+multi-driven net %s with %s driver pin '%s'3351*oasys27
#Inst_Cipher/data_path_inst/reset_TR2default:default2
1st2default:default2@
,Inst_Cipher/data_path_inst/reset_TR_reg__0/Q2default:default28
"C:/After 19-5-2020/spoc/Datapath.v2default:default2
3332default:default8@Z8-3352h px? 
?
+multi-driven net %s with %s driver pin '%s'3351*oasys27
#Inst_Cipher/data_path_inst/reset_TR2default:default2
2nd2default:default2=
)Inst_Cipher/data_path_inst/reset_TR_reg/Q2default:default28
"C:/After 19-5-2020/spoc/Datapath.v2default:default2
3372default:default8@Z8-3352h px? 
D
%s
*synth2,

Report Check Netlist: 
2default:defaulth p
x
? 
u
%s
*synth2]
I+------+------------------+-------+---------+-------+------------------+
2default:defaulth p
x
? 
u
%s
*synth2]
I|      |Item              |Errors |Warnings |Status |Description       |
2default:defaulth p
x
? 
u
%s
*synth2]
I+------+------------------+-------+---------+-------+------------------+
2default:defaulth p
x
? 
u
%s
*synth2]
I|1     |multi_driven_nets |      0|        1|Failed |Multi driven nets |
2default:defaulth p
x
? 
u
%s
*synth2]
I+------+------------------+-------+---------+-------+------------------+
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
O
%s
*synth27
#Start Renaming Generated Instances
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
?Finished Renaming Generated Instances : Time (s): cpu = 00:00:16 ; elapsed = 00:00:17 . Memory (MB): peak = 707.520 ; gain = 394.285
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
E
%s
*synth2-

Report RTL Partitions: 
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
W
%s
*synth2?
+| |RTL Partition |Replication |Instances |
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
W
%s
*synth2?
++-+--------------+------------+----------+
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
L
%s
*synth24
 Start Rebuilding User Hierarchy
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
?Finished Rebuilding User Hierarchy : Time (s): cpu = 00:00:17 ; elapsed = 00:00:17 . Memory (MB): peak = 707.520 ; gain = 394.285
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
K
%s
*synth23
Start Renaming Generated Ports
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
?Finished Renaming Generated Ports : Time (s): cpu = 00:00:17 ; elapsed = 00:00:17 . Memory (MB): peak = 707.520 ; gain = 394.285
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
M
%s
*synth25
!Start Handling Custom Attributes
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
?Finished Handling Custom Attributes : Time (s): cpu = 00:00:17 ; elapsed = 00:00:17 . Memory (MB): peak = 707.520 ; gain = 394.285
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
J
%s
*synth22
Start Renaming Generated Nets
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
?Finished Renaming Generated Nets : Time (s): cpu = 00:00:17 ; elapsed = 00:00:17 . Memory (MB): peak = 707.520 ; gain = 394.285
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
K
%s
*synth23
Start Writing Synthesis Report
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
A
%s
*synth2)

Report BlackBoxes: 
2default:defaulth p
x
? 
J
%s
*synth22
+-+--------------+----------+
2default:defaulth p
x
? 
J
%s
*synth22
| |BlackBox name |Instances |
2default:defaulth p
x
? 
J
%s
*synth22
+-+--------------+----------+
2default:defaulth p
x
? 
J
%s
*synth22
+-+--------------+----------+
2default:defaulth p
x
? 
A
%s*synth2)

Report Cell Usage: 
2default:defaulth px? 
D
%s*synth2,
+------+-------+------+
2default:defaulth px? 
D
%s*synth2,
|      |Cell   |Count |
2default:defaulth px? 
D
%s*synth2,
+------+-------+------+
2default:defaulth px? 
D
%s*synth2,
|1     |BUFG   |     3|
2default:defaulth px? 
D
%s*synth2,
|2     |CARRY4 |    24|
2default:defaulth px? 
D
%s*synth2,
|3     |LUT1   |     9|
2default:defaulth px? 
D
%s*synth2,
|4     |LUT2   |   430|
2default:defaulth px? 
D
%s*synth2,
|5     |LUT3   |   351|
2default:defaulth px? 
D
%s*synth2,
|6     |LUT4   |   273|
2default:defaulth px? 
D
%s*synth2,
|7     |LUT5   |   697|
2default:defaulth px? 
D
%s*synth2,
|8     |LUT6   |  1385|
2default:defaulth px? 
D
%s*synth2,
|9     |RAM32M |     5|
2default:defaulth px? 
D
%s*synth2,
|10    |FDRE   |   902|
2default:defaulth px? 
D
%s*synth2,
|11    |FDSE   |    20|
2default:defaulth px? 
D
%s*synth2,
|12    |IBUF   |    69|
2default:defaulth px? 
D
%s*synth2,
|13    |OBUF   |    36|
2default:defaulth px? 
D
%s*synth2,
+------+-------+------+
2default:defaulth px? 
E
%s
*synth2-

Report Instance Areas: 
2default:defaulth p
x
? 
k
%s
*synth2S
?+------+----------------------+-----------------------+------+
2default:defaulth p
x
? 
k
%s
*synth2S
?|      |Instance              |Module                 |Cells |
2default:defaulth p
x
? 
k
%s
*synth2S
?+------+----------------------+-----------------------+------+
2default:defaulth p
x
? 
k
%s
*synth2S
?|1     |top                   |                       |  4204|
2default:defaulth p
x
? 
k
%s
*synth2S
?|2     |  Inst_Cipher         |CryptoCore             |  3792|
2default:defaulth p
x
? 
k
%s
*synth2S
?|3     |    ctrl_inst         |Controller             |   340|
2default:defaulth p
x
? 
k
%s
*synth2S
?|4     |      cum_size_rg     |d_ff__parameterized2_6 |    10|
2default:defaulth p
x
? 
k
%s
*synth2S
?|5     |    data_path_inst    |Datapath               |  3452|
2default:defaulth p
x
? 
k
%s
*synth2S
?|6     |      bdi_rg          |d_ff__parameterized3   |   184|
2default:defaulth p
x
? 
k
%s
*synth2S
?|7     |      cum_size_rg     |d_ff__parameterized2   |   945|
2default:defaulth p
x
? 
k
%s
*synth2S
?|8     |      state_reg       |d_ff__parameterized4   |  1474|
2default:defaulth p
x
? 
k
%s
*synth2S
?|9     |      step_ctr_reg    |d_ff__parameterized2_1 |    43|
2default:defaulth p
x
? 
k
%s
*synth2S
?|10    |      step_func       |SLiSCP_step            |   519|
2default:defaulth p
x
? 
k
%s
*synth2S
?|11    |        S1            |SB                     |   289|
2default:defaulth p
x
? 
k
%s
*synth2S
?|12    |          rc_rg       |d_ff__parameterized1_3 |     7|
2default:defaulth p
x
? 
k
%s
*synth2S
?|13    |          rnd_ctr_reg |d_ff_4                 |   218|
2default:defaulth p
x
? 
k
%s
*synth2S
?|14    |          status_reg  |d_ff__parameterized0_5 |    64|
2default:defaulth p
x
? 
k
%s
*synth2S
?|15    |        S3            |SB_2                   |   230|
2default:defaulth p
x
? 
k
%s
*synth2S
?|16    |          rc_rg       |d_ff__parameterized1   |     7|
2default:defaulth p
x
? 
k
%s
*synth2S
?|17    |          rnd_ctr_reg |d_ff                   |   159|
2default:defaulth p
x
? 
k
%s
*synth2S
?|18    |          status_reg  |d_ff__parameterized0   |    64|
2default:defaulth p
x
? 
k
%s
*synth2S
?|19    |  Inst_Header_Fifo    |fwft_fifo              |    62|
2default:defaulth p
x
? 
k
%s
*synth2S
?|20    |  Inst_PostProcessor  |PostProcessor          |   104|
2default:defaulth p
x
? 
k
%s
*synth2S
?|21    |    SegLen            |StepDownCountLd_0      |    31|
2default:defaulth p
x
? 
k
%s
*synth2S
?|22    |  Inst_PreProcessor   |PreProcessor           |   138|
2default:defaulth p
x
? 
k
%s
*synth2S
?|23    |    SegLen            |StepDownCountLd        |    66|
2default:defaulth p
x
? 
k
%s
*synth2S
?+------+----------------------+-----------------------+------+
2default:defaulth p
x
? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
?
%s*synth2?
?Finished Writing Synthesis Report : Time (s): cpu = 00:00:17 ; elapsed = 00:00:17 . Memory (MB): peak = 707.520 ; gain = 394.285
2default:defaulth px? 
~
%s
*synth2f
R---------------------------------------------------------------------------------
2default:defaulth p
x
? 
s
%s
*synth2[
GSynthesis finished with 0 errors, 5 critical warnings and 54 warnings.
2default:defaulth p
x
? 
?
%s
*synth2?
~Synthesis Optimization Runtime : Time (s): cpu = 00:00:17 ; elapsed = 00:00:17 . Memory (MB): peak = 707.520 ; gain = 394.285
2default:defaulth p
x
? 
?
%s
*synth2?
Synthesis Optimization Complete : Time (s): cpu = 00:00:17 ; elapsed = 00:00:17 . Memory (MB): peak = 707.520 ; gain = 394.285
2default:defaulth p
x
? 
B
 Translating synthesized netlist
350*projectZ1-571h px? 
f
-Analyzing %s Unisim elements for replacement
17*netlist2
982default:defaultZ29-17h px? 
j
2Unisim Transformation completed in %s CPU seconds
28*netlist2
12default:defaultZ29-28h px? 
K
)Preparing netlist for logic optimization
349*projectZ1-570h px? 
u
)Pushed %s inverter(s) to %s load pin(s).
98*opt2
02default:default2
02default:defaultZ31-138h px? 
?
!Unisim Transformation Summary:
%s111*project2?
?  A total of 5 instances were transformed.
  RAM32M => RAM32M (RAMD32, RAMD32, RAMD32, RAMD32, RAMD32, RAMD32, RAMS32, RAMS32): 5 instances
2default:defaultZ1-111h px? 
U
Releasing license: %s
83*common2
	Synthesis2default:defaultZ17-83h px? 
?
G%s Infos, %s Warnings, %s Critical Warnings and %s Errors encountered.
28*	vivadotcl2
2682default:default2
542default:default2
52default:default2
02default:defaultZ4-41h px? 
^
%s completed successfully
29*	vivadotcl2 
synth_design2default:defaultZ4-42h px? 
?
I%sTime (s): cpu = %s ; elapsed = %s . Memory (MB): peak = %s ; gain = %s
268*common2"
synth_design: 2default:default2
00:00:212default:default2
00:00:222default:default2
757.4102default:default2
457.3202default:defaultZ17-268h px? 
K
"No constraint will be written out.1103*constraintsZ18-5210h px? 
?
 The %s '%s' has been generated.
621*common2

checkpoint2default:default2J
6C:/Users/HP/SpoC_15_11/SpoC_15_11.runs/synth_1/LWC.dcp2default:defaultZ17-1381h px? 
?
%s4*runtcl2p
\Executing : report_utilization -file LWC_utilization_synth.rpt -pb LWC_utilization_synth.pb
2default:defaulth px? 
?
sreport_utilization: Time (s): cpu = 00:00:00 ; elapsed = 00:00:00.049 . Memory (MB): peak = 757.410 ; gain = 0.000
*commonh px? 
?
Exiting %s at %s...
206*common2
Vivado2default:default2,
Mon Feb 15 09:31:35 20212default:defaultZ17-206h px? 


End Record