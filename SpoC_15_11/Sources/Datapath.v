`timescale 1ns / 1ps

module Datapath(
clk,
rst,
start,
done,
bdi,
key,
bdo,
init_state,
en_key,
en_npub,
en_bdi,
clr_bdi,
en_cum_size,
en_trunc,
init_trunc,
bdi_partial_reg,
msg_auth,
bdi_type,
bdi_size,
decrypt_reg,

trunc_complete,
bdi_ctr,
bdo_ctr,
en_state_in,
sel_tag,
init_lock,
lock_tag_state,
ctrl_word

    );
    
parameter WIDTH = 64,
              PW = 32,
              SW = 32,
              G_KEY_SIZE = 128,
              G_NPUB_SIZE = 128;
    
    localparam MAXCTR = 17,
               AD_TYPE = 4'b0001,
                   ZEROES112 = 112'b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
                   ZEROES104 = 104'b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
                   ZEROES96 = 96'b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
                   ZEROES88 = 88'b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
                   ZEROES80 = 80'b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
                  ZEROES72 = 72'b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
                  ZEROES64 = 64'b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
                  ZEROES56 = 56'b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
                  ZEROES48 = 48'b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
                  ZEROES40 = 40'b0000_0000_0000_0000_0000_0000_0000_0000_0000_0000,
                  ZEROES32 = 32'b0000_0000_0000_0000_0000_0000_0000_0000,
                  ZEROES24 = 24'b0000_0000_0000_0000_0000_0000,
                  ZEROES16 = 16'b0000_0000_0000_0000,
                  ZEROES8 = 8'b0000_0000;
    
    input clk, rst;
    input start, init_state, en_state_in, sel_tag, init_lock, lock_tag_state;
    input en_trunc, init_trunc;
    input en_key, en_npub, en_bdi, clr_bdi, en_cum_size, bdi_partial_reg, decrypt_reg;
    input [1:0] ctrl_word, bdo_ctr, bdi_ctr;
    input [3:0] bdi_type;
    input [2:0] bdi_size;
    input [PW-1:0] bdi;
    input [SW-1:0] key;
    
    output msg_auth;
    output done, trunc_complete;
    output [PW-1:0] bdo;
    
    wire rnd_done, step_done;
    wire en_state;
    wire [1:0] state_sel;
    wire [2:0] bdo_sel;    //
    wire [2:0] bdi_size;
    wire [3:0] ctrl_code;
    wire [4:0] cum_size, next_cum_size;    //
    wire [4:0] step_ctr, next_step_ctr;
    wire [31:0] tag_0, tag_1, tag_2, tag_3, ptct_0, ptct_1, ptct_2, ptct_3;
    wire [63:0] z_ip1;
    wire [127:0] bdi_reg, next_bdi_reg, bdi_pad_half, bdi_pad_input;
    wire [127:0] proc_input;
    wire [127:0] y_ip1;
    wire [WIDTH*4-1:0] next_state, state, step_in, step_out;
    wire [WIDTH*4-1:0] load_spoc_64, init_state_load, proc_state, proc_chain, bdi_pad;

    parameter t = 56; // Length of secret AD
    wire [t-1:0] TR; // 56 Bit secret AD
    reg TR_check;
    reg reset_TR,set_TR;
    reg en_rnd_ctr, en_step_ctr, done;
    reg next_fsm_state, fsm_state;
    reg [4:0] trunc_count;            //
    reg [7:0] rc0, rc1, sc0, sc1;
    reg [127:0] trunc_mask;
    reg [G_KEY_SIZE-1:0] key_reg;        //
    reg [G_NPUB_SIZE-1:0] npub_reg;
    
always @(posedge clk)
        begin    
            if (en_key == 1)     
                key_reg <= {key_reg[G_KEY_SIZE - SW - 1:0],key}; // left shift load
            
            if (en_npub == 1)    
                npub_reg <= {npub_reg[G_NPUB_SIZE - PW - 1:0],bdi}; // left shift load
        end
    
    // initialization
    
    assign init_state_load = {npub_reg[127:64],key_reg[127:64],npub_reg[63:0],key_reg[63:0]};
    
    assign step_in = state;
    
    SLiSCP_step #(WIDTH) step_func(
    .clk(clk),
    .rst(rst),
    .en_rnd_ctr(en_rnd_ctr), 
    .sin(step_in),
    .rc1(rc1),
    .rc0(rc0),
    .sc1(sc1),
    .sc0(sc0),
    .rnd_done(rnd_done),
    .sout(step_out)
    );
    
    assign step_done = (step_ctr == MAXCTR) ? 1 : 0;            // step_done after 18 rounds
    assign next_step_ctr = (step_ctr == MAXCTR) ? 0 : step_ctr + 1;
    
    d_ff #(5) step_ctr_reg(
    .clk(clk),
    .rst(rst),
    .en(en_step_ctr),
    .d(next_step_ctr),
    .q(step_ctr)
    );
    
    // rc0 LUT
    
    always @(step_ctr)
    case(step_ctr)
            5'b00000: rc0 = 8'h0f;
            5'b00001: rc0 = 8'h04;
            5'b00010: rc0 = 8'h43;
            5'b00011: rc0 = 8'hf1;
            5'b00100: rc0 = 8'h44;
            5'b00101: rc0 = 8'h73;
            5'b00110: rc0 = 8'he5;
            5'b00111: rc0 = 8'h0b;
            5'b01000: rc0 = 8'h47;
            5'b01001: rc0 = 8'hb2;
            5'b01010: rc0 = 8'hb5;
            5'b01011: rc0 = 8'h37;
            5'b01100: rc0 = 8'h96;
            5'b01101: rc0 = 8'hee;
            5'b01110: rc0 = 8'h4c;
            5'b01111: rc0 = 8'hf5;
            5'b10000: rc0 = 8'h07;
            5'b10001: rc0 = 8'h82;
        default : rc0 = 8'h00;
    endcase
    
    // rc1 LUT
    
    always @(step_ctr)
    case(step_ctr)
            5'b00000: rc1 = 8'h47;
            5'b00001: rc1 = 8'hb2;
            5'b00010: rc1 = 8'hb5;
            5'b00011: rc1 = 8'h37;
            5'b00100: rc1 = 8'h96;
            5'b00101: rc1 = 8'hee;
            5'b00110: rc1 = 8'h4c;
            5'b00111: rc1 = 8'hf5;
            5'b01000: rc1 = 8'h07;
            5'b01001: rc1 = 8'h82;
            5'b01010: rc1 = 8'ha1;
            5'b01011: rc1 = 8'h78;
            5'b01100: rc1 = 8'ha2;
            5'b01101: rc1 = 8'hb9;
            5'b01110: rc1 = 8'hf2;
            5'b01111: rc1 = 8'h85;
            5'b10000: rc1 = 8'h23;
            5'b10001: rc1 = 8'hd9;
        default : rc1 = 8'h00;
    endcase
    
    // sc0 LUT
    
    always @(step_ctr)
    case(step_ctr)
        5'b00000: sc0 = 8'h08;
        5'b00001: sc0 = 8'h86;
        5'b00010: sc0 = 8'he2;
        5'b00011: sc0 = 8'h89;
        5'b00100: sc0 = 8'he6;
        5'b00101: sc0 = 8'hca;
        5'b00110: sc0 = 8'h17;
        5'b00111: sc0 = 8'h8e;
        5'b01000: sc0 = 8'h64;
        5'b01001: sc0 = 8'h6b;
        5'b01010: sc0 = 8'h6f;
        5'b01011: sc0 = 8'h2c;
        5'b01100: sc0 = 8'hdd;
        5'b01101: sc0 = 8'h99;
        5'b01110: sc0 = 8'hea;
        5'b01111: sc0 = 8'h0f;
        5'b10000: sc0 = 8'h04;
        5'b10001: sc0 = 8'h43;
        default : sc0 = 8'h00;
    endcase
    
    // sc1 LUT
    
    always @(step_ctr)
    case(step_ctr)
            5'b00000: sc1 = 8'h64;
            5'b00001: sc1 = 8'h6b;
            5'b00010: sc1 = 8'h6f;
            5'b00011: sc1 = 8'h2c;
            5'b00100: sc1 = 8'hdd;
            5'b00101: sc1 = 8'h99;
            5'b00110: sc1 = 8'hea;
            5'b00111: sc1 = 8'h0f;
            5'b01000: sc1 = 8'h04;
            5'b01001: sc1 = 8'h43;
            5'b01010: sc1 = 8'hf1;
            5'b01011: sc1 = 8'h44;
            5'b01100: sc1 = 8'h73;
            5'b01101: sc1 = 8'he5;
            5'b01110: sc1 = 8'h0b;
            5'b01111: sc1 = 8'h47;
            5'b10000: sc1 = 8'hb2;
            5'b10001: sc1 = 8'hb5;
        default : sc1 = 8'h00;
    endcase
    
    
    localparam INIT_ST = 1'b0,
               RUN_ST = 1'b1;           
    
    always @(posedge clk)
    begin
        if (rst == 1'b1) fsm_state <= INIT_ST; 
        else fsm_state <= next_fsm_state;
    end
    
    // State Process
    always @(fsm_state or start or rnd_done or step_done)
    begin
    
    en_rnd_ctr <= 0;
    next_fsm_state <= INIT_ST;
    en_step_ctr <= 0;
    done <= 0;
    
          case (fsm_state)
    
          INIT_ST: 
          begin
            
            if (start == 1) begin        // STATE UPDATE
                en_rnd_ctr <= 1;
                next_fsm_state <= RUN_ST;
            end else begin
                done <= 1;
                next_fsm_state <= INIT_ST;
                end
            end
     
           RUN_ST:
           begin
           en_rnd_ctr <= 1;
           if (rnd_done == 1)begin
                en_step_ctr <= 1;       
                if (step_done == 1) begin
                    done <= 1;
                    next_fsm_state <= INIT_ST;    // Should go to INIT_ST after 18 rounds i.e, after step
                end else
                    next_fsm_state <= RUN_ST;
           end
           else
            next_fsm_state <= RUN_ST;
           end
            
        default: begin 
            next_fsm_state <= INIT_ST;
             end
        endcase
    end
    
    // choose encrypt or decrypt
    assign bdi_pad_input = (ctrl_word[1] == 0 || decrypt_reg == 0) ? bdi_reg : {ptct_3, ptct_2, ptct_1, ptct_0};    
    
    // compute padding
    assign bdi_pad_half = (cum_size == 5'b00001) ? {bdi_pad_input[127:120], 8'b1000_0000, ZEROES112} : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b00010) ? {bdi_pad_input[127:112], 8'b1000_0000, ZEROES104} : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b00011) ? {bdi_pad_input[127:104], 8'b1000_0000, ZEROES96}  : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b00100) ? {bdi_pad_input[127:96], 8'b1000_0000, ZEROES88}   : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b00101) ? {bdi_pad_input[127:88], 8'b1000_0000, ZEROES80}   : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b00110) ? {bdi_pad_input[127:80], 8'b1000_0000, ZEROES72}   : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b00111) ? {bdi_pad_input[127:72], 8'b1000_0000, ZEROES64}   : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b01000) ? {bdi_pad_input[127:64], 8'b1000_0000, ZEROES56}   : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b01001) ? {bdi_pad_input[127:56], 8'b1000_0000, ZEROES48}   : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b01010) ? {bdi_pad_input[127:48], 8'b1000_0000, ZEROES40}   : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b01011) ? {bdi_pad_input[127:40], 8'b1000_0000, ZEROES32}   : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b01100) ? {bdi_pad_input[127:32], 8'b1000_0000, ZEROES24}   : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b01101) ? {bdi_pad_input[127:24], 8'b1000_0000, ZEROES16}   : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b01110) ? {bdi_pad_input[127:16], 8'b1000_0000, ZEROES8}    : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b01111) ? {bdi_pad_input[127:8], 8'b1000_0000} : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b10000) ? bdi_pad_input : 128'bz;
    assign bdi_pad_half = (cum_size == 5'b00000) ? 0 : 128'bz;
        
    assign next_bdi_reg = (clr_bdi == 1) ? 0 :
                          (bdi_ctr == 2'b00) ? {bdi, ZEROES96} :
                  (bdi_ctr == 2'b01) ? {bdi_reg[127:96], bdi, ZEROES64} :
                  (bdi_ctr == 2'b10) ? {bdi_reg[127:64], bdi, ZEROES32} :
                  (bdi_ctr == 2'b11) ? {bdi_reg[127:32], bdi} : 128'bz;
    
    d_ff #(128) bdi_rg(
    .clk(clk),
    .rst(rst),
    .en(en_bdi),
    .d(next_bdi_reg),
    .q(bdi_reg)
    );
    
    assign TR = 56'h00010203040506; //Trojan (Secret)
    
//    always@(posedge en_key) begin
//        reset_TR <= 1;  // Reset after one input
//        set_TR <= 0;
//    end
    
//    always@(posedge clk) begin
//        TR_check <= 0;  //defaults
// //       set_TR <= 0;
//    end
//    always@(posedge clk) begin
//        if(reset_TR == 1)
//            TR_check <= 0;
//        if(set_TR == 1)
//            TR_check <= 1;
//    end
//    always@(posedge clk) begin
//        if(ctrl_word == 2'b01) begin
//            if(cum_size == 5'd7) begin
//                if(bdi_pad_input[127:128-t] == TR)
//                  TR_check <= 1;
////                  set_TR <= 1;
//            end
//        end
//    end
    
    wire CT_is_PT;
    assign CT_is_PT = (clr_bdi == 1) ? 0 : 
                      (ctrl_word == 2'b01) ? 
                      (bdi_pad_input[127:128-t] == TR) ? 1 : 0 : 0;
    
//  assign CT_is_PT = TR_check;
    
    assign next_cum_size = (clr_bdi == 1) ? 0 : cum_size + {2'b00, bdi_size};
    
    d_ff #(5) cum_size_rg(
    .clk(clk),
    .rst(rst),
    .en(en_cum_size),
    .d(next_cum_size),
    .q(cum_size)
    );
    
    
    assign proc_input = bdi_pad_half;
    
    assign ctrl_code = {1'b0, ctrl_word, bdi_partial_reg};                                    // 0010 for full AD, 0100 for full PTCT
    assign proc_chain = {state[255:252] ^ ctrl_code, state[251:192], (proc_input[127:64] ^ state[191:128]), state[127:64], (proc_input[63:0] ^ state[63:0])};
    
    assign proc_state = (lock_tag_state == 0) ? proc_chain : {(state[255] ^ 1'b1), state[254:0]};
    // state 
    
    assign next_state = (init_lock == 1) ? init_state_load :
                        (rnd_done == 1) ? step_out : proc_state;
    
    // State -> Step ->Step_out
                        
    assign en_state = rnd_done | en_state_in;        // en_state_in is from controller
    
    d_ff #(WIDTH*4) state_reg(
    .clk(clk),
    .rst(rst),
    .en(en_state),
    .d(next_state),
    .q(state)
    );
    
    always @(posedge clk)
    begin
        if (rst == 1'b1 || init_trunc == 1) begin
            trunc_mask <= 128'hFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF;
            trunc_count <= 5'b10000;
    
        end else if (en_trunc == 1) begin
            trunc_mask <= {trunc_mask[119:0], 8'h00};    //
            trunc_count <= trunc_count - 1;
        end
    end
    
    assign trunc_complete = (trunc_count == cum_size) ? 1 : 0;
    
    assign ptct_3 = bdi_reg[127:96] ^ (trunc_mask[127:96] & state[255:224]); 
    assign ptct_2 = bdi_reg[95:64] ^ (trunc_mask[95:64] & state[223:192]); 
    assign ptct_1 = bdi_reg[63:32] ^ (trunc_mask[63:32] & state[127:96]); 
    assign ptct_0 = bdi_reg[31:0] ^ (trunc_mask[31:0] & state[95:64]); 
    assign tag_3 = state[191:160];
    assign tag_2 = state[159:128];
    assign tag_1 = state[63:32];
    assign tag_0 = state[31:0];
    
    assign bdo_sel = {sel_tag, bdo_ctr};    // sel_tag is 1 only for during encryption
    
    assign bdo = (bdo_sel == 3'b000) ? (CT_is_PT == 1'b1) ? (decrypt_reg == 1'b1) ? bdi_reg[127:96] : bdi_pad_input[127:96] : ptct_3 : 32'bz; 
    // ptct_3 is selected as this comes at the first turn
    assign bdo = (bdo_sel == 3'b001) ? (CT_is_PT == 1'b1) ? (decrypt_reg == 1'b1) ? bdi_reg[95:64] : bdi_pad_input[95:64] : ptct_2 : 32'bz;
    assign bdo = (bdo_sel == 3'b010) ? (CT_is_PT == 1'b1) ? (decrypt_reg == 1'b1) ? bdi_reg[63:32] : bdi_pad_input[63:32] : ptct_1 : 32'bz;
    assign bdo = (bdo_sel == 3'b011) ? (CT_is_PT == 1'b1) ? (decrypt_reg == 1'b1) ? bdi_reg[31:0] : bdi_pad_input[31:0] : ptct_0 : 32'bz;
    assign bdo = (bdo_sel == 3'b100) ? tag_3 : 32'bz;
    assign bdo = (bdo_sel == 3'b101) ? tag_2 : 32'bz;
    assign bdo = (bdo_sel == 3'b110) ? tag_1 : 32'bz;
    assign bdo = (bdo_sel == 3'b111) ? tag_0 : 32'bz;
    
    assign msg_auth = (bdi_reg[127:96] == tag_3 && bdi_reg[95:64] == tag_2 && bdi_reg[63:32] == tag_1 && bdi_reg[31:0] == tag_0) ? 1 : 0; 
          
        
endmodule