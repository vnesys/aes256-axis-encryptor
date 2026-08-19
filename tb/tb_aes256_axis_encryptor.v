`timescale 1ns / 1ps

// Self-checking AES-256 stream testbench using FIPS-197 and NIST vectors.
module tb_aes256_axis_encryptor;

    reg          i_axis_aclk;
    reg          i_axis_aresetn;
    reg  [127:0] i_s_axis_tdata;
    reg          i_s_axis_tvalid;
    reg          i_s_axis_tlast;
    reg          mark_plaintext;

    wire [127:0] o_m_axis_tdata;
    wire         o_m_axis_tvalid;
    wire         o_m_axis_tlast;

    reg [127:0] expected_ciphertext [0:15];
    integer      accepted_cycle [0:15];
    integer      expected_write_index;
    integer      expected_read_index;
    integer      accepted_write_index;
    integer      cycle_count;
    integer      error_count;
    integer      timeout_count;

    aes256_axis_encryptor dut (
        .i_axis_aclk(i_axis_aclk),
        .i_axis_aresetn(i_axis_aresetn),
        .i_s_axis_tdata(i_s_axis_tdata),
        .i_s_axis_tvalid(i_s_axis_tvalid),
        .i_s_axis_tlast(i_s_axis_tlast),
        .o_m_axis_tdata(o_m_axis_tdata),
        .o_m_axis_tvalid(o_m_axis_tvalid),
        .o_m_axis_tlast(o_m_axis_tlast)
    );

    always #5 i_axis_aclk = ~i_axis_aclk;

    // Present one input beat; the DUT consumes it on the next rising edge.
    task send_beat;
        input [127:0] beat_data;
        input         beat_last;
        input         beat_is_plaintext;
        begin
            @(negedge i_axis_aclk);
            i_s_axis_tdata = beat_data;
            i_s_axis_tlast = beat_last;
            i_s_axis_tvalid = 1'b1;
            mark_plaintext = beat_is_plaintext;
        end
    endtask

    // Attach the expected result before sending a plaintext beat.
    task send_plaintext;
        input [127:0] plaintext_data;
        input [127:0] ciphertext_expected;
        input         plaintext_last;
        begin
            expected_ciphertext[expected_write_index] = ciphertext_expected;
            expected_write_index = expected_write_index + 1;
            send_beat(plaintext_data, plaintext_last, 1'b1);
        end
    endtask

    task drive_idle;
        begin
            @(negedge i_axis_aclk);
            i_s_axis_tdata = 128'h0;
            i_s_axis_tlast = 1'b0;
            i_s_axis_tvalid = 1'b0;
            mark_plaintext = 1'b0;
        end
    endtask

    // Wait until the final ciphertext beat has been visible for one cycle.
    task wait_for_output_last;
        begin
            timeout_count = 0;
            while (!o_m_axis_tlast && timeout_count < 80) begin
                @(negedge i_axis_aclk);
                timeout_count = timeout_count + 1;
            end
            if (!o_m_axis_tlast) begin
                $display("ERROR: timeout waiting for output TLAST");
                error_count = error_count + 1;
            end
        end
    endtask

    // Record plaintext acceptance and check outputs after DUT nonblocking updates.
    always @(posedge i_axis_aclk) begin
        cycle_count = cycle_count + 1;
        if (i_axis_aresetn && i_s_axis_tvalid && mark_plaintext) begin
            accepted_cycle[accepted_write_index] = cycle_count;
            accepted_write_index = accepted_write_index + 1;
        end
        #1;
        if (i_axis_aresetn && o_m_axis_tvalid) begin
            if (expected_read_index >= expected_write_index) begin
                $display("ERROR: unexpected ciphertext %032h", o_m_axis_tdata);
                error_count = error_count + 1;
            end else begin
                if (o_m_axis_tdata !== expected_ciphertext[expected_read_index]) begin
                    $display("ERROR: ciphertext[%0d] expected %032h received %032h",
                             expected_read_index, expected_ciphertext[expected_read_index],
                             o_m_axis_tdata);
                    error_count = error_count + 1;
                end
                if ((cycle_count - accepted_cycle[expected_read_index]) != 14) begin
                    $display("ERROR: ciphertext[%0d] latency expected 14 received %0d",
                             expected_read_index,
                             cycle_count - accepted_cycle[expected_read_index]);
                    error_count = error_count + 1;
                end
                expected_read_index = expected_read_index + 1;
            end
        end
    end

    initial begin
        i_axis_aclk = 1'b0;
        i_axis_aresetn = 1'b0;
        i_s_axis_tdata = 128'h0;
        i_s_axis_tvalid = 1'b0;
        i_s_axis_tlast = 1'b0;
        mark_plaintext = 1'b0;
        expected_write_index = 0;
        expected_read_index = 0;
        accepted_write_index = 0;
        cycle_count = 0;
        error_count = 0;
        timeout_count = 0;

        // Release the asynchronous reset away from a clock edge.
        #12;
        i_axis_aresetn = 1'b1;

        // NIST SP 800-38A: four consecutive blocks under one AES-256 key.
        send_beat(128'h603deb1015ca71be2b73aef0857d7781, 1'b0, 1'b0);
        send_beat(128'h1f352c073b6108d72d9810a30914dff4, 1'b0, 1'b0);
        send_plaintext(128'h6bc1bee22e409f96e93d7e117393172a,
                       128'hf3eed1bdb5d2a03c064b5a7e3db181f8, 1'b0);
        send_plaintext(128'hae2d8a571e03ac9c9eb76fac45af8e51,
                       128'h591ccb10d410ed26dc5ba74a31362870, 1'b0);
        send_plaintext(128'h30c81c46a35ce411e5fbc1191a0a52ef,
                       128'hb6ed21b99ca6f4f9f153e7b1beafed1d, 1'b0);
        send_plaintext(128'hf69f2445df4f9b17ad2b417be66c3710,
                       128'h23304b7a39f9f3ff067d8d8f9e24ecc7, 1'b1);
        drive_idle;
        wait_for_output_last;

        // FIPS-197 single-block example with a different packet key.
        send_beat(128'h000102030405060708090a0b0c0d0e0f, 1'b0, 1'b0);
        send_beat(128'h101112131415161718191a1b1c1d1e1f, 1'b0, 1'b0);
        send_plaintext(128'h00112233445566778899aabbccddeeff,
                       128'h8ea2b7ca516745bfeafc49904b496089, 1'b1);
        drive_idle;
        wait_for_output_last;

        repeat (3) @(posedge i_axis_aclk);
        if (expected_read_index != expected_write_index) begin
            $display("ERROR: expected %0d ciphertexts but observed %0d",
                     expected_write_index, expected_read_index);
            error_count = error_count + 1;
        end

        if (error_count == 0) begin
            $display("PASS: 5 AES-256 blocks matched with fixed 14-cycle latency");
        end else begin
            $display("FAIL: %0d testbench errors", error_count);
        end
        $finish;
    end

endmodule
