`include "svunit_defines.svh"

//===================================
// (Failsafe) timeout
//===================================
`define SVUNIT_TIMEOUT 200us

module udplb_datapath_unit_test;

    // Testcase name
    string name = "udplb_datapath_ut";

    // SVUnit base testcase
    svunit_pkg::svunit_testcase svunit_ut;

    //===================================
    // DUT + testbench
    //===================================
    // This test suite references the common smartnic_app
    // testbench top level. The 'tb' module is
    // loaded into the tb_glbl scope, so is available
    // at tb_glbl.tb.
    //
    // Interaction with the testbench is expected to occur
    // via the testbench environment class (tb_env). A
    // reference to the testbench environment is provided
    // here for convenience.
    tb_pkg::tb_env env;

    // VitisNetP4 table agent
    vitisnetp4_igr_verif_pkg::vitisnetp4_igr_agent vitisnetp4_agent;

    //===================================
    // Import common testcase tasks
    //===================================
    `include "../../esnet-smartnic-hw/src/smartnic_app/tests/common/tasks.svh"

    //===================================
    // Build
    //===================================
    function void build();
        svunit_ut = new(name);

        // Build testbench
        env = tb.build();
        env.set_debug_level(1);

        // Create P4 table agent
        vitisnetp4_agent = new(.hier_path(p4_dpic_hier_path)); // DPI-C P4 table agent requires hierarchical
                                                               // path to AXI-L write/read tasks
    endfunction

    //===================================
    // Setup for running the Unit Tests
    //===================================
    task setup();
        svunit_ut.setup();

        // start environment
        env.run();

        // Initialize vitisnetp4 tables
        vitisnetp4_agent.init();

        p4_sim_dir = "../../../p4/sim/";

        #100ns;
    endtask


    //===================================
    // Here we deconstruct anything we
    // need after running the Unit Tests
    //===================================
    task teardown();
        // Stop environment
        env.stop();

        svunit_ut.teardown();

        // Clean up vitisnetp4 tables
        vitisnetp4_agent.terminate();
    endtask

    //=======================================================================
    // TESTS
    //=======================================================================

    //===================================
    // All tests are defined between the
    // SVUNIT_TESTS_BEGIN/END macros
    //
    // Each individual test must be
    // defined between `SVTEST(_NAME_)
    // `SVTEST_END
    //
    // i.e.
    //   `SVTEST(mytest)
    //     <test code>
    //   `SVTEST_END
    //===================================

    `SVUNIT_TESTS_BEGIN

    `SVTEST(test_1)
        run_pkt_test(.testdir("test-1"));
    `SVTEST_END

    `SVUNIT_TESTS_END

endmodule
