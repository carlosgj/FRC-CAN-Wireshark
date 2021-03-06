#include "config.h"

#include <epan/packet.h>

#define FOO_PORT 1234

#define SRX_API_GENERAL		0x50       // 0x1400
#define SRX_API_FEEDBACK_0	0x51       // 0x1440
#define SRX_API_QUAD_ENCODER	0x52   // 0x1480
#define SRX_API_ANALOG_IN	0x53       // 0x14c0
#define SRX_API_BOOT		0x54       // 0x1500 - ??? not found
#define SRX_API_MISC		0x55       // 0x1540
#define SRX_API_COMM_STATUS 0x56       // 0x1580
#define SRX_API_PWM		    0x57       // 0x15c0
#define SRX_API_MOTION_PROFILE	0x58   // 0x1600
#define SRX_API_MOTION_MAGIC	0x59   // 0x1640
#define SRX_API_UART_GADGETEER	0x5A   // 0x1680
#define SRX_API_FEEDBACK_1	0x5B       // 0x16c0
#define SRX_API_BASE_PIDF_0	0x5C       // 0x1700
#define SRX_API_TURN_PIDF_1	0x5D       // 0x1740
#define SRX_API_FIRMWARE	0x5E       // 0x1780

#define SRX_API_CONTROL_3_GENERAL                  0x02  // 400080
#define SRX_API_CONTROL_4_ADVANCED                 0x03  // 4000C0
#define SRX_API_CONTROL_5_FEEDBACK_OUTPUT_OVERRIDE 0x04  // 400100
#define SRX_API_CONTROL_6_MOT_PROF_ADD_TRAJ_POINT  0x05  // 400140

#define PDP_API_STATUS1		0x50
#define PDP_API_STATUS2     0x51
#define PDP_API_STATUS3     0x52
#define PDP_API_STATUSENERGY 0x5D
#define PDP_API_CONTROL1	0x70

#define PCM_API_STATUS1		      0x50
#define PCM_API_STATUS_SOL_FAULTS 0x51
#define PCM_API_STATUS_DEBUG      0x52
#define PCM_API_CONTROL1	      0x53
#define PCM_API_CONTROL2	      0x54
#define PCM_API_CONTROL3	      0x55

static int proto_ctre = -1;

static int proto_talonsrx = -1;

static int hf_ctre_srx_api = -1;

static int hf_ctre_srx_error = -1;

static int hf_ctre_srx_fwlim = -1;

static int hf_ctre_srx_rvlim = -1;

static int hf_ctre_srx_flt_fwslim = -1;

static int hf_ctre_srx_flt_rvslim = -1;

static int hf_ctre_srx_flt_temp = -1;

static int hf_ctre_srx_flt_undervolt = -1;

static int hf_ctre_srx_flt_fwlim = -1;

static int hf_ctre_srx_flt_rvlim = -1;

static int hf_ctre_srx_flt_hardware = -1;

static int hf_ctre_srx_throttle = -1;

static int hf_ctre_srx_limen = -1;

static int hf_ctre_srx_fb = -1;

static int hf_ctre_srx_mode = -1;

static int hf_ctre_pdp_api = -1;

static int hf_ctre_pdp_chan1    = -1;
static int hf_ctre_pdp_chan1_h8 = -1;
static int hf_ctre_pdp_chan2_h6 = -1;
static int hf_ctre_pdp_chan1_l2 = -1;
static int hf_ctre_pdp_chan3_h4 = -1;
static int hf_ctre_pdp_chan2_l4 = -1;
static int hf_ctre_pdp_chan4_h2 = -1;
static int hf_ctre_pdp_chan3_l6 = -1;
static int hf_ctre_pdp_chan4_l8 = -1;
static int hf_ctre_pdp_chan5_h8 = -1;
static int hf_ctre_pdp_chan6_h6 = -1;
static int hf_ctre_pdp_chan5_l2 = -1;
static int hf_ctre_pdp_chan6_l4 = -1;

static int hf_ctre_pdp_chan7_h8 = -1;
static int hf_ctre_pdp_chan8_h6 = -1;
static int hf_ctre_pdp_chan7_l2 = -1;
static int hf_ctre_pdp_chan9_h4 = -1;
static int hf_ctre_pdp_chan8_l4 = -1;
static int hf_ctre_pdp_chan10_h2 = -1;
static int hf_ctre_pdp_chan9_l6 = -1;
static int hf_ctre_pdp_chan10_l8 = -1;
static int hf_ctre_pdp_chan11_h8 = -1;
static int hf_ctre_pdp_chan12_h6 = -1;
static int hf_ctre_pdp_chan11_l2 = -1;
static int hf_ctre_pdp_chan12_l4 = -1;

static int hf_ctre_pdp_chan13_h8 = -1;
static int hf_ctre_pdp_chan14_h6 = -1;
static int hf_ctre_pdp_chan13_l2 = -1;
static int hf_ctre_pdp_chan15_h4 = -1;
static int hf_ctre_pdp_chan14_l4 = -1;
static int hf_ctre_pdp_chan16_h2 = -1;
static int hf_ctre_pdp_chan15_l6 = -1;
static int hf_ctre_pdp_chan16_l8 = -1;

static int hf_ctre_pdp_intres = -1;

static int hf_ctre_pdp_voltage = -1;

static int hf_ctre_pdp_temp = -1;

static int hf_ctre_pdp_TmeasMs_likelywillbe20ms_ = -1;
static int hf_ctre_pdp_TotalCurrent_125mAperunit_h8 = -1;
static int hf_ctre_pdp_Power_125mWperunit_h4 = -1;
static int hf_ctre_pdp_TotalCurrent_125mAperunit_l4 = -1;
static int hf_ctre_pdp_Power_125mWperunit_m8 = -1;
static int hf_ctre_pdp_Energy_125mWPerUnitXTmeas_h4 = -1;
static int hf_ctre_pdp_Power_125mWperunit_l4 = -1;
static int hf_ctre_pdp_Energy_125mWPerUnitXTmeas_mh8 = -1;
static int hf_ctre_pdp_Energy_125mWPerUnitXTmeas_ml8 = -1;
static int hf_ctre_pdp_Energy_125mWPerUnitXTmeas_l8 = -1;

static int hf_ctre_pcm_api = -1;

static int dissect_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

static gint ett_detail = -1;

//static gint ett_srxgeneral = -1;

static const value_string srx_apis[] =
{
        { SRX_API_GENERAL, "General" },
        { SRX_API_FEEDBACK_0, "Feedback 0" },
        { SRX_API_QUAD_ENCODER, "Quad Encoder" },
        { SRX_API_ANALOG_IN, "Analog In" },
        { SRX_API_BOOT, "Boot Status" },
        { SRX_API_MISC, "Misc" },
        { SRX_API_COMM_STATUS, "Comm Status" },
        { SRX_API_PWM, "Pulse Width" },
        { SRX_API_MOTION_PROFILE, "Motion Profile Buffer" },
        { SRX_API_MOTION_MAGIC, "Motion Magic" },
		{ SRX_API_UART_GADGETEER, "UART Gadgeteer" },
		{ SRX_API_FEEDBACK_1, "Feedback 1" },
		{ SRX_API_BASE_PIDF_0, "Base PIDF 0" },
		{ SRX_API_TURN_PIDF_1, "Turn PIDF 1" },
		{ SRX_API_FIRMWARE, "Firmware API Status" },
		{ SRX_API_CONTROL_3_GENERAL, "Control 3 General" },
		{ SRX_API_CONTROL_4_ADVANCED, "Control 4 Advanced" },
		{ SRX_API_CONTROL_5_FEEDBACK_OUTPUT_OVERRIDE, "Control 5 Feedback Output Override" },
		{ SRX_API_CONTROL_6_MOT_PROF_ADD_TRAJ_POINT, "Control 6 Motion Profile Ad Trajector Point"}
};


static const value_string pdp_apis[] =
{
        { PDP_API_STATUS1, "Status 1" },
        { PDP_API_STATUS2, "Status 2" },
        { PDP_API_STATUS3, "Status 3" },
        { PDP_API_STATUSENERGY, "Status Energy" },
        { PDP_API_CONTROL1, "Control 1" }
};

static const value_string pcm_apis[] =
{
        { PCM_API_STATUS1, "Status 1" },
        { PCM_API_STATUS_SOL_FAULTS, "Status SOL Faults" },
        { PCM_API_STATUS_DEBUG, "Status Debug" },
        { PCM_API_CONTROL1, "Control 1" },
        { PCM_API_CONTROL2, "Control 2" },
        { PCM_API_CONTROL3, "Control 3" }
};

void
proto_register_can(void)
{

    proto_ctre = proto_register_protocol (
        "Cross-The-Road Electronics CAN Devices", /* name       */
        "CTRE-CAN",      /* short name */
        "ctre-can"       /* abbrev     */
        );

    proto_talonsrx = proto_register_protocol(
	"Talon SRX",
	"TalonSRX",
	"srx"
	);


    static hf_register_info hf_srx[] = {
        { &hf_ctre_srx_api,
            { "Talon SRX API", "can.frc.ctre.srx.api",
            FT_UINT32, BASE_HEX,
            VALS(srx_apis), 0x0000ffc0,
            NULL, HFILL }
        }
    };

    static hf_register_info srx_general[] = {
	{ &hf_ctre_srx_error, 
	    { "Closed Loop Error", "can.frc.ctre.srx.error",
	    FT_UINT64, BASE_HEX,
	    NULL, 0xffffff0000000000,
	    NULL, HFILL }
	},
	{ &hf_ctre_srx_fwlim,
	    { "Forward Limit Switch", "can.frc.ctre.srx.flim",
	    FT_BOOLEAN, 64,
	    NULL, 0x0000008000000000,
	    NULL, HFILL }
	},
	{ &hf_ctre_srx_rvlim,
            { "Reverse Limit Switch", "can.frc.ctre.srx.rlim",
            FT_BOOLEAN, 64,
            NULL, 0x0000004000000000,
            NULL, HFILL }
        },
	{ &hf_ctre_srx_flt_fwslim,
            { "Forward Soft Limit Switch Fault", "can.frc.ctre.srx.flt.fslim",
            FT_BOOLEAN, 64,
            NULL, 0x0000001000000000,
            NULL, HFILL }
        },
        { &hf_ctre_srx_flt_rvslim,
            { "Reverse Soft Limit Switch Fault", "can.frc.ctre.srx.flt.rslim",
            FT_BOOLEAN, 64,
            NULL, 0x0000000800000000,
            NULL, HFILL }
        },
        { &hf_ctre_srx_throttle,
            { "Applied Throttle", "can.frc.ctre.srx.throttle",
            FT_UINT64, BASE_DEC,
            NULL, 0x00000007ff000000,
            NULL, HFILL }
        },
        { &hf_ctre_srx_limen,
            { "Limit Switch Enable", "can.frc.ctre.srx.lim",
            FT_UINT64, BASE_HEX, 
            NULL, 0x0000000000e00000,
            NULL, HFILL }
        },
        { &hf_ctre_srx_fb,
            { "Feedback Device", "can.frc.ctre.srx.fb",
            FT_UINT64, BASE_DEC,
            NULL, 0x00000000001e0000,
            NULL, HFILL }
        },
        { &hf_ctre_srx_mode,
            { "Selected Mode", "can.frc.ctre.srx.mode",
            FT_UINT64, BASE_DEC,
            NULL, 0x000000000001e000,
            NULL, HFILL }
        },
        { &hf_ctre_srx_flt_temp,
            { "Over Temperature Fault", "can.frc.ctre.srx.flt.temp",
            FT_BOOLEAN, 64,
            NULL, 0x0000000000001000,
            NULL, HFILL }
        },
        { &hf_ctre_srx_flt_undervolt,
            { "Undervoltage Fault", "can.frc.ctre.srx.flt.undervolt",
            FT_BOOLEAN, 64,
            NULL, 0x0000000000000800,
            NULL, HFILL }
        },
        { &hf_ctre_srx_flt_fwlim,
            { "Forward Limit Switch Fault", "can.frc.ctre.srx.flt.fwlim",
            FT_BOOLEAN, 64,
            NULL, 0x0000000000000400,
            NULL, HFILL }
        },
        { &hf_ctre_srx_flt_rvlim,
            { "Reverse Limit Switch Fault", "can.frc.ctre.srx.flt.rvlim",
            FT_BOOLEAN, 64,
            NULL, 0x0000000000000200,
            NULL, HFILL }
        },
        { &hf_ctre_srx_flt_hardware,
            { "Hardware Failure", "can.frc.ctre.srx.flt.hardware",
            FT_BOOLEAN, 64,
            NULL, 0x0000000000000100,
            NULL, HFILL }
        },
    };


    static hf_register_info hf_pdp[] = {
        { &hf_ctre_pdp_api,
            { "PDP API", "can.frc.ctre.pdp.api",
            FT_UINT32, BASE_HEX,
            VALS(pdp_apis), 0x0000ffc0,
            NULL, HFILL }
        }
    };

    static hf_register_info hf_pcm[] = {
        { &hf_ctre_pcm_api,
            { "PDP API", "can.frc.ctre.pcm.api",
            FT_UINT32, BASE_HEX,
            VALS(pcm_apis), 0x0000ffc0,
            NULL, HFILL }
        }
    };

    static hf_register_info pdp_status1[] = {
        { &hf_ctre_pdp_chan1,
            { "Chan1", "can.frc.ctre.pdp.chan1",
            FT_UINT64, BASE_DEC,
            NULL, 0xff03000000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan1_h8,
            { "Chan1_h8", "can.frc.ctre.pdp.chan1_h8",
            FT_UINT64, BASE_DEC,
            NULL, 0xff00000000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan2_h6,
            { "Chan2_h6", "can.frc.ctre.pdp.chan2_h6",
            FT_UINT64, BASE_DEC,
            NULL, 0x00fC000000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan1_l2,
            { "Chan1_l2", "can.frc.ctre.pdp.chan1_l2",
            FT_UINT64, BASE_DEC,
            NULL, 0x0003000000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan3_h4,
            { "Chan3_h4", "can.frc.ctre.pdp.chan3_h4",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000f00000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan2_l4,
            { "Chan2_l4", "can.frc.ctre.pdp.chan2_l4",
            FT_UINT64, BASE_DEC,
            NULL, 0x00000f0000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan4_h2,
            { "Chan4_h2", "can.frc.ctre.pdp.chan4_h2",
            FT_UINT64, BASE_DEC,
            NULL, 0x000000c000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan3_l6,
            { "Chan3_l6", "can.frc.ctre.pdp.chan3_l6",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000003f00000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan4_l8,
            { "Chan4_l8", "can.frc.ctre.pdp.chan4_l8",
            FT_UINT64, BASE_DEC,
            NULL, 0x00000000ff000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan5_h8,
            { "Chan5_h8", "can.frc.ctre.pdp.chan5_h8",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000000000ff0000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan6_h6,
            { "Chan6_h6", "can.frc.ctre.pdp.chan6_h6",
            FT_UINT64, BASE_DEC,
            NULL, 0x000000000000fc00,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan5_l2,
            { "Chan5_l2", "can.frc.ctre.pdp.chan5_l2",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000000000000300,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan6_l4,
            { "Chan6_l4", "can.frc.ctre.pdp.chan6_l4",
            FT_UINT64, BASE_DEC,
            NULL, 0x000000000000000f,
            NULL, HFILL }
        }
    };

    static hf_register_info pdp_status2[] = {
        { &hf_ctre_pdp_chan7_h8,
            { "Chan7_h8", "can.frc.ctre.pdp.chan7_h8",
            FT_UINT64, BASE_DEC,
            NULL, 0xff00000000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan8_h6,
            { "Chan9_h6", "can.frc.ctre.pdp.chan8_h6",
            FT_UINT64, BASE_DEC,
            NULL, 0x00fc000000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan7_l2,
            { "Chan7_l2", "can.frc.ctre.pdp.chan7_l2",
            FT_UINT64, BASE_DEC,
            NULL, 0x0003000000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan9_h4,
            { "Chan9_h4", "can.frc.ctre.pdp.chan9_h4",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000f00000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan8_l4,
            { "Chan8_l4", "can.frc.ctre.pdp.chan8_l4",
            FT_UINT64, BASE_DEC,
            NULL, 0x00000f0000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan10_h2,
            { "Chan10_h2", "can.frc.ctre.pdp.chan10_h2",
            FT_UINT64, BASE_DEC,
            NULL, 0x000000c000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan9_l6,
            { "Chan9_l6", "can.frc.ctre.pdp.chan9_l6",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000003f00000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan10_l8,
            { "Chan10_l8", "can.frc.ctre.pdp.chan10_l8",
            FT_UINT64, BASE_DEC,
            NULL, 0x00000000ff000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan11_h8,
            { "Chan11_h8", "can.frc.ctre.pdp.chan11_h8",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000000000ff0000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan12_h6,
            { "Chan12_h6", "can.frc.ctre.pdp.chan12_h6",
            FT_UINT64, BASE_DEC,
            NULL, 0x000000000000fc00,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan11_l2,
            { "Chan11_l2", "can.frc.ctre.pdp.chan11_l2",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000000000000300,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan12_l4,
            { "Chan12_l4", "can.frc.ctre.pdp.chan12_l4",
            FT_UINT64, BASE_DEC,
            NULL, 0x000000000000000f,
            NULL, HFILL }
        },
    };

    static hf_register_info pdp_status3[] = {
        { &hf_ctre_pdp_chan13_h8,
            { "Chan13_h8", "can.frc.ctre.pdp.chan13_h8",
            FT_UINT64, BASE_DEC,
            NULL, 0xff00000000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan14_h6,
            { "Chan14_h6", "can.frc.ctre.pdp.chan14_h6",
            FT_UINT64, BASE_DEC,
            NULL, 0x00fc000000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan13_l2,
            { "Chan13_l2", "can.frc.ctre.pdp.chan13_l2",
            FT_UINT64, BASE_DEC,
            NULL, 0x0003000000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan15_h4,
            { "Chan15_h4", "can.frc.ctre.pdp.chan15_h4",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000f00000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan14_l4,
            { "Chan14_l4", "can.frc.ctre.pdp.chan14_l4",
            FT_UINT64, BASE_DEC,
            NULL, 0x00000f0000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan16_h2,
            { "Chan16_h2", "can.frc.ctre.pdp.chan16_h2",
            FT_UINT64, BASE_DEC,
            NULL, 0x000000c000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan15_l6,
            { "Chan15_l6", "can.frc.ctre.pdp.chan15_l6",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000003f00000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_chan16_l8,
            { "Chan16_l8", "can.frc.ctre.pdp.chan16_l8",
            FT_UINT64, BASE_DEC,
            NULL, 0x00000000ff000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_intres,
            { "Internal Resistance", "can.frc.ctre.pdp.intres",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000000000ff0000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_voltage,
            { "Bus Voltage", "can.frc.ctre.pdp.voltage",
            FT_UINT64, BASE_DEC,
            NULL, 0x000000000000ff00,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_temp,
            { "Temperature", "can.frc.ctre.pdp.temp",
            FT_UINT64, BASE_DEC,
            NULL, 0x00000000000000ff,
            NULL, HFILL }
        }
    };

    static hf_register_info pdp_statusenergy[] = {
        { &hf_ctre_pdp_TmeasMs_likelywillbe20ms_,
            { "TmeasMs_likelywillbe20ms_", "can.frc.ctre.pdp.TmeasMs_likelywillbe20ms_",
            FT_UINT64, BASE_DEC,
            NULL, 0xff00000000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_TotalCurrent_125mAperunit_h8,
            { "TotalCurrent_125mAperunit_h8", "can.frc.ctre.pdp.TotalCurrent_125mAperunit_h8",
            FT_UINT64, BASE_DEC,
            NULL, 0x00ff000000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_Power_125mWperunit_h4,
            { "Power_125mWperunit_h4", "can.frc.ctre.pdp.Power_125mWperunit_h4",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000f00000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_TotalCurrent_125mAperunit_l4,
            { "TotalCurrent_125mAperunit_l4", "can.frc.ctre.pdp.TotalCurrent_125mAperunit_l4",
            FT_UINT64, BASE_DEC,
            NULL, 0x00000f0000000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_Power_125mWperunit_m8,
            { "Power_125mWperunit_m8", "can.frc.ctre.pdp.Power_125mWperunit_m8",
            FT_UINT64, BASE_DEC,
            NULL, 0x000000ff00000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_Energy_125mWPerUnitXTmeas_h4,
            { "Energy_125mwPerUnitXTmeas_h4", "can.frc.ctre.pdp.Energy_125mwPerUnitXTmeas_h4",
            FT_UINT64, BASE_DEC,
            NULL, 0x00000000f0000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_Power_125mWperunit_l4,
            { "Power_125mWperunit_l4", "can.frc.ctre.pdp.Power_125mWperunit_l4",
            FT_UINT64, BASE_DEC,
            NULL, 0x000000000f000000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_Energy_125mWPerUnitXTmeas_mh8,
            { "Energy_125mwPerUnitXTmeas_mh8", "can.frc.ctre.pdp.Energy_125mwPerUnitXTmeas_mh8",
            FT_UINT64, BASE_DEC,
            NULL, 0x0000000000ff0000,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_Energy_125mWPerUnitXTmeas_ml8,
            { "Energy_125mwPerUnitXTmeas_ml8", "can.frc.ctre.pdp.Energy_125mwPerUnitXTmeas_ml8",
            FT_UINT64, BASE_DEC,
            NULL, 0x000000000000ff00,
            NULL, HFILL }
        },
        { &hf_ctre_pdp_Energy_125mWPerUnitXTmeas_l8,
            { "Energy_125mwPerUnitXTmeas_l8", "can.frc.ctre.pdp.Energy_125mwPerUnitXTmeas_l8",
            FT_UINT64, BASE_DEC,
            NULL, 0x00000000000000ff,
            NULL, HFILL }
        }
	};
    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_detail
    };

    //static gint *ettsrxgeneral[] = {
//	&ett_srxgeneral
  //  };

    proto_register_field_array(proto_talonsrx, hf_srx, array_length(hf_srx));
    proto_register_field_array(proto_talonsrx, hf_pdp, array_length(hf_pdp));
    proto_register_field_array(proto_talonsrx, hf_pcm, array_length(hf_pcm));
    proto_register_field_array(proto_talonsrx, srx_general, array_length(srx_general));
    proto_register_field_array(proto_talonsrx, pdp_status1, array_length(pdp_status1));
    proto_register_field_array(proto_talonsrx, pdp_status2, array_length(pdp_status2));
    proto_register_field_array(proto_talonsrx, pdp_status3, array_length(pdp_status3));
    proto_register_field_array(proto_talonsrx, pdp_statusenergy, array_length(pdp_statusenergy));
    proto_register_subtree_array(ett, array_length(ett));
    //proto_register_subtree_array(ettsrxgeneral, array_length(ettsrxgeneral));
}

void
proto_reg_handoff_can(void)
{
    static dissector_handle_t can_handle;

    can_handle = create_dissector_handle(dissect_can, proto_ctre);
    dissector_add_uint("can.frc.mfr", 4, can_handle);
}



static int
dissect_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{

    tvbuff_t *id_bits = tvb_new_real_data((unsigned char *)data, 4, 4);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CTRE CAN");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    col_add_str(pinfo->cinfo, COL_INFO, "CTRE CAN Packet");
    guint32 canID = *((guint32*)data);
    canID &= 0x1fffffff;
    const unsigned char type = (canID >> 24) & 0b011111;
    const unsigned int api = (canID >> 6) & 0b0000001111111111;
    //col_add_fstr(pinfo->cinfo, COL_INFO, "%04X", api);
    proto_item *ti = proto_tree_add_item(tree, proto_ctre, tvb, 0, -1, ENC_NA);
    //proto_tree_add_item(tree, proto_ctre, tvb, 0, -1, ENC_NA);
    //proto_tree *foo_tree = proto_item_add_subtree(ti, ett_foo);
    //proto_tree_add_item(foo_tree, hf_frccan_dev_type, id_bits, 0, 4, ENC_LITTLE_ENDIAN);
    //proto_tree_add_item(foo_tree, hf_frccan_mfr, id_bits, 0, 4, ENC_LITTLE_ENDIAN);
    //proto_tree_add_item(foo_tree, hf_frccan_api, id_bits, 0, 4, ENC_LITTLE_ENDIAN);
    //proto_tree_add_item(foo_tree, hf_frccan_id, id_bits, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree *detail_tree = proto_item_add_subtree(ti, ett_detail);
    proto_tree *datatree;
    //proto_item_append_text(detail_tree, "Talon SRX Stuff");
    switch(type){
	case 2: //This is talon srx
	    col_clear(pinfo->cinfo,COL_INFO);
	    col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Unknown Frame");
	    proto_tree_add_item(detail_tree, hf_ctre_srx_api, id_bits, 0, 4, ENC_LITTLE_ENDIAN);
	    switch(api){
		case SRX_API_GENERAL:
			col_clear(pinfo->cinfo,COL_INFO);
		    col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX General Status");
		    //datatree = proto_item_add_subtree(ti, ett_srxgeneral);
		    datatree = ti;
		    //proto_item_append_text(datatree, "General Fields");
		    proto_tree_add_item(datatree, hf_ctre_srx_error, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_fwlim, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_rvlim, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_flt_fwslim, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_flt_rvslim, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_throttle, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_limen, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_fb, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_mode, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_flt_temp, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_flt_undervolt, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_flt_fwlim, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_flt_rvlim, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_srx_flt_hardware, tvb, 0, 8, ENC_BIG_ENDIAN);
		    break;
		case SRX_API_FEEDBACK_0:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Feedback 0 Status");
		    break;
		case SRX_API_QUAD_ENCODER:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Quad Encoder Status");
		    break;
		case SRX_API_ANALOG_IN:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Analog In Status");
		    break;
		case SRX_API_BOOT:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Boot");
		    break;
		case SRX_API_MISC:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Misc Status");
		    break;
		case SRX_API_COMM_STATUS:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Comm Status");
		    break;
		case SRX_API_PWM:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX PWM Status");
		    break;
		case SRX_API_MOTION_PROFILE:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Motion Profile Status");
		    break;
		case SRX_API_MOTION_MAGIC:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Motion Magic Status");
		    break;
		case SRX_API_UART_GADGETEER:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Gadgeteer Status");
		    break;
		case SRX_API_FEEDBACK_1:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Feedback 1 Status");
		    break;
		case SRX_API_BASE_PIDF_0:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Base PIDF 0 Status");
		    break;
		case SRX_API_TURN_PIDF_1:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Turn PIDF 1 Status");
		    break;
		case SRX_API_FIRMWARE:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Firmware Status");
		    break;
		case SRX_API_CONTROL_3_GENERAL:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Control 3 General");
		    break;
		case SRX_API_CONTROL_4_ADVANCED:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Control 4 Advanced");
		    break;
		case SRX_API_CONTROL_5_FEEDBACK_OUTPUT_OVERRIDE:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Control 5 Feedback Output Override");
		    break;
		case SRX_API_CONTROL_6_MOT_PROF_ADD_TRAJ_POINT:
		    col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Control 6 Mot Prof Add Traj Point");
		    break;
		default:
		    break;
	    }
	    break;
	case 8: //PDP
	    col_clear(pinfo->cinfo,COL_INFO);
	    col_add_fstr(pinfo->cinfo, COL_INFO, "PDP Unknown Frame");
	    proto_tree_add_item(detail_tree, hf_ctre_pdp_api, id_bits, 0, 4, ENC_LITTLE_ENDIAN);
	    switch(api){
		case PDP_API_STATUS1:
            col_clear(pinfo->cinfo,COL_INFO);
		    col_add_fstr(pinfo->cinfo, COL_INFO, "PDP Status 1");
		    datatree = ti;
			proto_tree_add_item(datatree, hf_ctre_pdp_chan1   , tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan1_h8, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan2_h6, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan1_l2, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan3_h4, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan2_l4, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan4_h2, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan3_l6, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan4_l8, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan5_h8, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan6_h6, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan5_l2, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan6_l4, tvb, 0, 8, ENC_BIG_ENDIAN);
		    break;
		case PDP_API_STATUS2:
            col_clear(pinfo->cinfo,COL_INFO);
		    col_add_fstr(pinfo->cinfo, COL_INFO, "PDP Status 2");
		    datatree = ti;
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan7_h8, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan8_h6, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan7_l2, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan9_h4, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan8_l4, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan10_h2, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan9_l6, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan10_l8, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan11_h8, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan12_h6, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan11_l2, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan12_l4, tvb, 0, 8, ENC_BIG_ENDIAN);
		    break;
        case PDP_API_STATUS3:
            col_clear(pinfo->cinfo,COL_INFO);
		    col_add_fstr(pinfo->cinfo, COL_INFO, "PDP Status 3");
		    datatree = ti;
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan13_h8, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan14_h6, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan13_l2, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan15_h4, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan14_l4, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan16_h2, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan15_l6, tvb, 0, 8, ENC_BIG_ENDIAN);
		    proto_tree_add_item(datatree, hf_ctre_pdp_chan16_l8, tvb, 0, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(datatree, hf_ctre_pdp_intres, tvb, 0, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(datatree, hf_ctre_pdp_voltage, tvb, 0, 8, ENC_BIG_ENDIAN);
            proto_tree_add_item(datatree, hf_ctre_pdp_temp, tvb, 0, 8, ENC_BIG_ENDIAN);
		    break;
		case PDP_API_STATUSENERGY:
			col_clear(pinfo->cinfo,COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO, "PDP Status Energy");
			datatree = ti;
			proto_tree_add_item(datatree, hf_ctre_pdp_TmeasMs_likelywillbe20ms_, tvb, 0, 8, ENC_BIG_ENDIAN);
			proto_tree_add_item(datatree, hf_ctre_pdp_TotalCurrent_125mAperunit_h8 , tvb, 0, 8, ENC_BIG_ENDIAN);
			proto_tree_add_item(datatree, hf_ctre_pdp_Power_125mWperunit_h4 , tvb, 0, 8, ENC_BIG_ENDIAN);
			proto_tree_add_item(datatree, hf_ctre_pdp_TotalCurrent_125mAperunit_l4 , tvb, 0, 8, ENC_BIG_ENDIAN);
			proto_tree_add_item(datatree, hf_ctre_pdp_Power_125mWperunit_m8 , tvb, 0, 8, ENC_BIG_ENDIAN);
			proto_tree_add_item(datatree, hf_ctre_pdp_Energy_125mWPerUnitXTmeas_h4 , tvb, 0, 8, ENC_BIG_ENDIAN);
			proto_tree_add_item(datatree, hf_ctre_pdp_Power_125mWperunit_l4 , tvb, 0, 8, ENC_BIG_ENDIAN);
			proto_tree_add_item(datatree, hf_ctre_pdp_Energy_125mWPerUnitXTmeas_mh8 , tvb, 0, 8, ENC_BIG_ENDIAN);
			proto_tree_add_item(datatree, hf_ctre_pdp_Energy_125mWPerUnitXTmeas_ml8 , tvb, 0, 8, ENC_BIG_ENDIAN);
			proto_tree_add_item(datatree, hf_ctre_pdp_Energy_125mWPerUnitXTmeas_l8 , tvb, 0, 8, ENC_BIG_ENDIAN);
			break;
        case PDP_API_CONTROL1:
            col_clear(pinfo->cinfo,COL_INFO);
		    col_add_fstr(pinfo->cinfo, COL_INFO, "PDP Control 1");
			break;

		default:
		    break;
	    }
	    break;
	case 9: // PCM
	    col_clear(pinfo->cinfo,COL_INFO);
	    col_add_fstr(pinfo->cinfo, COL_INFO, "PCM Unknown Frame");
	    proto_tree_add_item(detail_tree, hf_ctre_pcm_api, id_bits, 0, 4, ENC_LITTLE_ENDIAN);
		switch(api)
		{
			case PCM_API_STATUS1:
				col_clear(pinfo->cinfo,COL_INFO);
				col_add_fstr(pinfo->cinfo, COL_INFO, "PCM Status 1");
				break;
			case PCM_API_STATUS_SOL_FAULTS:
				col_clear(pinfo->cinfo,COL_INFO);
				col_add_fstr(pinfo->cinfo, COL_INFO, "PCM Status SOL Faults");
				break;
			case PCM_API_STATUS_DEBUG:
				col_clear(pinfo->cinfo,COL_INFO);
				col_add_fstr(pinfo->cinfo, COL_INFO, "PCM Status Debug");
				break;
			case PCM_API_CONTROL1:
				col_clear(pinfo->cinfo,COL_INFO);
				col_add_fstr(pinfo->cinfo, COL_INFO, "PCM Control 1");
				break;
			case PCM_API_CONTROL2:
				col_clear(pinfo->cinfo,COL_INFO);
				col_add_fstr(pinfo->cinfo, COL_INFO, "PCM Control 2");
				break;
			case PCM_API_CONTROL3:
				col_clear(pinfo->cinfo,COL_INFO);
				col_add_fstr(pinfo->cinfo, COL_INFO, "PCM Control 3");
				break;
			default:
				break;
		}
		break;
	default:
	    break;
    }

    return tvb_captured_length(tvb);
}

