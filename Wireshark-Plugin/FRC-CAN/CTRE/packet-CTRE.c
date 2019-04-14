#include "config.h"

#include <epan/packet.h>

#define FOO_PORT 1234

#define SRX_API_GENERAL		0x50
#define SRX_API_FEEDBACK_0	0x51
#define SRX_API_QUAD_ENCODER	0x52
#define SRX_API_ANALOG_IN	0x53
#define SRX_API_BOOT		0x54
#define SRX_API_UNKNOWN		0x55
#define SRX_API_DEBUG		0x56
#define SRX_API_PWM		0x57
#define SRX_API_MOTION_PROFILE	0x58
#define SRX_API_MOTION_MAGIC	0x59
#define SRX_API_UART_GADGETEER	0x5A
#define SRX_API_FEEDBACK_1	0x5B
#define SRX_API_BASE_PIDF_0	0x5C
#define SRX_API_TURN_PIDF_1	0x5D
#define SRX_API_FIRMWARE	0x5E


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
        { SRX_API_UNKNOWN, "???" },
        { SRX_API_DEBUG, "Debug" },
        { SRX_API_PWM, "Pulse Width" },
        { SRX_API_MOTION_PROFILE, "Motion Profile Buffer" },
        { SRX_API_MOTION_MAGIC, "Motion Magic" },
	{ SRX_API_UART_GADGETEER, "UART Gadgeteer" },
	{ SRX_API_FEEDBACK_1, "Feedback 1" },
	{ SRX_API_BASE_PIDF_0, "Base PIDF 0" },
	{ SRX_API_TURN_PIDF_1, "Turn PIDF 1" }, 
	{ SRX_API_FIRMWARE, "Firmware API Status" }
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


    static hf_register_info hf[] = {
        { &hf_ctre_srx_api,
            { "Talon SRX API", "can.frc.ctre.srx.api",
            FT_UINT32, BASE_HEX,
            VALS(srx_apis), 0x0000ffc0,
            NULL, HFILL }
        }
    };

    static hf_register_info general[] = {
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

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_detail
    };

    //static gint *ettsrxgeneral[] = {
//	&ett_srxgeneral
  //  };

    proto_register_field_array(proto_talonsrx, hf, array_length(hf));
    proto_register_field_array(proto_talonsrx, general, array_length(general));
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
    unsigned char type = canID >> 24;
    unsigned int api = (canID >> 6) & 0b0000001111111111;
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
	case 2:
	    //This is talon srx
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
                    col_add_fstr(pinfo->cinfo, COL_INFO, "Talon SRX Feedback 0");
		    break;
		case SRX_API_QUAD_ENCODER:
		    break;
		default:
		    break;
	    };
	    break;
	case 8:
	    //PDP
	    col_clear(pinfo->cinfo,COL_INFO);
	    col_add_fstr(pinfo->cinfo, COL_INFO, "PDP Unknown Frame");
	    break;
	default:
	    break;
    };


    return tvb_captured_length(tvb);
}

