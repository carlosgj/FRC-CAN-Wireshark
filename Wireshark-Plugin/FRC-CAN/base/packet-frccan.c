#include "config.h"

#include <epan/packet.h>

#define FOO_PORT 1234

static const value_string manufacturers[] =
{
	{ 0x00, "Broadcast" },
	{ 0x01, "National Instruments" },
	{ 0x02, "Texas Instruments (Stellaris)" },
	{ 0x03, "DEKA" },
	{ 0x04, "CTRE" }
};

static const value_string device_types[] =
{
	{ 0x00, "Broadcast" },
	{ 0x01, "Robot Controller" },
	{ 0x02, "Motor Controller" },
	{ 0x03, "Relay Controller" },
	{ 0x04, "Gyro Sensor" },
	{ 0x05, "Accelerometer" },
	{ 0x06, "Ultrasonic Sensor" },
	{ 0x07, "Gear Tooth Sensor" },
	{ 0x08, "Power Distribution" },
	{ 0x1f, "Firmware Update" }
};

static dissector_table_t mfr_dissector_table;

static int proto_can = -1;

static int dissect_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

static int hf_frccan_dev_type = -1;

static int hf_frccan_mfr = -1;

static int hf_frccan_api = -1;

static int hf_frccan_id = -1;

static gint ett_foo = -1;

void
proto_register_can(void)
{

   static hf_register_info hf[] = {
        { &hf_frccan_dev_type,
            { "Device Type", "can.frc.type",
            FT_UINT32, BASE_HEX,
            VALS(device_types), 0x1f000000,
            "ASDF", HFILL }
        },
	{ &hf_frccan_mfr,
            { "Manufacturer", "can.frc.mfr",
            FT_UINT32, BASE_HEX,
            VALS(manufacturers), 0x00ff0000,
            "ASDF", HFILL }
        },
        { &hf_frccan_api,
            { "API", "can.frc.api",
            FT_UINT32, BASE_HEX,
            NULL, 0x0000ffc0,
            "ASDF", HFILL }
        },
        { &hf_frccan_id,
            { "Device ID", "can.frc.id",
            FT_UINT32, BASE_HEX,
            NULL, 0x0000003f,
            "ASDF", HFILL }
        },


    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_foo
    };

    proto_can = proto_register_protocol (
        "FRC Base CAN", /* name       */
        "FRC-CAN",      /* short name */
        "frc-can"       /* abbrev     */
        );
    
    proto_register_field_array(proto_can, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    mfr_dissector_table = register_dissector_table("can.frc.mfr", "Device Manufacturer", proto_can, FT_UINT32, BASE_DEC);

}

void
proto_reg_handoff_can(void)
{
    static dissector_handle_t can_handle;

    can_handle = create_dissector_handle(dissect_can, proto_can);
    dissector_add_for_decode_as("can.subdissector", can_handle);
}



static int
dissect_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{

    tvbuff_t *id_bits = tvb_new_real_data((unsigned char *)data, 4, 4);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FRC-CAN");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    //col_add_fstr(pinfo->cinfo, COL_INFO, "%02X:%02X:%02X:%02X", ((unsigned char*)data)[0], ((unsigned char*)data)[1], ((unsigned char*)data)[2], ((unsigned char*)data)[3]);
    proto_item *ti = proto_tree_add_item(tree, proto_can, tvb, 0, -1, ENC_NA);
//    proto_tree_add_item(tree, proto_can, tvb, 0, -1, ENC_NA);
    proto_tree *foo_tree = proto_item_add_subtree(ti, ett_foo);
    proto_tree_add_item(foo_tree, hf_frccan_dev_type, id_bits, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(foo_tree, hf_frccan_mfr, id_bits, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(foo_tree, hf_frccan_api, id_bits, 0, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(foo_tree, hf_frccan_id, id_bits, 0, 4, ENC_LITTLE_ENDIAN);
    unsigned char mfr = ((unsigned char*)data)[2];
    dissector_try_uint_new(mfr_dissector_table, mfr, tvb, pinfo, tree, TRUE, data);


    return tvb_captured_length(tvb);
}

