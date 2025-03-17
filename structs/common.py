from binaryninja import *
from typing import cast

bv = cast(BinaryView, bv) # type: ignore

def define_vec3f():
    (struct, name) = bv.parse_type_string("""
    struct Vec3f __packed {
        float m_x;
        float m_y;
        float m_z;
    };
    """)

    bv.define_user_type(name, Type.structure_type(struct))

define_vec3f()
