import os
import tempfile

from entropytrace.adapters.micropython import (
    _collect_declarations,
    _NODE_CACHE,
    _table_entries,
    find_module_registrations,
)
from entropytrace.buildset import TranslationUnit

# A minimal synthetic stand-in for random.c + modngu.c's preprocessed
# shape, collapsed into one TU for a self-contained test.
SYNTHETIC_PREPROCESSED = """
static const mp_obj_fun_builtin_fixed_t random_bytes_obj = {{&mp_type_fun_builtin_1}, .fun._1 = random_bytes};
static const mp_rom_map_elem_t globals_table[] = {
    { ((mp_obj_t)((((mp_uint_t)(MP_QSTR___name__)) << 3) | 2)), ((mp_obj_t)((((mp_uint_t)(MP_QSTR_random)) << 3) | 2)) },
    { ((mp_obj_t)((((mp_uint_t)(MP_QSTR_bytes)) << 3) | 2)), (&random_bytes_obj) },
};
static const mp_obj_dict_t globals_table_obj = { .base = {&mp_type_dict}, .map = { .all_keys_are_qstrs = 1, .is_fixed = 1, .is_ordered = 1, .used = 1, .alloc = 1, .table = (mp_map_elem_t *)(mp_rom_map_elem_t *)globals_table, }, };
const mp_obj_module_t mp_module_random = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&globals_table_obj,
};
"""


def test_collect_declarations_finds_all_four_shapes():
    _NODE_CACHE.clear()
    decls = _collect_declarations(SYNTHETIC_PREPROCESSED, "random.c")
    assert set(decls) == {
        "random_bytes_obj",
        "globals_table",
        "globals_table_obj",
        "mp_module_random",
    }
    assert decls["random_bytes_obj"].type_name == "mp_obj_fun_builtin_fixed_t"
    assert decls["globals_table"].is_array
    assert decls["globals_table"].type_name == "mp_rom_map_elem_t"
    assert decls["globals_table_obj"].type_name == "mp_obj_dict_t"
    assert decls["mp_module_random"].type_name == "mp_obj_module_t"


def test_table_entries_extracts_qstr_name_and_value():
    _NODE_CACHE.clear()
    _collect_declarations(SYNTHETIC_PREPROCESSED, "random.c")
    node = _NODE_CACHE[("random.c", "globals_table")]
    entries = _table_entries(node)
    names = {name: value for name, value in entries}
    assert names["bytes"].strip() == "(&random_bytes_obj)"
    assert names["__name__"] is not None  # key present even though not a &ident value


def test_find_module_registrations_reads_raw_source_not_preprocessed():
    """MP_REGISTER_MODULE is a preprocessor no-op, so this has to be found
    by scanning the raw file on disk - exactly what a TranslationUnit's
    `.source`/`.cwd` point at."""
    with tempfile.TemporaryDirectory() as tmp:
        src_path = os.path.join(tmp, "modngu.c")
        with open(src_path, "w") as f:
            f.write(
                "extern const mp_obj_module_t mp_module_random;\n"
                "const mp_obj_module_t mp_module_ngu = {0};\n"
                "MP_REGISTER_MODULE(MP_QSTR_ngu, mp_module_ngu, 1);\n"
            )
        tu = TranslationUnit("modngu.c", "modngu.o", "", False, tmp)
        registrations = find_module_registrations([tu])
        assert registrations == {"ngu": "mp_module_ngu"}


def test_find_module_registrations_skips_stub_tus():
    tu = TranslationUnit("stm32/rng.c", "rng.o", "", True, "/nonexistent")
    assert find_module_registrations([tu]) == {}
