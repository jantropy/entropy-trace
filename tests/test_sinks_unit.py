import os
import tempfile

from entropytrace.analysis.sinks import (
    SinkCategory,
    find_bip32_master_seed_sink,
    load_sink_catalogue,
    locate_python_catalogue_sink,
)
from entropytrace.buildset import TranslationUnit

SYNTHETIC_HDNODE_C = """
typedef unsigned int mp_obj_t;
typedef struct { void *buf; unsigned long len; } mp_buffer_info_t;
typedef struct { char left[32], right[32]; } left_right_t;
void mp_get_buffer_raise(mp_obj_t obj, mp_buffer_info_t *buf, int flags);
void hmac_sha512(const unsigned char *key, int keylen, const void *data, unsigned long datalen, left_right_t *out);

static mp_obj_t s_hdnode_from_master(mp_obj_t self_in, mp_obj_t master_secret_in) {
    mp_buffer_info_t buf;
    mp_get_buffer_raise(master_secret_in, &buf, 1);
    left_right_t I;
    hmac_sha512((const unsigned char *)"Bitcoin seed", 12, buf.buf, buf.len, &I);
    return self_in;
}
"""


def _synthetic_build_set(tmp: str, filename: str, content: str) -> list[TranslationUnit]:
    path = os.path.join(tmp, filename)
    with open(path, "w") as f:
        f.write(content)
    return [TranslationUnit(filename, filename + ".o", "", False, tmp)]


def test_find_bip32_master_seed_sink_locates_the_anchor_and_traces_the_parameter():
    with tempfile.TemporaryDirectory() as tmp:
        build_set = _synthetic_build_set(tmp, "hdnode.c", SYNTHETIC_HDNODE_C)
        sink = find_bip32_master_seed_sink(build_set, os.path.join(tmp, "stub"))
        assert sink is not None
        assert sink.name == "s_hdnode_from_master"
        assert sink.entry_symbol == "master_secret_in"
        assert sink.category == SinkCategory.SEED_GENERATION
        assert sink.entropy_critical is True
        assert sink.mechanism == "structural_anchor"
        assert sink.file == "hdnode.c"


def test_find_bip32_master_seed_sink_absent_when_no_anchor_present():
    with tempfile.TemporaryDirectory() as tmp:
        build_set = _synthetic_build_set(
            tmp, "unrelated.c", "static int f(void) { return 42; }\n"
        )
        assert find_bip32_master_seed_sink(build_set, os.path.join(tmp, "stub")) is None


def test_locate_python_catalogue_sink_reads_real_line_from_checkout():
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "shared"))
        with open(os.path.join(tmp, "shared", "seed.py"), "w") as f:
            f.write("x = 1\ny = 2\n\ndef generate_seed():\n    return b'x' * 32\n")
        entry = {
            "name": "generate_seed",
            "category": "SEED_GENERATION",
            "language": "python",
            "file": "shared/seed.py",
            "entry_symbol": "generate_seed",
        }
        sink = locate_python_catalogue_sink(entry, tmp)
        assert sink is not None
        assert sink.line == 4
        assert sink.entropy_critical is True


def test_locate_python_catalogue_sink_returns_none_when_function_absent():
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "shared"))
        with open(os.path.join(tmp, "shared", "seed.py"), "w") as f:
            f.write("def something_else():\n    pass\n")
        entry = {
            "name": "generate_seed",
            "category": "SEED_GENERATION",
            "language": "python",
            "file": "shared/seed.py",
            "entry_symbol": "generate_seed",
        }
        assert locate_python_catalogue_sink(entry, tmp) is None


def test_load_sink_catalogue_has_generate_seed_entry():
    yaml_path = os.path.join(os.path.dirname(__file__), "..", "data", "sinks.yaml")
    entries = load_sink_catalogue(yaml_path)
    names = {e["name"] for e in entries}
    assert "generate_seed" in names
