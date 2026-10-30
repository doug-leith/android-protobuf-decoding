"""S2 cell id -> (level, lat, lng) of the cell's centre, after the S2 geometry library
(S2CellId::ToFaceIJOrientation, quadratic projection)."""
import math

POS_TO_IJ = [[0, 1, 3, 2], [0, 2, 3, 1], [3, 2, 0, 1], [3, 1, 0, 2]]
POS_TO_ORIENTATION = [1, 0, 0, 3]
LOOKUP_IJ = [0] * 1024


def _init(level, i, j, orig, pos, orientation):
    if level == 4:
        LOOKUP_IJ[(pos << 2) + orig] = (((i << 4) + j) << 2) + orientation
        return
    level += 1
    i, j, pos = i << 1, j << 1, pos << 2
    r = POS_TO_IJ[orientation]
    for k in range(4):
        _init(level, i + (r[k] >> 1), j + (r[k] & 1), orig, pos + k, orientation ^ POS_TO_ORIENTATION[k])


for _o in range(4):
    _init(0, 0, 0, _o, 0, _o)


def _st_to_uv(s):
    return (4 * s * s - 1) / 3 if s >= 0.5 else (1 - 4 * (1 - s) * (1 - s)) / 3


def cell_level(cid):
    return 30 - ((cid & -cid).bit_length() - 1) // 2


def cell_to_latlng(cid):
    face = cid >> 61
    i = j = 0
    bits = face & 1
    for k in range(7, -1, -1):
        nbits = 2 if k == 7 else 4
        bits += ((cid >> (k * 8 + 1)) & ((1 << (2 * nbits)) - 1)) << 2
        bits = LOOKUP_IJ[bits]
        i += (bits >> 6) << (k * 4)
        j += ((bits >> 2) & 15) << (k * 4)
        bits &= 3
    level = cell_level(cid)
    size = 1 << (30 - level)
    s = ((i & ~(size - 1)) + size / 2) / (1 << 30)
    t = ((j & ~(size - 1)) + size / 2) / (1 << 30)
    u, v = _st_to_uv(s), _st_to_uv(t)
    x, y, z = [(1, u, v), (-u, 1, v), (-u, -v, 1), (-1, -v, -u), (v, -1, -u), (v, u, -1)][face]
    return level, math.degrees(math.atan2(z, math.hypot(x, y))), math.degrees(math.atan2(y, x))


def token_to_id(token):
    return int(token.ljust(16, "0"), 16)
