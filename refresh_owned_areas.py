"""Read the newest Anno 1800 save and list areas owned by human player 0.

The save is read only. The trainer uses this list solely to decide which live
memory records may be changed. Ownership comes from each session's AreaInfo,
which also covers Cape Trelawney's Crown Falls.
"""
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).with_name('vendor')))
from a7s2xml import read_rda, decompress_stream


def filedb_dictionary(data, offset):
    count = struct.unpack_from('<I', data, offset)[0]
    ids = struct.unpack_from('<%dH' % count, data, offset + 4)
    position = offset + 4 + count * 2
    names = {}
    for ident in ids:
        end = data.index(b'\0', position)
        names[ident] = data[position:end].decode('utf-8', 'replace')
        position = end + 1
    return names


def filedb_attributes(data):
    """Yield (tag path, attribute name, raw value) without expanding huge XML."""
    _, tags_offset, attrs_offset, _, _ = struct.unpack_from('<IIIII', data, len(data) - 20)
    tags = filedb_dictionary(data, tags_offset)
    attrs = filedb_dictionary(data, attrs_offset)
    path = []
    position = 0
    while position + 8 <= tags_offset:
        size, ident = struct.unpack_from('<IH', data, position)
        position += 8
        if ident == 0:
            if path:
                path.pop()
        elif ident & 0x8000:
            value = data[position:position + size]
            position += (size + 7) & ~7
            yield tuple(path), attrs.get(ident), value
        else:
            path.append(tags.get(ident, '?'))


def sessions_from_save(raw):
    session_guid = None
    for path, name, value in filedb_attributes(raw):
        if name == 'SessionGUID' and 'SessionDesc' in path:
            session_guid = int.from_bytes(value, 'little')
        elif name == 'BinaryData' and 'SessionData' in path:
            yield session_guid, value


def area_owners(session):
    area_id = None
    owners = {}
    for path, name, value in filedb_attributes(session):
        if path[-2:] == ('GameSessionManager', 'AreaInfo') and name is None and len(value) == 2:
            area_id = int.from_bytes(value, 'little')
            owners.setdefault(area_id, None)
        elif (path[-4:] == ('GameSessionManager', 'AreaInfo', '?', 'Owner')
              and name == 'id' and area_id is not None):
            owners[area_id] = int.from_bytes(value, 'little')
    return owners


def main():
    save_root = Path.home() / 'Documents' / 'Anno 1800' / 'accounts'
    saves = list(save_root.glob('*/*/*.a7s'))
    if not saves:
        raise SystemExit('No Anno 1800 saves found under ' + str(save_root))
    save = max(saves, key=lambda path: path.stat().st_mtime)
    print('Reading', save.name)

    archive = read_rda(save.read_bytes())
    packed = next(blob for name, blob in archive if name.lower() == 'data.a7s')
    raw = decompress_stream(packed)
    owned = set()
    seen_areas = {}
    for session_guid, session in sessions_from_save(raw):
        for area_id, owner_id in sorted(area_owners(session).items()):
            print('Session', session_guid, 'Area', area_id, 'Owner', owner_id,
                  'HUMAN' if owner_id == 0 else '')
            previous = seen_areas.get(area_id)
            if previous is not None and previous[1] != owner_id:
                raise SystemExit(
                    'Conflicting ownership for Area %d: Session %s Owner %s; '
                    'Session %s Owner %s. Existing owned_areas.txt was not changed.'
                    % (area_id, previous[0], previous[1], session_guid, owner_id))
            seen_areas[area_id] = (session_guid, owner_id)
            if owner_id == 0:
                owned.add(area_id)
    if not owned:
        raise SystemExit('No human-owned areas found; refusing to overwrite the current map.')

    destination = Path(__file__).with_name('owned_areas.txt')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
                mode='w', encoding='utf-8', newline='\n', dir=destination.parent,
                prefix=destination.name + '.', suffix='.tmp', delete=False) as output:
            temporary = Path(output.name)
            output.write('# Anno 1800 human participant 0; generated from ' + save.name + '\n')
            output.write('\n'.join(str(area) for area in sorted(owned)) + '\n')
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print('Saved', destination, 'with', len(owned), 'human areas')


if __name__ == '__main__':
    main()
