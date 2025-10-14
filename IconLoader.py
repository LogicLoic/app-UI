#Credits to ChatGPT

import pefile
from io import BytesIO
from PIL import Image

def extract_highres_icon_from_exe(exe_path, out_path=None):
    pe = pefile.PE(exe_path)
    resources = []
    group_icons = []

    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        raise RuntimeError("Aucune ressource trouvée dans le fichier.")

    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if resource_type.name is not None:
            name = str(resource_type.name)
        else:
            name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, str(resource_type.struct.Id))

        if name == "RT_GROUP_ICON":
            for entry in resource_type.directory.entries:
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                group_icons.append(data)

        elif name == "RT_ICON":
            for entry in resource_type.directory.entries:
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                resources.append(data)

    if not group_icons or not resources:
        raise RuntimeError("Aucune icône trouvée dans ce .exe")

    group_data = group_icons[0]
    reserved, res_type, count = int.from_bytes(group_data[:2], 'little'), int.from_bytes(group_data[2:4], 'little'), int.from_bytes(group_data[4:6], 'little')
    ico_header = group_data[:6]
    entries = []

    for i in range(count):
        entry = bytearray(group_data[6 + i * 14:6 + (i + 1) * 14])
        idx = int.from_bytes(group_data[6 + i * 14 + 12:6 + i * 14 + 14], 'little') - 1
        img_data = resources[idx]
        entry[12:16] = len(img_data).to_bytes(4, 'little')
        entries.append((bytes(entry), img_data))

    ico_data = bytearray(ico_header)
    offset = 6 + len(entries) * 16
    for entry, img_data in entries:
        ico_data += entry[:12] + offset.to_bytes(4, 'little')
        offset += len(img_data)
    for entry, img_data in entries:
        ico_data += img_data

    image = Image.open(BytesIO(ico_data))

    if out_path:
        image.save(out_path)
    return image

