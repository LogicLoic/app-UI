#Credits to ChatGPT

import io
import pefile
from PIL import Image

def extract_highres_icon_from_exe(exe_path):
    try:
        pe = pefile.PE(exe_path)

        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            print(f"[WARN] {exe_path} n’a pas de ressources.")
            return None

        icon_groups = []
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.name is not None and str(entry.name) == "ICON":
                icon_groups.append(entry)
            elif hasattr(entry, "id") and entry.id == pefile.RESOURCE_TYPE["RT_ICON"]:
                icon_groups.append(entry)

        if not icon_groups:
            print(f"[WARN] Aucune icône trouvée dans {exe_path}.")
            return None

        # Récupère toutes les icônes et prend la plus grande
        icon_data = []
        for group in icon_groups:
            for entry in group.directory.entries:
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                icon_data.append(data)

        if not icon_data:
            print(f"[WARN] Ressources d’icône vides dans {exe_path}.")
            return None

        # Construit une image PIL à partir de la plus grande icône trouvée
        largest = max(icon_data, key=len)
        ico = io.BytesIO(largest)
        img = Image.open(ico)
        return img

    except Exception as e:
        print(f"[ERROR] Extraction échouée pour {exe_path}: {e}")
        return None
